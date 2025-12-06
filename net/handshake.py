"""
Handshake simple: intercambio DH efímero + HKDF para derivar claves.
Mensajes serializados en formato len-prefixed fields.
"""
import os, struct
from crypto.dh import gen_private, gen_public, compute_shared # Importa funciones DH
from crypto.hkdf import hkdf # Importa la función HKDF
from crypto.hmac import hmac_sha256 # Importa la función para generar un HMAC usando SHA-256

# Funciones auxiliares para serializar y parsear campos con prefijo de longitud
def _serialize_fields(fields):
    # Serializa una lista de campos como len-prefixed fields
    out = b''

    # Itera sobre cada campo y lo serializa con un prefijo de longitud
    for f in fields:
        out += struct.pack('>I', len(f)) + f
    return out

# Función auxiliar para parsear campos con prefijo de longitud
def _parse_fields(b):
    # Parsea una secuencia de bytes en una lista de campos len-prefixed
    i = 0
    fields = []

    # Itera sobre la secuencia de bytes y extrae campos len-prefixed
    while i < len(b):
        # Verifica que haya suficientes bytes para leer la longitud
        if i+4 > len(b):
            break

        # Verifica que haya suficientes bytes para leer el campo
        L = struct.unpack('>I', b[i:i+4])[0]
        i += 4
        if i+L > len(b): 
            break
        fields.append(b[i:i+L]) # Extrae el campo y lo añade a la lista
        i += L
    return fields

# Clase Handshake para manejar el proceso de handshake
class Handshake:
    # Inicializa el estado del handshake
    def __init__(self, psk: bytes = b''):
        self.psk = psk # Clave precompartida opcional para autenticación
        self.nonce = None # Nonce de 12 bytes para AEAD
        self.priv = None # Clave privada DH
        self.pub = None # Clave pública DH
        self.client_init_msg = None # Mensaje inicial del cliente
        self.key_enc = None # Clave de cifrado derivada
        self.key_mac = None # Clave MAC derivada

    # --- CLIENTE ---
    # Inicia el handshake desde el lado del cliente
    def client_init(self):
        # Genera clave privada y pública DH, y nonce para AEAD
        self.priv = gen_private()
        
        # Genera la clave pública DH correspondiente a la clave privada
        pub_int = gen_public(self.priv)

        # Convierte la clave pública a bytes y la ajusta a 32 bytes
        pub_bytes = pub_int.to_bytes((pub_int.bit_length() + 7) // 8, 'big')

        # Ajusta la clave pública a 32 bytes rellenando con ceros a la izquierda
        self.pub = pub_bytes.rjust(32, b'\x00')

        # Genera un nonce aleatorio de 12 bytes para AEAD
        self.nonce = os.urandom(12)

        # Serializa el mensaje INIT con ID, nonce y clave pública
        msg = _serialize_fields([b'CLIENT', self.nonce, self.pub])

        # Guarda el mensaje inicial del cliente para el transcript
        self.client_init_msg = msg

        # Devuelve el mensaje inicial del cliente para enviar al servidor
        return msg

    # Completa el handshake desde el lado del cliente con la respuesta del servidor
    def client_finish(self, server_msg: bytes):
        # Parsea el mensaje del servidor y verifica su formato
        fields = _parse_fields(server_msg)
        
        # Verifica que el mensaje tenga el número correcto de campos
        if len(fields) != 4:
            raise ValueError("server_msg malformed") # Verifica que el mensaje del servidor esté bien formado
        
        # Extrae los campos del mensaje del servidor
        server_id, server_nonce, server_pub_bytes, auth = fields

        # Convierte la clave pública del servidor de bytes a entero
        server_pub = int.from_bytes(server_pub_bytes, 'big')

        # Calcula la clave compartida usando la clave pública del servidor y la clave privada del cliente
        shared = compute_shared(server_pub, self.priv)

        # Convierte la clave compartida a bytes y la ajusta a 32 bytes
        shared_bytes = shared.to_bytes((shared.bit_length() + 7) // 8, 'big').rjust(32, b'\x00')

        # Deriva las claves y nonce usando HKDF con la clave compartida y los nonces
        ikm = shared_bytes + self.nonce + server_nonce

        # Deriva las claves y nonce usando HKDF con la clave compartida y los nonces
        key_material = hkdf(b'', ikm, b'handshake', 76) 

        # Divide el material clave en clave de cifrado, clave MAC y nonce
        self.key_enc = key_material[:32]
        self.key_mac = key_material[32:64]
        self.nonce = key_material[64:]

        # Verifica la autenticación del servidor usando HMAC-SHA256
        transcript = self.client_init_msg + _serialize_fields([server_id, server_nonce, server_pub_bytes])

        # Selecciona la clave de autenticación: PSK si está disponible, de lo contrario la clave MAC derivada
        auth_key = self.psk if self.psk else self.key_mac

        # Calcula el HMAC esperado y lo compara con el recibido
        expected = hmac_sha256(auth_key, transcript)

        # Compara el HMAC esperado con el recibido para verificar la autenticación del servidor
        if expected != auth:
            raise ValueError('Server authentication failed')

        # Genera el mensaje FINAL del cliente con su HMAC
        final_tag = hmac_sha256(auth_key, transcript + b'CLIENT_FIN')

        # Devuelve el mensaje FINAL del cliente para enviar al servidor
        return _serialize_fields([b'CLIENT_FIN', final_tag])

    # --- SERVIDOR ---
    # Procesa el mensaje INIT del cliente y genera la respuesta del servidor
    def server_response(self, client_msg: bytes):
        # Parsea el mensaje del cliente y verifica su formato
        fields = _parse_fields(client_msg)

        # Verifica que el mensaje tenga el número correcto de campos
        if len(fields) != 3:
            raise ValueError("client_msg malformed") # Verifica que el mensaje del cliente esté bien formado
        
        # Extrae los campos del mensaje del cliente
        client_id, client_nonce, client_pub_bytes = fields
        client_pub = int.from_bytes(client_pub_bytes, 'big')

        # Genera la clave privada y pública DH del servidor
        self.priv = gen_private()
        pub_int = gen_public(self.priv)

        # Convierte la clave pública del servidor a bytes y la ajusta a 32 bytes
        pub_bytes = pub_int.to_bytes((pub_int.bit_length() + 7) // 8, 'big').rjust(32, b'\x00')

        # Almacena la clave pública y genera un nonce para el handshake
        self.pub = pub_bytes
        self.nonce_handshake = os.urandom(12)

        # Calcula la clave compartida usando la clave pública del cliente y la clave privada del servidor
        shared = compute_shared(client_pub, self.priv)

        # Convierte la clave compartida a bytes y la ajusta a 32 bytes
        shared_bytes = shared.to_bytes((shared.bit_length() + 7) // 8, 'big').rjust(32, b'\x00')

        # Deriva las claves y nonce usando HKDF con la clave compartida y los nonces
        ikm = shared_bytes + client_nonce + self.nonce_handshake

        # Deriva las claves y nonce usando HKDF con la clave compartida y los nonces
        key_material = hkdf(b'', ikm, b'handshake', 76) 

        # Divide el material clave en clave de cifrado, clave MAC y nonce
        self.key_enc = key_material[:32]
        self.key_mac = key_material[32:64]
        self.nonce = key_material[64:]

        # Genera el mensaje de respuesta del servidor con su HMAC
        transcript = client_msg + _serialize_fields([b'SERVER', self.nonce_handshake, self.pub])

        # Selecciona la clave de autenticación: PSK si está disponible, de lo contrario la clave MAC derivada
        auth_key = self.psk if self.psk else self.key_mac

        # Calcula el HMAC del mensaje de respuesta del servidor
        auth = hmac_sha256(auth_key, transcript)

        # Devuelve el mensaje de respuesta del servidor para enviar al cliente
        return _serialize_fields([b'SERVER', self.nonce_handshake, self.pub, auth])
