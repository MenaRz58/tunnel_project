"""
AEAD: Encrypt-then-MAC using ChaCha20 for confidentiality and HMAC-SHA256 for authentication.
"""
from .chacha20 import chacha20_xor # Importa la función para cifrar/descifrar usando ChaCha20 en modo XOR
from .hmac import hmac_sha256 # Importa la función para generar un HMAC usando SHA-256
import struct 

def encrypt_then_mac(key_enc: bytes, key_mac: bytes, nonce12: bytes, counter: int, plaintext: bytes, aad: bytes=b'') -> bytes:
    # Cifra el mensaje usando ChaCha20-XOR con la clave de cifrado, contador y nonce
    ct = chacha20_xor(key_enc, counter, nonce12, plaintext)

    # Empaqueta el contador en 4 bytes en big-endian → se usará como header del mensaje
    header = struct.pack('>I', counter)

    # Genera un MAC (etiqueta de autenticidad) tomando AAD + header + ciphertext
    tag = hmac_sha256(key_mac, aad + header + ct)

    # Devuelve el mensaje completo → header | ciphertext | tag
    return header + ct + tag


def verify_and_decrypt(key_enc: bytes, key_mac: bytes, nonce12: bytes, counter: int, data: bytes, aad: bytes=b'') -> tuple[bool, bytes]:
    # Verifica que el mensaje tenga al menos los bytes mínimos: 4 de header + 32 del tag = 36 → si no alcanza, está corrupto.
    if len(data) < 36:
        return False, b''
    
    # Extrae el header (contador), ciphertext y tag recibido
    header = data[:4]
    ct = data[4:-32]
    tag = data[-32:]

    # Genera el MAC esperado y lo compara con el recibido
    expected = hmac_sha256(key_mac, aad + header + ct)

    # Compara el MAC esperado con el recibido para verificar la integridad y autenticidad
    if expected != tag:
        return False, b''
    
    # Desempaqueta el contador del header para usarlo en la descifrado
    msg_counter = struct.unpack('>I', header)[0]
    if msg_counter != counter:
        # El paquete es íntegro, pero NO tiene el contador secuencial esperado.
        # Esto es un ataque de Replay, paquete fuera de orden, o pérdida de sincronización.
        print(f"[REPLAY DETECTED] Expected counter {counter}, got {msg_counter}")
        return False, b''
    
    # Descifra el ciphertext usando ChaCha20-XOR con la clave de cifrado, contador y nonce
    pt = chacha20_xor(key_enc, msg_counter, nonce12, ct)

    # Retorna éxito=True y el mensaje en texto plano
    return True, pt