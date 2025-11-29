"""
Handshake simple: intercambio DH efímero + HKDF para derivar claves.
Mensajes serializados en formato len-prefixed fields.
"""
import os, struct
from crypto.dh import gen_private, gen_public, compute_shared
from crypto.hkdf import hkdf
from crypto.hmac import hmac_sha256

def _serialize_fields(fields):
    out = b''
    for f in fields:
        out += struct.pack('>I', len(f)) + f
    return out

def _parse_fields(b):
    i = 0
    fields = []
    while i < len(b):
        if i+4 > len(b):
            break
        L = struct.unpack('>I', b[i:i+4])[0]
        i += 4
        if i+L > len(b): 
            break
        fields.append(b[i:i+L])
        i += L
    return fields

class Handshake:
    def __init__(self, psk: bytes = b''):
        self.psk = psk
        self.nonce = None
        self.priv = None
        self.pub = None
        self.client_init_msg = None
        self.key_enc = None
        self.key_mac = None

    # --- CLIENTE ---
    def client_init(self):
        self.priv = gen_private()
        pub_int = gen_public(self.priv)
        pub_bytes = pub_int.to_bytes((pub_int.bit_length() + 7) // 8, 'big')
        self.pub = pub_bytes.rjust(32, b'\x00')
        self.nonce = os.urandom(12)
        msg = _serialize_fields([b'CLIENT', self.nonce, self.pub])
        self.client_init_msg = msg
        return msg

    def client_finish(self, server_msg: bytes):
        fields = _parse_fields(server_msg)
        if len(fields) != 4:
            raise ValueError("server_msg malformed")
        server_id, server_nonce, server_pub_bytes, auth = fields
        server_pub = int.from_bytes(server_pub_bytes, 'big')

        shared = compute_shared(server_pub, self.priv)
        shared_bytes = shared.to_bytes((shared.bit_length() + 7) // 8, 'big').rjust(32, b'\x00')

        ikm = shared_bytes + self.nonce + server_nonce
        key_material = hkdf(b'', ikm, b'handshake', 76) 

        self.key_enc = key_material[:32]
        self.key_mac = key_material[32:64]
        self.nonce = key_material[64:]

        transcript = self.client_init_msg + _serialize_fields([server_id, server_nonce, server_pub_bytes])
        auth_key = self.psk if self.psk else self.key_mac
        expected = hmac_sha256(auth_key, transcript)
        if expected != auth:
            raise ValueError('Server authentication failed')

        final_tag = hmac_sha256(auth_key, transcript + b'CLIENT_FIN')
        return _serialize_fields([b'CLIENT_FIN', final_tag])

    # --- SERVIDOR ---
    def server_response(self, client_msg: bytes):
        fields = _parse_fields(client_msg)
        if len(fields) != 3:
            raise ValueError("client_msg malformed")
        client_id, client_nonce, client_pub_bytes = fields
        client_pub = int.from_bytes(client_pub_bytes, 'big')

        self.priv = gen_private()
        pub_int = gen_public(self.priv)
        pub_bytes = pub_int.to_bytes((pub_int.bit_length() + 7) // 8, 'big').rjust(32, b'\x00')
        self.pub = pub_bytes
        self.nonce_handshake = os.urandom(12)

        shared = compute_shared(client_pub, self.priv)
        shared_bytes = shared.to_bytes((shared.bit_length() + 7) // 8, 'big').rjust(32, b'\x00')

        ikm = shared_bytes + client_nonce + self.nonce_handshake
        key_material = hkdf(b'', ikm, b'handshake', 76) 

        self.key_enc = key_material[:32]
        self.key_mac = key_material[32:64]
        self.nonce = key_material[64:]

        transcript = client_msg + _serialize_fields([b'SERVER', self.nonce_handshake, self.pub])
        auth_key = self.psk if self.psk else self.key_mac
        auth = hmac_sha256(auth_key, transcript)
        return _serialize_fields([b'SERVER', self.nonce_handshake, self.pub, auth])
