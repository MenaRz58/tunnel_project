"""
AEAD: Encrypt-then-MAC using ChaCha20 for confidentiality and HMAC-SHA256 for authentication.
"""
from .chacha20 import chacha20_xor
from .hmac import hmac_sha256
import struct

def encrypt_then_mac(key_enc: bytes, key_mac: bytes, nonce12: bytes, counter: int, plaintext: bytes, aad: bytes=b'') -> bytes:
    ct = chacha20_xor(key_enc, counter, nonce12, plaintext)
    header = struct.pack('>I', counter)
    tag = hmac_sha256(key_mac, aad + header + ct)
    return header + ct + tag


def verify_and_decrypt(key_enc: bytes, key_mac: bytes, nonce12: bytes, counter: int, data: bytes, aad: bytes=b'') -> tuple[bool, bytes]:
    if len(data) < 36:
        return False, b''
    header = data[:4]
    ct = data[4:-32]
    tag = data[-32:]
    expected = hmac_sha256(key_mac, aad + header + ct)
    if expected != tag:
        return False, b''
    msg_counter = struct.unpack('>I', header)[0]
    if msg_counter != counter:
        # El paquete es íntegro, pero NO tiene el contador secuencial esperado.
        # Esto es un ataque de Replay, paquete fuera de orden, o pérdida de sincronización.
        print(f"[REPLAY DETECTED] Expected counter {counter}, got {msg_counter}")
        return False, b''
    pt = chacha20_xor(key_enc, msg_counter, nonce12, ct)
    return True, pt