"""
HKDF (extract + expand) usando HMAC-SHA256
"""
from .hmac import hmac_sha256


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if salt is None or len(salt)==0:
        salt = b'\x00'*32
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    n = (length + 31) // 32
    okm = b''
    t = b''
    for i in range(1, n+1):
        t = hmac_sha256(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)