# crypto/poly1305.py
"""
Implementación Poly1305 MAC en Python puro.
Funciona con cualquier mensaje de bytes y clave de 32 bytes.
"""

def clamp(r: bytes) -> bytes:
    """Clamping de r según la especificación Poly1305"""
    t = bytearray(r)
    t[3] &= 15
    t[7] &= 15
    t[11] &= 15
    t[15] &= 15
    t[4] &= 252
    t[8] &= 252
    t[12] &= 252
    return bytes(t)

def le_bytes_to_num(b: bytes) -> int:
    """Convierte bytes little-endian a número entero"""
    return sum(x << (8*i) for i, x in enumerate(b))

def num_to_16_le(n: int) -> bytes:
    """Convierte un entero a 16 bytes little-endian"""
    return bytes((n >> (8*i)) & 0xff for i in range(16))

def mac(msg: bytes, key: bytes) -> bytes:
    """
    Calcula Poly1305 MAC para un mensaje msg con clave de 32 bytes.
    key = r(16 bytes) || s(16 bytes)
    """
    if len(key) != 32:
        raise ValueError("Poly1305 key debe tener 32 bytes")
    r = clamp(key[:16])
    s = key[16:]
    r_num = le_bytes_to_num(r)
    s_num = le_bytes_to_num(s)

    acc = 0
    p = 2**130 - 5

    # Procesar mensaje en bloques de 16 bytes
    for i in range(0, len(msg), 16):
        block = msg[i:i+16]
        if len(block) < 16:
            block += b'\x01' + b'\x00'*(15-len(block))
        else:
            block += b'\x01'
        n = le_bytes_to_num(block)
        acc = (acc + n) * r_num % p

    acc = (acc + s_num) % (1 << 128)
    return num_to_16_le(acc)

def verify(key: bytes, msg: bytes, tag: bytes) -> bool:
    """Verifica que el tag corresponda al mensaje"""
    return mac(msg, key) == tag
