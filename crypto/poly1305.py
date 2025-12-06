# crypto/poly1305.py
"""
Implementación Poly1305 MAC en Python puro.
Funciona con cualquier mensaje de bytes y clave de 32 bytes.
"""

# Clamping de r según la especificación Poly1305
def clamp(r: bytes) -> bytes:
    """Clamping de r según la especificación Poly1305"""
    t = bytearray(r)
    t[3] &= 15 # Aplica máscara para clamping
    t[7] &= 15
    t[11] &= 15
    t[15] &= 15
    t[4] &= 252
    t[8] &= 252
    t[12] &= 252

    return bytes(t)

# Convierte bytes little-endian a número entero
def le_bytes_to_num(b: bytes) -> int:
    """Convierte bytes little-endian a número entero"""

    # Suma cada byte desplazado según su posición
    return sum(x << (8*i) for i, x in enumerate(b))

# Convierte un número entero a 16 bytes little-endian
def num_to_16_le(n: int) -> bytes:
    """Convierte un entero a 16 bytes little-endian"""

    # Extrae cada byte desplazado y lo convierte a bytes
    return bytes((n >> (8*i)) & 0xff for i in range(16))

# Calcula Poly1305 MAC para un mensaje con una clave dada
def mac(msg: bytes, key: bytes) -> bytes:
    """
    Calcula Poly1305 MAC para un mensaje msg con clave de 32 bytes.
    key = r(16 bytes) || s(16 bytes)
    """

    # Verifica que la clave tenga 32 bytes
    if len(key) != 32:
        # Si la clave no tiene 32 bytes, lanza un error
        raise ValueError("Poly1305 key debe tener 32 bytes")
    
    # Divide la clave en r y s, y aplica clamping a r
    r = clamp(key[:16])
    s = key[16:]

    # Convierte r y s a números enteros
    r_num = le_bytes_to_num(r)
    s_num = le_bytes_to_num(s)

    # Inicializa el acumulador
    acc = 0

    # Módulo p = 2^130 - 5
    p = 2**130 - 5

    # Procesar mensaje en bloques de 16 bytes
    for i in range(0, len(msg), 16):
        # Extrae un bloque de 16 bytes del mensaje
        block = msg[i:i+16]

        # Añade el byte 0x01 al final del bloque (padding)
        if len(block) < 16:

            # Añade padding con 0x01 seguido de ceros si el bloque es menor a 16 bytes
            block += b'\x01' + b'\x00'*(15-len(block))
        else:
            # Añade byte 0x01 al final si el bloque tiene 16 bytes
            block += b'\x01'

        # Convierte el bloque a número entero little-endian
        n = le_bytes_to_num(block)

        # Actualiza el acumulador: acc = (acc + n) * r mod p
        acc = (acc + n) * r_num % p

    # Añade s al acumulador final: acc = (acc + s) mod 2^128
    acc = (acc + s_num) % (1 << 128)

    # Convierte el acumulador final a 16 bytes little-endian y lo devuelve
    return num_to_16_le(acc)

# Verificar la autenticidad e integridad de un mensaje comparando el MAC calculado localmente con el tag recibido.
def verify(key: bytes, msg: bytes, tag: bytes) -> bool:
    """Verifica que el tag corresponda al mensaje"""

    # Calcula el MAC del mensaje con la clave y compara con el tag dado
    return mac(msg, key) == tag
