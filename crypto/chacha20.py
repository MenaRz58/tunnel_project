"""
Implementación de ChaCha20 (RFC 7539) - simplificada pero funcional.
"""
import struct

# Rotación a la izquierda en un entero de 32 bits. Se desplaza 'x' n bits a la izquierda y lo que se sale por arriba vuelve por la derecha. Mantiene el resultado en 32 bits con & 0xffffffff.
def _rotl32(x, n):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

# Una ronda de ChaCha20: toma 4 enteros de 32 bits y aplica las operaciones de la ronda.    
def quarter_round(a,b,c,d):
    a = (a + b) & 0xffffffff; d ^= a; d = _rotl32(d, 16)
    c = (c + d) & 0xffffffff; b ^= c; b = _rotl32(b, 12)
    a = (a + b) & 0xffffffff; d ^= a; d = _rotl32(d, 8)
    c = (c + d) & 0xffffffff; b ^= c; b = _rotl32(b, 7)
    return a,b,c,d

# Genera un bloque de 64 bytes de keystream de ChaCha20 dado una clave de 32 bytes, un contador y un nonce de 12 bytes.
def chacha20_block(key32, counter, nonce12):
    # key32: 32 bytes, counter: int, nonce12: 12 bytes
    constants = b'expand 32-byte k'
    state = list(struct.unpack('<4I', constants) + struct.unpack('<8I', key32) + (counter & 0xffffffff, ) + struct.unpack('<3I', nonce12))
    working = state.copy()

    # 20 rounds = 10 ciclos de 2 rondas (columna + diagonal)
    for _ in range(10):
        # column rounds
        working[0],working[4],working[8],working[12] = quarter_round(working[0],working[4],working[8],working[12])
        working[1],working[5],working[9],working[13] = quarter_round(working[1],working[5],working[9],working[13])
        working[2],working[6],working[10],working[14] = quarter_round(working[2],working[6],working[10],working[14])
        working[3],working[7],working[11],working[15] = quarter_round(working[3],working[7],working[11],working[15])

        # diagonal rounds
        working[0],working[5],working[10],working[15] = quarter_round(working[0],working[5],working[10],working[15])
        working[1],working[6],working[11],working[12] = quarter_round(working[1],working[6],working[11],working[12])
        working[2],working[7],working[8],working[13] = quarter_round(working[2],working[7],working[8],working[13])
        working[3],working[4],working[9],working[14] = quarter_round(working[3],working[4],working[9],working[14])

    out = []

    # Suma el estado original al estado trabajado y empaqueta el resultado en bytes
    for i in range(16):
        out.append((working[i] + state[i]) & 0xffffffff)
    return struct.pack('<16I', *out)

# Cifra o descifra datos usando ChaCha20 en modo XOR.
def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    # key: 32 bytes, nonce: 12 bytes
    out = b''
    i = 0

    # Procesa los datos en bloques de 64 bytes
    while i < len(data):
        # Genera un bloque de keystream para el contador y nonce actuales
        block = chacha20_block(key, counter, nonce)

        # Incrementa el contador para el siguiente bloque
        counter = (counter + 1) & 0xffffffff

        # Toma un chunk de 64 bytes del data y lo XORea con el keystream
        chunk = data[i:i+64]

        # Genera el keystream para el chunk actual
        keystream = block[:len(chunk)]

        # XOR y agrega al output
        out += bytes(a ^ b for a,b in zip(chunk, keystream))

        # Avanza al siguiente bloque de 64 bytes
        i += 64
    
    # Devuelve el resultado cifrado o descifrado
    return out