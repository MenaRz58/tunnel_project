"""
Implementación de ChaCha20 (RFC 7539) - simplificada pero funcional.
"""
import struct


def _rotl32(x, n):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))


def quarter_round(a,b,c,d):
    a = (a + b) & 0xffffffff; d ^= a; d = _rotl32(d, 16)
    c = (c + d) & 0xffffffff; b ^= c; b = _rotl32(b, 12)
    a = (a + b) & 0xffffffff; d ^= a; d = _rotl32(d, 8)
    c = (c + d) & 0xffffffff; b ^= c; b = _rotl32(b, 7)
    return a,b,c,d


def chacha20_block(key32, counter, nonce12):
    # key32: 32 bytes, counter: int, nonce12: 12 bytes
    constants = b'expand 32-byte k'
    state = list(struct.unpack('<4I', constants) + struct.unpack('<8I', key32) + (counter & 0xffffffff, ) + struct.unpack('<3I', nonce12))
    working = state.copy()
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
    for i in range(16):
        out.append((working[i] + state[i]) & 0xffffffff)
    return struct.pack('<16I', *out)


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    # key: 32 bytes, nonce: 12 bytes
    out = b''
    i = 0
    while i < len(data):
        block = chacha20_block(key, counter, nonce)
        counter = (counter + 1) & 0xffffffff
        chunk = data[i:i+64]
        keystream = block[:len(chunk)]
        out += bytes(a ^ b for a,b in zip(chunk, keystream))
        i += 64
    return out