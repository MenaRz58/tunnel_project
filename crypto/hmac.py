from .sha256 import sha256


BLOCKSIZE = 64


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    if len(key) > BLOCKSIZE:
        key = sha256(key)
    if len(key) < BLOCKSIZE:
        key = key + b'\x00' * (BLOCKSIZE - len(key))
    o_key_pad = bytes((b ^ 0x5c) for b in key)
    i_key_pad = bytes((b ^ 0x36) for b in key)
    return sha256(o_key_pad + sha256(i_key_pad + data))


if __name__ == '__main__':
    from .sha256 import sha256
    print(hmac_sha256(b'key', b'The quick brown fox').hex())