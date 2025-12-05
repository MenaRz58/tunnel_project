from .sha256 import sha256 # Importa la función sha256 para calcular el hash SHA-256

# Tamaño del bloque para SHA-256
BLOCKSIZE = 64

# Implementa HMAC usando SHA-256
def hmac_sha256(key: bytes, data: bytes) -> bytes:
    # Ajusta la longitud de la clave según el tamaño del bloque
    if len(key) > BLOCKSIZE:
        # Si la clave es más larga que el tamaño del bloque, se hashea para reducir su tamaño
        key = sha256(key)

    # Si la clave es más corta que el tamaño del bloque, se rellena con ceros
    if len(key) < BLOCKSIZE:
        # Rellena la clave con ceros hasta alcanzar el tamaño del bloque
        key = key + b'\x00' * (BLOCKSIZE - len(key))

    # Crea los pads externo e interno aplicando XOR con los valores 0x5c y 0x36 respectivamente
    o_key_pad = bytes((b ^ 0x5c) for b in key)
    i_key_pad = bytes((b ^ 0x36) for b in key)

    # Devuelve el HMAC calculado como SHA256(o_key_pad || SHA256(i_key_pad || data))
    return sha256(o_key_pad + sha256(i_key_pad + data))

# Prueba rápida del HMAC-SHA256
if __name__ == '__main__':
    from .sha256 import sha256 # Asegura que sha256 esté importado para la prueba

    # Imprime el HMAC-SHA256 para la clave 'key' y el mensaje 'The quick brown fox'
    print(hmac_sha256(b'key', b'The quick brown fox').hex())