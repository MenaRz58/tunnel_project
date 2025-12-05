import struct

# SHA-256 constantes
K = [
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Funciones auxiliares
def _rotr(x, n):
    # Rotación a la derecha de un entero de 32 bits
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

# Función principal SHA-256
def sha256(message: bytes) -> bytes:
    # Pre-procesamiento
    ml = len(message) * 8

    # Añade el bit '1' seguido de ceros hasta que el mensaje tenga un tamaño congruente a 448 mod 512
    message += b'\x80'

    # Añade ceros hasta que el mensaje tenga un tamaño congruente a 448 mod 512
    while (len(message) * 8) % 512 != 448:
        # Añade un byte cero al mensaje
        message += b'\x00'

    # Añade la longitud original del mensaje como un entero de 64 bits big-endian
    message += struct.pack('>Q', ml)

    # Inicializa los valores hash
    H = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
    ]

    # Procesa el mensaje en bloques sucesivos de 512 bits
    for i in range(0, len(message), 64):
        # Extrae el bloque de 64 bytes
        chunk = message[i:i+64]

        # Prepara el mensaje extendido W
        w = list(struct.unpack('>16I', chunk)) + [0]*48

        # Extiende el mensaje
        for t in range(16, 64):
            # Calcula s0 y s1 para la extensión del mensaje
            s0 = (_rotr(w[t-15], 7) ^ _rotr(w[t-15], 18) ^ (w[t-15] >> 3)) & 0xffffffff
            s1 = (_rotr(w[t-2], 17) ^ _rotr(w[t-2], 19) ^ (w[t-2] >> 10)) & 0xffffffff

            # Calcula el valor extendido w[t]
            w[t] = (w[t-16] + s0 + w[t-7] + s1) & 0xffffffff

        # Inicializa las variables de trabajo con los valores hash actuales
        a,b,c,d,e,f,g,h = H

        # Realiza las 64 rondas de compresión
        for t in range(64):
            # Calcula las funciones y valores temporales para la ronda t
            S1 = (_rotr(e,6) ^ _rotr(e,11) ^ _rotr(e,25)) & 0xffffffff

            # Calcula la función elección (ch)
            ch = (e & f) ^ ((~e) & g)

            # Calcula la suma temporal temp1
            temp1 = (h + S1 + ch + K[t] + w[t]) & 0xffffffff

            # Calcula la suma temporal temp2
            S0 = (_rotr(a,2) ^ _rotr(a,13) ^ _rotr(a,22)) & 0xffffffff
            maj = (a & b) ^ (a & c) ^ (b & c) # Calcula la función mayoría (maj)
            temp2 = (S0 + maj) & 0xffffffff

            # Actualiza las variables de trabajo
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        # Actualiza los valores hash con los resultados de esta ronda
        H = [ (H[0]+a)&0xffffffff, (H[1]+b)&0xffffffff, (H[2]+c)&0xffffffff, (H[3]+d)&0xffffffff,
        (H[4]+e)&0xffffffff, (H[5]+f)&0xffffffff, (H[6]+g)&0xffffffff, (H[7]+h)&0xffffffff ]

    # Devuelve el hash final como una secuencia de bytes
    return b''.join(struct.pack('>I', h) for h in H)

# Prueba rápida del SHA-256
if __name__ == '__main__':
    # Imprime el SHA-256 del mensaje vacío
    print(sha256(b'').hex()) # Debería ser: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'