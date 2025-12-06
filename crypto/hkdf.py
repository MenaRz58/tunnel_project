"""
HKDF (extract + expand) usando HMAC-SHA256
"""
from .hmac import hmac_sha256 # Importa la función para generar un HMAC usando SHA-256

# HKDF Extract
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    # Si no se proporciona sal, usa un valor por defecto de 32 bytes de ceros
    if salt is None or len(salt)==0:
        # Valor por defecto para sal
        salt = b'\x00'*32

    # Genera la clave pseudoaleatoria (PRK) usando HMAC-SHA256 
    return hmac_sha256(salt, ikm)

# HKDF Expand
def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    # Calcula el número de bloques necesarios (cada bloque es de 32 bytes para SHA-256)
    n = (length + 31) // 32

    # Inicializa el valor de salida y el bloque temporal
    okm = b''
    t = b''

    # Genera los bloques de salida concatenando HMACs encadenados
    for i in range(1, n+1):
        # Calcula el siguiente bloque usando HMAC con la clave PRK y el bloque anterior concatenado con info y el contador
        t = hmac_sha256(prk, t + info + bytes([i]))

        # Añade el bloque generado al valor de salida
        okm += t

    # Devuelve los primeros 'length' bytes del valor de salida
    return okm[:length]

# HKDF (extract + expand)
def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    # Realiza la extracción para obtener la clave pseudoaleatoria (PRK)
    prk = hkdf_extract(salt, ikm)

    # Realiza la expansión para obtener la clave de salida (OKM)
    return hkdf_expand(prk, info, length)