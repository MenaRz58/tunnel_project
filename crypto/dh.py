"""
Implementación DH sobre grupo MODP (RFC 3526 - 2048-bit) usando pow().
"""
import os

# Parámetros del grupo MODP 2048-bit (RFC 3526)
P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA6"
    "3B139B22514A08798E3404DD" 
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563"
)

# Constantes del grupo
P = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
'29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381'
'FFFFFFFFFFFFFFFF', 16)
G = 2

# Genera una clave privada aleatoria de 'bits' bits.
def gen_private(bits=256):
    # Usa os.urandom para obtener bytes aleatorios y los convierte a un entero grande
    return int.from_bytes(os.urandom(bits//8), 'big')

# Genera la clave pública correspondiente a la clave privada dada.
def gen_public(priv):
    # Calcula G^priv mod P
    return pow(G, priv, P)

# Calcula la clave compartida usando la clave pública del peer y la clave privada propia.
def compute_shared(peer_pub, priv):
    # Calcula peer_pub^priv mod P
    return pow(peer_pub, priv, P)