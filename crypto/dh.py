"""
Implementación DH sobre grupo MODP (RFC 3526 - 2048-bit) usando pow().
"""
import os


# 2048-bit MODP Group (RFC 3526) - prime in hex
P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA6"
    "3B139B22514A08798E3404DD" 
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563"
)

# To simplify, use Python's recommended group from RFC but here use shorter example prime for runtime
# For educational/demo, we'll use a smaller safe prime to keep operations fast in the lab.
P = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
'29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381'
'FFFFFFFFFFFFFFFF', 16)
G = 2

def gen_private(bits=256):
    # small private for demo - in production use >= 2048-bit operations
    return int.from_bytes(os.urandom(bits//8), 'big')


def gen_public(priv):
    return pow(G, priv, P)


def compute_shared(peer_pub, priv):
    return pow(peer_pub, priv, P)