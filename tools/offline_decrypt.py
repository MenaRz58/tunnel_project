"""
Script que toma un pcap con payloads (base UDP payloads) y, conociendo la clave y nonce, intenta descifrar y reconstruir tráfico TUN.
Este script asume que los payloads están en orden y concatena los plaintexts.
"""
import sys
from crypto.hmac import hmac_sha256
from crypto.chacha20 import chacha20_xor

def verify_and_decrypt_examples(key_enc, key_mac, nonce, counter, data):
    from crypto.aead import verify_and_decrypt
    return verify_and_decrypt(key_enc, key_mac, nonce, counter, data)

if __name__ == '__main__':
    print('offline_decrypt is a template. For real pcap parsing use scapy or tshark to extract UDP payloads.')