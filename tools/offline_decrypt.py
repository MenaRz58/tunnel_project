"""
Script que toma un pcap con payloads (base UDP payloads) y, conociendo la clave y nonce, intenta descifrar y reconstruir tráfico TUN.
Este script asume que los payloads están en orden y concatena los plaintexts.
"""
import sys # Para manejo de argumentos y salida estándar
from crypto.hmac import hmac_sha256 # Para verificación HMAC
from crypto.chacha20 import chacha20_xor # Para descifrado ChaCha20

# Función para verificar y descifrar datos usando ChaCha20 y HMAC-SHA256
def verify_and_decrypt_examples(key_enc, key_mac, nonce, counter, data):
    from crypto.aead import verify_and_decrypt # Importa la función verify_and_decrypt del módulo aead
    return verify_and_decrypt(key_enc, key_mac, nonce, counter, data) # Llama a la función importada con los parámetros proporcionados

# Punto de entrada del script
if __name__ == '__main__':
    # Muestra un mensaje indicando que este es un script de plantilla
    print('offline_decrypt is a template. For real pcap parsing use scapy or tshark to extract UDP payloads.')