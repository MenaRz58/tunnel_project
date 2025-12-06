#!/usr/bin/env python3
"""
proof_decrypt.py
Herramienta para demostrar descifrado manual de un paquete capturado (Hex)
usando las claves obtenidas del log del Handshake.

Únicamente descifra el contenido
del payload y lo imprime como texto plano (hex y ASCII), por lo que es
adecuada para sesiones de prueba donde el plaintext es texto o datos
humanamente legibles.
"""

import binascii
from crypto.aead import verify_and_decrypt # Importa la función de descifrado y verificación

def main():
    print("--- DEMOSTRACIÓN DE DESCIFRADO OFFLINE ---") 
    
    # Solicitud interactiva de claves derivadas durante el handshake
    print("Introduce las claves (copiar del log [HANDSHAKE] Finished):")
    hex_key_enc = input("Key Enc (hex): ").strip() # Clave de cifrado en hexadecimal
    hex_key_mac = input("Key Mac (hex): ").strip() # Clave MAC en hexadecimal
    hex_nonce   = input("Nonce   (hex, son los ultimos 24 chars del log de keys si imprimiste todo o hardcodeado): ").strip() # Nonce en hexadecimal
    
    # Solicitud del payload cifrado, típicamente extraído de Wireshark
    print("\nIntroduce el paquete cifrado completo (UDP Payload en Hex):") 
    hex_packet = input("Packet (hex): ").strip() 

     # Conversión de todas las entradas desde hex a bytes
    try:
        key_enc = binascii.unhexlify(hex_key_enc)
        key_mac = binascii.unhexlify(hex_key_mac)
        nonce   = binascii.unhexlify(hex_nonce) 
        packet  = binascii.unhexlify(hex_packet)
    except Exception as e:
        print("Error formato hex:", e) # Error al convertir de hex a bytes
        return

    # Descifrado mediante AEAD (el contador se extrae desde el paquete)
    ok, plaintext = verify_and_decrypt(key_enc, key_mac, nonce, 0, packet)

    # Resultado del descifrado
    if ok:
        print("\n[ÉXITO] Firma HMAC válida.") # Firma válida
        print(f"Texto Plano (Hex): {plaintext.hex()}") # Muestra el texto plano en hexadecimal
        print(f"Texto Plano (ASCII): {plaintext[:100]}...") # Muestra los primeros 100 caracteres en ASCII  
        
    else:
        print("\n[FALLO] La firma HMAC no coincide o la clave es incorrecta.") # Firma inválida

if __name__ == '__main__':
    main()