#!/usr/bin/env python3
"""
proof_decrypt.py
Herramienta para demostrar descifrado manual de un paquete capturado (Hex)
usando las claves obtenidas del log del Handshake.
"""
import binascii # Para conversión hex <-> bytes
import struct
from crypto.aead import verify_and_decrypt # Importa la función de descifrado y verificación

# Función principal
def main():
    print("--- DEMOSTRACIÓN DE DESCIFRADO OFFLINE ---") # Título
    
    # 1. DATOS QUE COPIAS DEL LOG DE PYTHON (Handshake)
    print("Introduce las claves (copiar del log [HANDSHAKE] Finished):")
    hex_key_enc = input("Key Enc (hex): ").strip() # Clave de cifrado en hexadecimal
    hex_key_mac = input("Key Mac (hex): ").strip() # Clave MAC en hexadecimal
    hex_nonce   = input("Nonce   (hex, son los ultimos 24 chars del log de keys si imprimiste todo o hardcodeado): ").strip() # Nonce en hexadecimal
    # NOTA: En tu código actual, el nonce se deriva en el handshake. 
    # Asegúrate de imprimirlo en handshake.py o client.py para poder copiarlo aquí.
    
    # 2. DATOS QUE COPIAS DE WIRESHARK O LOG (Payload UDP)
    print("\nIntroduce el paquete cifrado completo (UDP Payload en Hex):") # Paquete cifrado en hexadecimal
    hex_packet = input("Packet (hex): ").strip() # Paquete cifrado en hexadecimal

    # Convierte de hex a bytes
    try:
        key_enc = binascii.unhexlify(hex_key_enc)
        key_mac = binascii.unhexlify(hex_key_mac)
        # Si no tienes el nonce a mano, recuerda que tu código usa uno derivado de HKDF.
        # Para facilitar la demo, puedes imprimir 'self.nonce.hex()' en el print del handshake.
        nonce   = binascii.unhexlify(hex_nonce) 
        packet  = binascii.unhexlify(hex_packet)
    except Exception as e:
        print("Error formato hex:", e) # Error al convertir de hex a bytes
        return

    # 3. INTENTAR DESCIFRAR
    # El contador está en los primeros 4 bytes del paquete, verify_and_decrypt lo extrae.
    # Pasamos 0 como contador local porque la función usará el del paquete.
    ok, plaintext = verify_and_decrypt(key_enc, key_mac, nonce, 0, packet)

    # 4. MOSTRAR RESULTADOS
    if ok:
        print("\n[ÉXITO] Firma HMAC válida.") # Firma válida
        print(f"Texto Plano (Hex): {plaintext.hex()}") # Muestra el texto plano en hexadecimal
        print(f"Texto Plano (ASCII): {plaintext[:100]}...") # Muestra los primeros 100 caracteres en ASCII  
        
        # Opcional: Guardar a archivo si es una imagen/pdf
        # with open('recuperado.bin', 'wb') as f:
        #     f.write(plaintext)
    else:
        print("\n[FALLO] La firma HMAC no coincide o la clave es incorrecta.") # Firma inválida

# Punto de entrada del script
if __name__ == '__main__':
    main()