#!/usr/bin/env python3
"""
pcap_decryptor.py
Herramienta Forense: Descifra tráfico VPN capturado y genera un PCAP limpio.
Usa Scapy para manejo de archivos y 'crypto.aead' propio para el descifrado.
"""
import sys
import binascii
from scapy.all import rdpcap, wrpcap, IP, UDP
# Importamos TU criptografía
from crypto.aead import verify_and_decrypt

# --- CONFIGURACIÓN AUTOMÁTICA ---
# Puerto UDP donde corre tu túnel (Groso2 escucha aquí)
VPN_PORT = 50000

def main():
    print("--- VPN TRAFFIC DECRYPTOR (Forensic Tool) ---")
    if len(sys.argv) != 3:
        print("Uso: python3 pcap_decryptor.py <entrada_cifrada.pcap> <salida_limpia.pcap>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # 1. SOLICITAR CLAVES DE LA SESIÓN CAPTURADA
    print("\nIntroduce las claves de la sesión (copiar del log de Groso1/2):")
    try:
        # Input con limpieza automática de espacios/saltos
        hex_enc = input("Key Enc (hex): ").strip().replace(' ', '')
        hex_mac = input("Key Mac (hex): ").strip().replace(' ', '')
        hex_nonce = input("Nonce   (hex): ").strip().replace(' ', '')

        key_enc = binascii.unhexlify(hex_enc)
        key_mac = binascii.unhexlify(hex_mac)
        nonce   = binascii.unhexlify(hex_nonce)
    except Exception as e:
        print(f"[ERROR] Formato de claves incorrecto: {e}")
        return

    print(f"\n[*] Leyendo captura: {input_file}...")
    try:
        packets = rdpcap(input_file)
    except FileNotFoundError:
        print("[ERROR] No se encuentra el archivo de entrada.")
        return

    decrypted_packets = []
    count_ok = 0
    count_total = 0

    print("[*] Procesando paquetes...")

    for pkt in packets:
        # Filtramos solo paquetes UDP relacionados con el puerto VPN
        if UDP in pkt and (pkt[UDP].sport == VPN_PORT or pkt[UDP].dport == VPN_PORT):
            count_total += 1
            
            # Extraer payload cifrado
            # Scapy a veces añade padding, aseguramos tomar solo el payload
            cipher_data = bytes(pkt[UDP].payload)
            
            if len(cipher_data) < 36: # Mínimo header+tag
                continue

            # 2. DESCIFRAR CON TU CÓDIGO PROPIO
            # El contador (0) no se usa, la función lo lee del header del paquete
            ok, plaintext = verify_and_decrypt(key_enc, key_mac, nonce, 0, cipher_data)

            if ok:
                # 3. RECONSTRUCCIÓN
                # plaintext es el paquete IP interno completo.
                # Lo convertimos a objeto Scapy para guardarlo en el nuevo PCAP.
                try:
                    # Creamos un paquete IP con los datos descifrados
                    ip_pkt = IP(plaintext)
                    # Mantenemos la marca de tiempo original para el orden
                    ip_pkt.time = pkt.time
                    decrypted_packets.append(ip_pkt)
                    count_ok += 1
                except Exception as e:
                    # Si no es un paquete IP válido, lo ignoramos
                    pass
            else:
                # Opcional: Imprimir error si falla HMAC
                # print(f"hmac fail packet #{count_total}")
                pass

    # 4. GUARDAR RESULTADO
    if count_ok > 0:
        print(f"\n[RESULTADO]")
        print(f"Paquetes analizados: {count_total}")
        print(f"Paquetes descifrados: {count_ok}")
        print(f"Generando archivo: {output_file} ...")
        
        wrpcap(output_file, decrypted_packets)
        
        print("\n[ÉXITO] ¡Archivo generado!")
        print(f"-> Abre '{output_file}' en Wireshark.")
        print("-> Verás el tráfico interno (PDF, Pings, Texto) totalmente legible.")
    else:
        print("\n[FALLO] No se pudo descifrar ningún paquete.")
        print("Verifica que las claves correspondan a ESTA captura específica.")

if __name__ == '__main__':
    main()