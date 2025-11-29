#!/usr/bin/env python3
"""
groso1.py - Cliente lado Groso1
Usa net/client.py -> run_client(peer_ip, port, tun_ip)
Por defecto envía a la gateway (GrosoGW) en puerto 50000.
Ejecutar con sudo (necesita /dev/net/tun).
"""
import argparse
import os
import sys

# Ajusta el path si ejecutas desde otra carpeta
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from net.client import run_client

def main():
    parser = argparse.ArgumentParser(description="Groso1 client - inicia handshake hacia GrosoGW")
    #parser.add_argument('--peer', default='192.168.10.1', help='IP de la gateway (GrosoGW). Default: 192.168.10.1')
    parser.add_argument('--peer', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=50001)
    #parser.add_argument('--port', type=int, default=50000, help='Puerto de la gateway (default 50000)')
    parser.add_argument('--tun-ip', default='10.10.0.2/30', help='IP que usará el tun local (default 10.10.0.2/30)')
    parser.add_argument('--tun-name', default='tun1', help='Nombre de la interfaz TUN local')
    args = parser.parse_args()
    
    print(f"[groso1] Enviando handshake a {args.peer}:{args.port} y configurando tun {args.tun_ip} ({args.tun_name})")
    # run_client crea tun y hace handshake
    run_client(args.peer, args.port, tun_ip=args.tun_ip, tun_name=args.tun_name)

if __name__ == '__main__':
    # Ejecutar con sudo
    if os.geteuid() != 0:
        print("Este script requiere privilegios de root. Ejecuta con sudo.")
        sys.exit(1)
    main()
