#!/usr/bin/env python3
"""
groso2.py - Servidor lado Groso2
Usa net/server.py -> run_server(listen, port, tun_ip)
Por defecto escucha en puerto 50001 (gateway reenviará a ese puerto).
Ejecutar con sudo (necesita /dev/net/tun).
"""
import argparse
import os
import sys

# Ajusta el path si ejecutas desde otra carpeta
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT) # Añade el directorio del proyecto al path

from net.server import run_server # Importa la función run_server

# Función principal
def main():
    # Parseo de argumentos
    parser = argparse.ArgumentParser(description="Groso2 server - escucha handshake y crea tun")

    #parser.add_argument('--listen', default='0.0.0.0', help='IP de escucha local')
    parser.add_argument('--listen', default='0.0.0.0', help='IP de escucha local')

    #parser.add_argument('--port', type=int, default=50001, help='Puerto a escuchar (default 50001)')
    parser.add_argument('--port', type=int, default=50001, help='Puerto a escuchar (default 50001)')
    parser.add_argument('--tun-ip', default='10.20.0.2/30', help='IP que usará el tun local (default 10.20.0.2/30)') # IP que usará la interfaz TUN local
    parser.add_argument('--tun-name', default='tun2', help='Nombre de la interfaz TUN local') # Nombre de la interfaz TUN local
    args = parser.parse_args() # Parsea los argumentos de la línea de comandos
     
    # Mostrar configuración
    print(f"[groso2] Escuchando {args.listen}:{args.port}, tun {args.tun_ip} ({args.tun_name})")

    # run_server crea tun y espera handshake
    run_server(args.listen, args.port, tun_ip=args.tun_ip, tun_name=args.tun_name)

# Punto de entrada del script
if __name__ == '__main__':
    if os.geteuid() != 0:
        print("Este script requiere privilegios de root. Ejecuta con sudo.") # Mensaje de error si no se ejecuta como root
        sys.exit(1) # Sale del programa con código de error 
    main()
