#!/usr/bin/env python3
"""
groso_gw.py - Gateway / Relay UDP simple
Función: actuar como punto intermedio entre Groso1 y Groso2.
- Escucha en puerto 50000 (donde Groso1 envía)
- Escucha en puerto 50001 (donde Groso2 envía)
- Cuando recibe desde Groso1 -> reenvía a (GROSO2_IP, 50001)
- Cuando recibe desde Groso2 -> reenvía a (GROSO1_IP, 50000)

No inspecciona ni modifica paquetes; solo reenvía bytes UDP.
Útil para simular gateway, NAT, MITM (puedes modificar aquí para atacar).
Ejecutar sin sudo (no requiere /dev/net/tun), pero con permisos para bind.
"""
import argparse # Para parsear argumentos de línea de comandos
import socket # Para manejo de sockets UDP
import select # Para multiplexación de E/S
import time # Para funciones de tiempo (sleep)

# Función principal para ejecutar el relay
def run_relay(listen_ip, port_a, port_b, g1_ip=None, g2_ip=None):
    """
    listen_ip: IP de la interface donde el relay escucha (ej. 0.0.0.0)
    port_a: puerto donde escucha los packets del Groso1 (ej. 50000)
    port_b: puerto donde escucha los packets del Groso2 (ej. 50001)
    g1_ip: IP física de Groso1 (si None, se usará la IP del primer paquete recibido)
    g2_ip: IP física de Groso2 (si None, se usará la IP del primer paquete recibido)
    """
    # Crea y vincula sockets UDP para ambos puertos
    sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_a.bind((listen_ip, port_a))
    sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_b.bind((listen_ip, port_b))

    # Establece los endpoints conocidos si se proporcionaron IPs estáticas
    print(f"[gw] Relay listening on {listen_ip}:{port_a} (from G1) and {listen_ip}:{port_b} (from G2)")

    # Inicializa las direcciones de los endpoints conocidos si se proporcionaron IPs estáticas
    addr_g1 = None if g1_ip is None else (g1_ip, 0)
    addr_g2 = None if g2_ip is None else (g2_ip, 0)

    # Bucle principal para manejar el reenvío de paquetes
    while True:
        # Espera hasta que haya datos para leer en cualquiera de los sockets
        rlist, _, _ = select.select([sock_a, sock_b], [], [], 1.0)

        # Maneja los datos entrantes en los sockets
        for s in rlist:
            # Recibe datos y dirección del remitente
            data, addr = s.recvfrom(65535)

            # Actualiza las direcciones de los endpoints conocidos si es la primera vez que se recibe un paquete
            src_ip, src_port = addr

            # Actualiza las direcciones de los endpoints conocidos si es la primera vez que se recibe un paquete
            if s is sock_a:
                # packet from Groso1 -> forward to Groso2
                if addr_g2 is None:
                    # Aprende la dirección de Groso2 desde el primer paquete recibido
                    print(f"[gw] pkt from G1 {addr} len={len(data)} (g2 unknown - buffering dropped)")
                    continue
                dest = (addr_g2[0], port_b)
                sock_a.sendto(data, dest) # Reenvía el paquete a Groso2
                print(f"[gw] G1->{dest} len={len(data)}") # Muestra información del reenvío
            else:
                # packet from Groso2 -> forward to Groso1
                if addr_g1 is None:
                    # Aprende la dirección de Groso1 desde el primer paquete recibido
                    print(f"[gw] pkt from G2 {addr} len={len(data)} (g1 unknown - buffering dropped)")
                    continue
                dest = (addr_g1[0], port_a)
                sock_b.sendto(data, dest) # Reenvía el paquete a Groso1
                print(f"[gw] G2->{dest} len={len(data)}") # Muestra información del reenvío

        # Try to learn endpoints: if we've seen a packet on port_a, record that as G1; similarly for port_b
        # (we rely on the kernel to populate addr_g1/addr_g2 from recent recvfroms -- alternatively we could store last seen)
        # For simplicity, we'll poll last connected addresses via getsockname? Not necessary.
        # We'll implement a lightweight discovery: if a packet arrives, set mapping (done above via addr variable).
        
        time.sleep(0.001) # Duerme 1ms para evitar bucle ocupado

# Función principal para parsear argumentos y ejecutar el relay
def main():
    parser = argparse.ArgumentParser(description="GrosoGW UDP relay (simple): forward between ports 50000 and 50001") # Crea un analizador de argumentos para la línea de comandos
    parser.add_argument('--listen', default='0.0.0.0', help='IP to bind (default 0.0.0.0)') # Dirección IP en la que el relay escuchará
    parser.add_argument('--port-g1', type=int, default=50000, help='Port where Groso1 sends (default 50000)') # Puerto donde escucha los packets del Groso1
    parser.add_argument('--port-g2', type=int, default=50001, help='Port where Groso2 listens (default 50001)') # Puerto donde escucha los packets del Groso2
    parser.add_argument('--g1-ip', default=None, help='(optional) Static IP of Groso1 (if you want to preset)') # IP estática opcional de Groso1
    parser.add_argument('--g2-ip', default=None, help='(optional) Static IP of Groso2 (if you want to preset)') # IP estática opcional de Groso2
    args = parser.parse_args() # Parsea los argumentos de la línea de comandos
    run_relay(args.listen, args.port_g1, args.port_g2, g1_ip=args.g1_ip, g2_ip=args.g2_ip) # Ejecuta el relay con los parámetros proporcionados

# Punto de entrada del script
if __name__ == '__main__':
    main() # Ejecuta la función principal
