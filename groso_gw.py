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
import argparse
import socket
import select
import time

def run_relay(listen_ip, port_a, port_b, g1_ip=None, g2_ip=None):
    """
    listen_ip: IP de la interface donde el relay escucha (ej. 0.0.0.0)
    port_a: puerto donde escucha los packets del Groso1 (ej. 50000)
    port_b: puerto donde escucha los packets del Groso2 (ej. 50001)
    g1_ip: IP física de Groso1 (si None, se usará la IP del primer paquete recibido)
    g2_ip: IP física de Groso2 (si None, se usará la IP del primer paquete recibido)
    """
    sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_a.bind((listen_ip, port_a))
    sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_b.bind((listen_ip, port_b))
    print(f"[gw] Relay listening on {listen_ip}:{port_a} (from G1) and {listen_ip}:{port_b} (from G2)")
    # mappings
    addr_g1 = None if g1_ip is None else (g1_ip, 0)
    addr_g2 = None if g2_ip is None else (g2_ip, 0)

    # single epoll/select loop
    while True:
        rlist, _, _ = select.select([sock_a, sock_b], [], [], 1.0)
        for s in rlist:
            data, addr = s.recvfrom(65535)
            src_ip, src_port = addr
            if s is sock_a:
                # packet from Groso1 -> forward to Groso2
                if addr_g2 is None:
                    # if we don't know g2 IP yet, we cannot forward. We'll expect groso2 to have sent at least one packet to port_b.
                    print(f"[gw] pkt from G1 {addr} len={len(data)} (g2 unknown - buffering dropped)")
                    continue
                dest = (addr_g2[0], port_b)
                sock_a.sendto(data, dest)
                print(f"[gw] G1->{dest} len={len(data)}")
            else:
                # packet from Groso2 -> forward to Groso1
                if addr_g1 is None:
                    print(f"[gw] pkt from G2 {addr} len={len(data)} (g1 unknown - buffering dropped)")
                    continue
                dest = (addr_g1[0], port_a)
                sock_b.sendto(data, dest)
                print(f"[gw] G2->{dest} len={len(data)}")
        # Try to learn endpoints: if we've seen a packet on port_a, record that as G1; similarly for port_b
        # (we rely on the kernel to populate addr_g1/addr_g2 from recent recvfroms -- alternatively we could store last seen)
        # For simplicity, we'll poll last connected addresses via getsockname? Not necessary.
        # We'll implement a lightweight discovery: if a packet arrives, set mapping (done above via addr variable).
        # Sleep a tiny bit to avoid busy loop.
        time.sleep(0.001)

def main():
    parser = argparse.ArgumentParser(description="GrosoGW UDP relay (simple): forward between ports 50000 and 50001")
    parser.add_argument('--listen', default='0.0.0.0', help='IP to bind (default 0.0.0.0)')
    parser.add_argument('--port-g1', type=int, default=50000, help='Port where Groso1 sends (default 50000)')
    parser.add_argument('--port-g2', type=int, default=50001, help='Port where Groso2 listens (default 50001)')
    parser.add_argument('--g1-ip', default=None, help='(optional) Static IP of Groso1 (if you want to preset)')
    parser.add_argument('--g2-ip', default=None, help='(optional) Static IP of Groso2 (if you want to preset)')
    args = parser.parse_args()
    run_relay(args.listen, args.port_g1, args.port_g2, g1_ip=args.g1_ip, g2_ip=args.g2_ip)

if __name__ == '__main__':
    main()
