import argparse, socket, select, os
from net.tun_if import tun_create, tun_up
from net.handshake import Handshake
from crypto.aead import encrypt_then_mac, verify_and_decrypt

MIN_IPV4_LEN = 20

def run_client(peer_ip, port, tun_ip='10.10.0.2/30', tun_name='tun0'):
    tun = tun_create(tun_name)
    try:
        tun_up(tun_name, tun_ip)
    except Exception as e:
        print('Warning: tun_up failed:', e)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 0))

    hs = Handshake(psk=b'CRIPTOGRAFIA_CONTRASENA_SECRETA')
    init = hs.client_init()
    print("[HANDSHAKE] Sending INIT")
    sock.sendto(init, (peer_ip, port))

    data, _ = sock.recvfrom(65535)
    final = hs.client_finish(data)
    sock.sendto(final, (peer_ip, port))
    print("[HANDSHAKE] Finished")
    print(f"[KEYS] Enc: {hs.key_enc.hex()}")
    print(f"[KEYS] Mac: {hs.key_mac.hex()}")
    print(f"[KEYS] Nonce: {hs.nonce.hex()}")

    counter_send = 1
    counter_recv = 1

    while True:
        r, _, _ = select.select([sock, tun], [], [])
        if tun in r:
            pkt = os.read(tun, 65535)
            if len(pkt) == 0: 
                continue
            version = (pkt[0] >> 4)
            if version != 4:
                continue
            payload = encrypt_then_mac(hs.key_enc, hs.key_mac, hs.nonce, counter_send, pkt)
            sock.sendto(payload, (peer_ip, port))
            print(f"[TUN TX] Envíando {len(pkt)} bytes (IPv4)")
            counter_send += 1

        if sock in r:
            data, addr = sock.recvfrom(65535)
            ok, pt = verify_and_decrypt(hs.key_enc, hs.key_mac, hs.nonce, counter_recv, data)
            if not ok:
                print(f"[UDP RX] counter={counter_recv} ok=False invalid MAC")
                counter_recv += 1
                continue
            # Solo escribir si el paquete parece válido (IPv4 mínimo 20 bytes)
            if len(pt) >= MIN_IPV4_LEN:
                version = pt[0] >> 4
                if version == 4:
                    os.write(tun, pt)
                else:
                    print(f"[TUN] Skipped non-IPv4 packet first16={pt[:16].hex()} len={len(pt)}")
            else:
                print(f"[TUN] Skipped too short packet first16={pt[:16].hex()} len={len(pt)}")
            if pt[0] == 0x45:  
                os.write(tun, pt)
            else:
                print(f"[TUN] Skipped invalid packet first16={pt[:16].hex()} len={len(pt)}")
            print(f"[UDP RX] counter={counter_recv} ok=True len(pt)={len(pt)} first16={pt[:16].hex()}")
            counter_recv += 1

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--peer', required=True)
    parser.add_argument('--port', type=int, default=50000)
    parser.add_argument('--tun-ip', default='10.10.0.2/30')
    parser.add_argument('--tun-name', default='tun0')
    args = parser.parse_args()
    run_client(args.peer, args.port, args.tun_ip, args.tun_name)
