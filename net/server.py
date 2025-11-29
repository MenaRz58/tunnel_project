import argparse, socket, select, os
from net.tun_if import tun_create, tun_up
from net.handshake import Handshake
from crypto.aead import encrypt_then_mac, verify_and_decrypt

MIN_IPV4_LEN = 20 # Longitud mínima de un paquete IPv4

def run_server(listen, port, tun_ip='10.10.0.1/30', tun_name='tun0'):
    tun = tun_create(tun_name)
    try:
        tun_up(tun_name, tun_ip)
    except Exception as e:
        print('Warning: tun_up failed:', e)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen, port))
    print(f"[SERVER] Listening {listen}:{port}")

    clients = {}

    while True:
        r, _, _ = select.select([sock, tun], [], [])
        if sock in r:
            data, addr = sock.recvfrom(65535)
            if addr not in clients:
                print(f"[HANDSHAKE] from {addr}")
                hs = Handshake()
                try:
                    resp = hs.server_response(data)
                except Exception as e:
                    print("[HANDSHAKE] Error:", e)
                    continue
                clients[addr] = {'hs': hs, 'counter_send':1, 'counter_recv':1, 'finished':True}
                sock.sendto(resp, addr)
                print(f"[HANDSHAKE] Finished with {addr}")
                print(f"[KEYS] Enc: {hs.key_enc.hex()}")
                print(f"[KEYS] Mac: {hs.key_mac.hex()}")
                print(f"[KEYS] Nonce: {hs.nonce.hex()}")
                continue

            entry = clients[addr]
            hs = entry['hs']
            ok, pt = verify_and_decrypt(hs.key_enc, hs.key_mac, hs.nonce, entry['counter_recv'], data)
            print(f"[ALL RX] counter={entry['counter_recv']} ok={ok} len={len(pt)} first16={pt[:16].hex() if len(pt)>=16 else ''}")

            if len(pt) >= MIN_IPV4_LEN:
                version = pt[0] >> 4
                if version == 4:
                    os.write(tun, pt)
                else:
                    print(f"[TUN] Non-IPv4 packet, not writing to tun, first16={pt[:16].hex()} len={len(pt)}")
            else:
                print(f"[TUN] Packet too short, not writing to tun, len={len(pt)}")

            print(f"[DECRYPT RX] counter={entry['counter_recv']} ok={ok} len(pt)={len(pt)} first16={pt[:16].hex()}")
            entry['counter_recv'] += 1

        if tun in r:
            pkt = os.read(tun, 65535)
            version = (pkt[0] >> 4)
            if version != 4:
                continue
            if len(pkt):
                for addr, entry in clients.items():
                    payload = encrypt_then_mac(hs.key_enc, hs.key_mac, hs.nonce, entry['counter_send'], pkt)
                    sock.sendto(payload, addr)
                    print(f"[UDP TX] to {addr} counter={entry['counter_send']} len={len(pkt)} first16={pkt[:16].hex() if len(pkt)>=16 else ''}")
                    entry['counter_send'] += 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--listen', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=50000)
    parser.add_argument('--tun-ip', default='10.10.0.1/30')
    parser.add_argument('--tun-name', default='tun0')
    args = parser.parse_args()
    run_server(args.listen, args.port, args.tun_ip, args.tun_name)
