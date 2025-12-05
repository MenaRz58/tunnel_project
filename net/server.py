import argparse, socket, select, os
from net.tun_if import tun_create, tun_up # Importa funciones para crear y configurar la interfaz TUN
from net.handshake import Handshake # Importa la clase Handshake para manejar el protocolo de handshake
from crypto.aead import encrypt_then_mac, verify_and_decrypt # Importa funciones AEAD para cifrado y autenticación

# Constantes
MIN_IPV4_LEN = 20 # Longitud mínima de un paquete IPv4

# Función principal para ejecutar el servidor
def run_server(listen, port, tun_ip='10.10.0.1/30', tun_name='tun0'):
    # Crea y configura la interfaz TUN
    tun = tun_create(tun_name)

    # Intenta configurar la interfaz TUN con la IP proporcionada
    try:
        tun_up(tun_name, tun_ip) # Sube la interfaz TUN
    except Exception as e:
        print('Warning: tun_up failed:', e) # Muestra una advertencia si no se puede subir la interfaz TUN

    # Crea un socket UDP para escuchar conexiones entrantes
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Asocia el socket a la dirección y puerto especificados
    sock.bind((listen, port))

    # Muestra un mensaje indicando que el servidor está escuchando en la dirección y puerto especificados
    print(f"[SERVER] Listening {listen}:{port}")

    # Diccionario para almacenar el estado de los clientes conectados
    clients = {}

    # Bucle principal para manejar la comunicación entre TUN y UDP
    while True:
        # Espera hasta que haya datos para leer en el socket UDP o en la interfaz TUN
        r, _, _ = select.select([sock, tun], [], [])

        # Maneja datos entrantes en el socket UDP
        if sock in r:
            # Recibe datos y dirección del cliente
            data, addr = sock.recvfrom(65535)

            # Si el cliente es nuevo, inicia el handshake
            if addr not in clients:
                print(f"[HANDSHAKE] from {addr}") # Nuevo cliente, iniciando handshake
                hs = Handshake()

                # Intenta procesar la respuesta del servidor durante el handshake
                try:
                    resp = hs.server_response(data) # Procesa el mensaje INIT del cliente y genera la respuesta del servidor
                except Exception as e:
                    print("[HANDSHAKE] Error:", e) # Muestra un error si el handshake falla
                    continue

                # Almacena el estado del cliente en el diccionario
                clients[addr] = {'hs': hs, 'counter_send':1, 'counter_recv':1, 'finished':True}

                # Envía la respuesta del servidor al cliente
                sock.sendto(resp, addr)

                # Muestra información del handshake y las claves generadas
                print(f"[HANDSHAKE] Finished with {addr}")
                print(f"[KEYS] Enc: {hs.key_enc.hex()}")
                print(f"[KEYS] Mac: {hs.key_mac.hex()}")
                print(f"[KEYS] Nonce: {hs.nonce.hex()}")
                continue

            # Si el cliente ya existe, procesa los datos recibidos
            entry = clients[addr]

            # Obtiene el estado del handshake del cliente
            hs = entry['hs']

            # Verifica y descifra el mensaje recibido usando las claves del cliente
            ok, pt = verify_and_decrypt(hs.key_enc, hs.key_mac, hs.nonce, entry['counter_recv'], data)

            # Muestra información del paquete recibido y su estado de verificación
            print(f"[ALL RX] counter={entry['counter_recv']} ok={ok} len={len(pt)} first16={pt[:16].hex() if len(pt)>=16 else ''}")

            # Si la verificación fue exitosa, escribe el paquete en la interfaz TUN si es IPv4
            if len(pt) >= MIN_IPV4_LEN:
                # Verifica la versión del paquete IP
                version = pt[0] >> 4
                if version == 4:
                    os.write(tun, pt)
                else:
                    print(f"[TUN] Non-IPv4 packet, not writing to tun, first16={pt[:16].hex()} len={len(pt)}") # No es un paquete IPv4, no se escribe en TUN
            else:
                print(f"[TUN] Packet too short, not writing to tun, len={len(pt)}") # Paquete demasiado corto, no se escribe en TUN

            # Incrementa el contador de recepción del cliente
            print(f"[DECRYPT RX] counter={entry['counter_recv']} ok={ok} len(pt)={len(pt)} first16={pt[:16].hex()}")
            entry['counter_recv'] += 1

        # Maneja datos entrantes en la interfaz TUN
        if tun in r:
            # Lee un paquete desde la interfaz TUN
            pkt = os.read(tun, 65535)
            version = (pkt[0] >> 4) # Verifica la versión del paquete IP

            # Si el paquete no es IPv4, se ignora
            if version != 4:
                continue

            # Envía el paquete a todos los clientes conectados
            if len(pkt):
                # Recorre todos los clientes y envía el paquete cifrado
                for addr, entry in clients.items():
                    # Cifra y autentica el paquete antes de enviarlo por UDP
                    payload = encrypt_then_mac(hs.key_enc, hs.key_mac, hs.nonce, entry['counter_send'], pkt)

                    # Envía el paquete cifrado al cliente
                    sock.sendto(payload, addr)

                    # Muestra información sobre el paquete enviado
                    print(f"[UDP TX] to {addr} counter={entry['counter_send']} len={len(pkt)} first16={pkt[:16].hex() if len(pkt)>=16 else ''}")

                    # Incrementa el contador de envío del cliente
                    entry['counter_send'] += 1

# Punto de entrada del script
if __name__ == '__main__':
    parser = argparse.ArgumentParser() # Crea un analizador de argumentos para la línea de comandos
    parser.add_argument('--listen', default='0.0.0.0') # Dirección IP en la que el servidor escuchará
    parser.add_argument('--port', type=int, default=50000) # Puerto en el que el servidor escuchará
    parser.add_argument('--tun-ip', default='10.10.0.1/30') # Dirección IP y máscara para la interfaz TUN
    parser.add_argument('--tun-name', default='tun0') # Nombre de la interfaz TUN   
    args = parser.parse_args() # Parsea los argumentos de la línea de comandos
    run_server(args.listen, args.port, args.tun_ip, args.tun_name) # Ejecuta el servidor con los parámetros proporcionados
