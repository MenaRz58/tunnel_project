import argparse, socket, select, os # Importa módulos necesarios
from net.tun_if import tun_create, tun_up # Importa funciones para crear y configurar la interfaz TUN
from net.handshake import Handshake # Importa la clase Handshake para manejar el protocolo de handshake
from crypto.aead import encrypt_then_mac, verify_and_decrypt # Importa funciones AEAD para cifrado y autenticación

# Define la longitud mínima de un paquete IPv4
MIN_IPV4_LEN = 20

# Función principal para ejecutar el cliente
def run_client(peer_ip, port, tun_ip='10.10.0.2/30', tun_name='tun0'):
    # Crea y configura la interfaz TUN
    tun = tun_create(tun_name)

    # Sube la interfaz TUN con la IP especificada
    try:
        tun_up(tun_name, tun_ip)
    
    # Maneja excepciones si no se puede subir la interfaz TUN
    except Exception as e:
        # Muestra una advertencia si no se puede subir la interfaz TUN
        print('Warning: tun_up failed:', e)

    # Crea un socket UDP para comunicarse con el servidor
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 0))

    hs = Handshake(psk=b'CRIPTOGRAFIA_CONTRASENA_SECRETA')
    init = hs.client_init()

    # Envía el mensaje INIT al servidor
    print("[HANDSHAKE] Sending INIT")
    sock.sendto(init, (peer_ip, port))

    # Espera la respuesta del servidor y completa el handshake
    data, _ = sock.recvfrom(65535)

    # Procesa la respuesta del servidor y obtiene las claves y nonce
    final = hs.client_finish(data)

    # Envía el mensaje FINAL al servidor
    sock.sendto(final, (peer_ip, port))

    # Handshake completado, muestra las claves y nonce
    print("[HANDSHAKE] Finished")
    print(f"[KEYS] Enc: {hs.key_enc.hex()}")
    print(f"[KEYS] Mac: {hs.key_mac.hex()}")
    print(f"[KEYS] Nonce: {hs.nonce.hex()}")

    # Inicializa los contadores de envío y recepción
    counter_send = 1
    counter_recv = 1

    # Bucle principal para manejar la comunicación entre TUN y UDP
    while True:
        # Espera hasta que haya datos para leer en el socket UDP o en la interfaz TUN
        r, _, _ = select.select([sock, tun], [], [])

        # Maneja datos entrantes en la interfaz TUN
        if tun in r:
            # Lee un paquete de la interfaz TUN
            pkt = os.read(tun, 65535)

            # Ignora paquetes vacíos o no IPv4
            if len(pkt) == 0: 
                continue

            # Verifica que el paquete sea IPv4
            version = (pkt[0] >> 4)

            # Si el paquete no es IPv4, se ignora
            if version != 4:
                continue

            # Cifra y autentica el paquete antes de enviarlo por UDP
            payload = encrypt_then_mac(hs.key_enc, hs.key_mac, hs.nonce, counter_send, pkt)

            # Envía el paquete cifrado al servidor
            sock.sendto(payload, (peer_ip, port))

            # Muestra información sobre el paquete enviado
            print(f"[TUN TX] Envíando {len(pkt)} bytes (IPv4)")

            # Incrementa el contador de envío
            counter_send += 1

        # Maneja datos entrantes en el socket UDP
        if sock in r:
            # Recibe un paquete del socket UDP
            data, addr = sock.recvfrom(65535)

            # Verifica y descifra el paquete recibido
            ok, pt = verify_and_decrypt(hs.key_enc, hs.key_mac, hs.nonce, counter_recv, data)
            
            # Verifica si la autenticación fue exitosa
            if not ok:
                # Si la autenticación falla, muestra un mensaje y continúa
                print(f"[UDP RX] counter={counter_recv} ok=False invalid MAC")

                # Incrementa el contador de recepción y continúa con el siguiente paquete
                counter_recv += 1
                continue
            # Solo escribir si el paquete parece válido (IPv4 mínimo 20 bytes)
            if len(pt) >= MIN_IPV4_LEN:
                # Verifica que el paquete sea IPv4
                version = pt[0] >> 4

                # Verifica que el paquete sea IPv4
                if version == 4:
                    # Escribe el paquete descifrado en la interfaz TUN
                    os.write(tun, pt)
                else:
                    # Si el paquete no es IPv4, se ignora
                    print(f"[TUN] Skipped non-IPv4 packet first16={pt[:16].hex()} len={len(pt)}")
            else:
                # Si el paquete es demasiado corto, se ignora
                print(f"[TUN] Skipped too short packet first16={pt[:16].hex()} len={len(pt)}")
            
            # Verifica si el paquete es un paquete IPv4 válido con encabezado estándar
            if pt[0] == 0x45:  
                # Escribe el paquete descifrado en la interfaz TUN
                os.write(tun, pt)

            # Muestra información sobre el paquete recibido    
            else:
                # Si el paquete no es válido, se ignora
                print(f"[TUN] Skipped invalid packet first16={pt[:16].hex()} len={len(pt)}")
            print(f"[UDP RX] counter={counter_recv} ok=True len(pt)={len(pt)} first16={pt[:16].hex()}")
            counter_recv += 1

# Ejecuta el cliente si se llama directamente desde la línea de comandos
if __name__ == '__main__':
    parser = argparse.ArgumentParser() # Crea un parser de argumentos
    parser.add_argument('--peer', required=True) # Dirección IP del servidor
    parser.add_argument('--port', type=int, default=50000) # Puerto del servidor
    parser.add_argument('--tun-ip', default='10.10.0.2/30') # Dirección IP de la interfaz TUN
    parser.add_argument('--tun-name', default='tun0') # Nombre de la interfaz TUN
    args = parser.parse_args() # Parsea los argumentos de la línea de comandos
    run_client(args.peer, args.port, args.tun_ip, args.tun_name) # Ejecuta el cliente con los argumentos proporcionados
