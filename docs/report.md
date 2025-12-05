
Proyecto: Canal cifrado virtual (TUN) - Implementación desde cero
Lenguaje: Python 3 (probado en Ubuntu Server)
Descripción: Implementación educativa de primitives criptográficas (SHA-256, HMAC, HKDF, ChaCha20), protocolo DH ephemeral, handshake autenticado, e implementación de un túnel TUN sobre UDP con Encrypt-then-MAC.


Instrucciones rápidas:
1. Poner las máquinas en la red interna de VirtualBox.
2. Copiar la carpeta del proyecto a las VMs (Groso1, Groso2).
3. Con sudo: crear tun0 fuera del script o permitir que el script lo haga.
4. En servidor: sudo python3 net/server.py --listen 0.0.0.0 --port 50000
En cliente: sudo python3 net/client.py --peer 192.168.56.12 --port 50000


Archivos incluidos:
- crypto/sha256.py
- crypto/hmac.py
- crypto/hkdf.py
- crypto/chacha20.py
- crypto/dh.py
- crypto/aead.py
- net/tun_if.py
- net/handshake.py
- net/server.py
- net/client.py
- tools/offline_decrypt.py
- run_server.sh
- run_client.sh
- groso_gw.py
- groso1.py
- groso2.py
- proof_decrypt.py


Nota: Esta implementación está hecha con fines académicos y demostrativos; revisa el informe teórico para discutir seguridad, consideraciones y pruebas.
