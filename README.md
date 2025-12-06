# tunnel_project

**Proyecto — Canal Cifrado Virtual (TUN) Implementado Desde Cero**

Este proyecto consiste en la construcción de un canal de comunicación cifrado y autenticado implementado totalmente desde cero. El objetivo principal es demostrar que es posible diseñar una VPN funcional sin depender de bibliotecas criptográficas externas, utilizando únicamente primitivas desarrolladas manualmente en Python. Se implementaron mecanismos completos de cifrado, autenticación y derivación de claves, junto con un protocolo de handshake Diffie-Hellman efímero autenticado y encapsulación de tráfico IP mediante una interfaz TUN transportada sobre UDP.

El sistema fue desarrollado y probado en Python 3 sobre Ubuntu Server, usando dos máquinas virtuales conectadas dentro de una misma red interna. El túnel permite el envío transparente de tráfico IP, incluyendo pings y transferencia de archivos, garantizando confidencialidad, integridad y autenticación mutua. Adicionalmente, se incluyen herramientas para descifrado offline del tráfico capturado, con el fin de validar experimentalmente la seguridad del diseño.

**Ejecución rápida**

El proyecto incluye scripts para desplegar un canal cifrado funcional con tres nodos: un gateway (GrosoGW) actuando como servidor del túnel y dos clientes (Groso1 y Groso2). Todos utilizan el mismo protocolo criptográfico, con intercambio efímero de claves Diffie–Hellman, cifrado ChaCha20 y autenticación HMAC bajo el esquema Encrypt-then-MAC. Para ejecutarlos es necesario contar con privilegios de root, ya que la creación de la interfaz TUN requiere acceso a /dev/net/tun.

* Modo directo (rápido y sencillo)
Para iniciar el sistema de la manera más simple, basta con arrancar el servidor y luego los clientes. En la máquina que actuará como gateway se ejecuta:
*sudo python3 net/server.py --listen 0.0.0.0 --port 50000*

Posteriormente, en Groso1 se corre:
*sudo python3 groso1.py --peer <IP_GATEWAY> --port 50000*

Groso2 se ejecuta de forma similar, cambiando únicamente el script correspondiente. Cuando ambos clientes completen el handshake con GrosoGW, cada uno obtendrá una interfaz TUN propia. A partir de ese punto podrán intercambiar tráfico cifrado extremo a extremo a través del servidor.

Modo recomendado para laboratorio

En un escenario realista se recomienda utilizar la topología:

[ Groso1 ]  ⇆  [ GrosoGW ]  ⇆  [ Groso2 ]
     tun1         tun0           tun2


Primero se lanza el gateway con el comando anterior. Luego, Groso1 puede iniciarse con:
*sudo python3 groso1.py --peer <IP_GATEWAY> --port 50000 --tun-ip 10.10.0.2/30 --tun-name tun1*

Esto realizará el handshake, negociará claves y activará la interfaz tun1. Después, Groso2 puede levantarse de manera similar:
*sudo python3 groso2.py --peer <IP_GATEWAY> --port 50000 --tun-ip 10.10.0.6/30 --tun-name tun2*

Con ambos clientes conectados, el túnel queda disponible para pruebas de conectividad (ping, transferencia de archivos, tráfico TCP/UDP), pudiendo además capturar paquetes en la red y verificar que el contenido permanece cifrado.

* Scripts adicionales incluidos

Además de los clientes y el gateway, el repositorio contiene un script llamado groso_gw.py que actúa como alternativa de ejecución del servidor, automatizando parte del proceso. El archivo proof_decrypt.py permite validar el descifrado utilizando claves derivadas, útil para comprobación en entornos controlados. Del mismo modo, el script tools/offline_decrypt.py puede emplearse para análisis forense o verificación de PCAPs capturados, siempre que se posea la clave correspondiente.

**Contenido del proyecto**

El repositorio está organizado en módulos que separan claramente la capa criptográfica, la capa de protocolo, las herramientas auxiliares y los scripts para la ejecución práctica en laboratorio. Dentro de crypto/ se encuentran las implementaciones manuales de SHA-256, HMAC, HKDF, ChaCha20 y Diffie-Hellman, junto con el esquema AEAD Encrypt-then-MAC. En net/ reside la lógica del túnel TUN sobre UDP, el handshake autenticado y los controladores del cliente/servidor. El directorio tools/ incluye utilidades para análisis forense y descifrado offline, mientras que en la raíz se encuentran scripts de automatización y ejecución para los nodos del entorno experimental.

La estructura principal del repositorio es la siguiente:

crypto/ → primitivas criptográficas implementadas a mano
net/ → túnel TUN, handshake, cliente y servidor
tools/ → descifrador offline, análisis y verificación
groso_gw.py, groso1.py, groso2.py → scripts de ejecución para las VMs del laboratorio
proof_decrypt.py → validación y descifrado controlado para pruebas
run_server.sh / run_client.sh → ejecución rápida del demo

**Nota importante**

Este desarrollo tiene fines estrictamente académicos y experimentales. No es seguro para uso en producción ni reemplaza protocolos reales como IPsec, WireGuard o TLS. El código y el informe técnico contienen un análisis detallado de la seguridad, sus limitaciones y las pruebas realizadas para validar funcionamiento, rendimiento y resistencia frente a ataques controlados.

Para entender el protocolo, el razonamiento criptográfico y la reproducibilidad del experimento, se recomienda consultar el informe complementario incluido junto con este repositorio.