"""
Utilities para manejar TUN en Linux.
"""
import os, fcntl, struct, subprocess

# Definiciones de constantes para configurar la interfaz TUN
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

# Crea una interfaz TUN con el nombre especificado
def tun_create(name='tun0'):
    # Abre el dispositivo TUN
    tun = os.open('/dev/net/tun', os.O_RDWR)

    # Configura la interfaz TUN con el nombre y las banderas adecuadas
    ifr = struct.pack('16sH', name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
    
    # Realiza la llamada ioctl para configurar la interfaz TUN
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    return tun # Devuelve el descriptor de archivo de la interfaz TUN

# Sube la interfaz TUN con la IP y MTU especificadas
def tun_up(name='tun0', ip='10.10.0.1/30', mtu=1400):
    subprocess.check_call(['ip', 'addr', 'add', ip, 'dev', name]) # Asigna la dirección IP a la interfaz TUN
    subprocess.check_call(['ip', 'link', 'set', 'dev', name, 'mtu', str(mtu)]) # Configura el MTU de la interfaz TUN
    subprocess.check_call(['ip', 'link', 'set', 'dev', name, 'up']) # Sube la interfaz TUN  