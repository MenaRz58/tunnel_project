# """
# Utilities para manejar TUN en Linux.
# """
# import os, fcntl, struct, subprocess


# TUNSETIFF = 0x400454ca
# IFF_TUN = 0x0001
# IFF_TAP = 0x0002
# IFF_NO_PI = 0x1000


# def tun_create(name='tun0'):
#     tun = os.open('/dev/net/tun', os.O_RDWR)
#     ifr = struct.pack('16sH', name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
#     fcntl.ioctl(tun, TUNSETIFF, ifr)
#     return tun


# def tun_up(name='tun0', ip='10.10.0.1/30', mtu=1400):
#     subprocess.check_call(['ip', 'addr', 'add', ip, 'dev', name])
#     subprocess.check_call(['ip', 'link', 'set', 'dev', name, 'mtu', str(mtu)])
#     subprocess.check_call(['ip', 'link', 'set', 'dev', name, 'up'])


"""
Utilities para manejar TUN en Linux.
"""
import os, fcntl, struct, subprocess

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

def tun_create(name='tun0'):
    tun = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    return tun

def tun_up(name='tun0', ip='10.10.0.1/30', mtu=1400):
    subprocess.check_call(['ip', 'addr', 'add', ip, 'dev', name])
    subprocess.check_call(['ip', 'link', 'set', 'dev', name, 'mtu', str(mtu)])
    subprocess.check_call(['ip', 'link', 'set', 'dev', name, 'up'])
