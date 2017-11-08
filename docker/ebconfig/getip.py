#!/usr/bin/env python3

import sys
import fcntl
import socket
import struct

def get_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    st = struct.Struct('256s')

    #struct.pack('256s', ifname[:15])

    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.Struct('256s').pack(ifname[:15].encode('utf-8'))
    )[20:24])



print(get_ip(sys.argv[1]))
