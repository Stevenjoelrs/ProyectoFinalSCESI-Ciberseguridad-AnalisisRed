import socket
import struct

def parse_ethernet_header(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return {
        'dest_mac': ':'.join(format(x, '02x') for x in dest_mac),
        'src_mac': ':'.join(format(x, '02x') for x in src_mac),
        'protocol': socket.htons(proto)
    }
