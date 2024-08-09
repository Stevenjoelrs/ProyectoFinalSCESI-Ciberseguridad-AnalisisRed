import socket
import struct

def parse_ethernet_header(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return {
        'dest_mac': ':'.join(format(x, '02x') for x in dest_mac),
        'src_mac': ':'.join(format(x, '02x') for x in src_mac),
        'protocol': socket.htons(proto)
    }

def parse_ip_header(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return {
        'version': version,
        'header_length': header_length,
        'ttl': ttl,
        'protocol': proto,
        'src_ip': socket.inet_ntoa(src),
        'dest_ip': socket.inet_ntoa(target)
    }