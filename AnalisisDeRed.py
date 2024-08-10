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

def parse_tcp_header(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'sequence': sequence,
        'acknowledgment': acknowledgment,
        'header_length': offset
    }

def filter_traffic(packet, protocol):
    if protocol == 'TCP' and packet['protocol'] == 6:
        return True
    elif protocol == 'UDP' and packet['protocol'] == 17:
        return True
    elif protocol == 'ICMP' and packet['protocol'] == 1:
        return True
    return False
