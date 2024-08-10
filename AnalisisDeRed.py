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
    elif protocol == 'HTTP' and packet['protocol'] == 6 and ('src_port' in packet and 'dest_port' in packet) and (packet['src_port'] == 80 or packet['dest_port'] == 80):
        return True
    return False

def scan_ports(ip): #escanea que puertos estan abiertos
    open_ports = []
    for port in range(1, 1024):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def main(protocol_filter=None):
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        raw_data, addr = conn.recvfrom(65536)
        ethernet_header = parse_ethernet_header(raw_data)
        print('\nEthernet Header:', ethernet_header)
        
        if ethernet_header['protocol'] == 8:  # IPv4
            ip_header = parse_ip_header(raw_data[14:])
            print('IP Header:', ip_header)
            
            if protocol_filter and not filter_traffic(ip_header, protocol_filter):
                continue
            
            if ip_header['protocol'] == 6:  # TCP
                tcp_header = parse_tcp_header(raw_data[14 + ip_header['header_length']:])
                print('TCP Header:', tcp_header)

if __name__ == "__main__":
    protocol = input("Ingrese el tipo de tráfico a filtrar (TCP, UDP, ICMP) o presione Enter para capturar todo: ")
    main(protocol_filter=protocol.upper() if protocol else None)