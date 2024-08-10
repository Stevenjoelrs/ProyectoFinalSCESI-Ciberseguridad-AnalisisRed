import socket
import struct
import subprocess
from collections import defaultdict
from colorama import Fore, Style, init

init()

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

def parse_http_header(data):
    try:
        http_data = data.decode('utf-8')
        headers = http_data.split('\r\n')
        return headers
    except UnicodeDecodeError:
        return None

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

def scan_ports(ip):
    open_ports = []
    for port in range(1, 1024):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def run_nmap(ip):
    result = subprocess.run(['nmap', '-sV', ip], capture_output=True, text=True)
    return result.stdout

def send_alert(message):
    print(f"{Fore.RED}ALERTA: {message}{Style.RESET_ALL}")

def detect_anomalies(ip, packet_count):
    if packet_count[ip] > 1500:  # Umbral de ejemplo
        send_alert(f'Tráfico inusual detectado desde {ip}: {packet_count[ip]} paquetes')

def detect_brute_force(ip, failed_attempts):
    if failed_attempts[ip] > 10:  # Umbral de ejemplo
        send_alert(f'Posible ataque de fuerza bruta detectado desde {ip}: {failed_attempts[ip]} intentos fallidos')

def main(protocol_filter=None):
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    packet_count = defaultdict(int)
    failed_attempts = defaultdict(int)
    
    while True:
        raw_data, addr = conn.recvfrom(65536)
        ethernet_header = parse_ethernet_header(raw_data)
        print(f'\n{Fore.BLUE}Ethernet Header:{Style.RESET_ALL} {ethernet_header}')
        
        if ethernet_header['protocol'] == 8:  # IPv4
            ip_header = parse_ip_header(raw_data[14:])
            print(f'{Fore.GREEN}IP Header:{Style.RESET_ALL} {ip_header}')
            
            packet_count[ip_header['src_ip']] += 1
            detect_anomalies(ip_header['src_ip'], packet_count)
            
            if protocol_filter and not filter_traffic(ip_header, protocol_filter):
                continue
            
            if ip_header['protocol'] == 6:  # TCP
                tcp_header = parse_tcp_header(raw_data[14 + ip_header['header_length']:])
                print(f'{Fore.YELLOW}TCP Header:{Style.RESET_ALL} {tcp_header}')
                
                ip_header['src_port'] = tcp_header['src_port']
                ip_header['dest_port'] = tcp_header['dest_port']
                
                if tcp_header['src_port'] == 22 and tcp_header['acknowledgment'] == 0:  # Ejemplo de intento fallido en SSH
                    failed_attempts[ip_header['src_ip']] += 1
                    detect_brute_force(ip_header['src_ip'], failed_attempts)
                
                if tcp_header['dest_port'] == 80 or tcp_header['src_port'] == 80:
                    http_header = parse_http_header(raw_data[14 + ip_header['header_length'] + tcp_header['header_length']:])
                    if http_header:
                        print(f'{Fore.MAGENTA}HTTP Header:{Style.RESET_ALL}')
                        for line in http_header:
                            print(f'{Fore.MAGENTA}{line}{Style.RESET_ALL}')

                open_ports = scan_ports(ip_header['src_ip'])
                if open_ports:
                    send_alert(f'Puertos abiertos detectados en {ip_header["src_ip"]}: {open_ports}')
                
                nmap_result = run_nmap(ip_header['src_ip'])
                if "open" in nmap_result:
                    send_alert(f'Posible vulnerabilidad detectada en {ip_header["src_ip"]}:\n{nmap_result}')
                print(f'{Fore.CYAN}Resultado de Nmap para {ip_header["src_ip"]}:{Style.RESET_ALL}\n{nmap_result}')

if __name__ == "__main__":
    protocol = input("Ingrese el tipo de tráfico a filtrar (TCP, UDP, ICMP, HTTP) o presione Enter para capturar todo: ")
    main(protocol_filter=protocol.upper() if protocol else None)