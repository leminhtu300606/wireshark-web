"""
Packet parsers for different protocols
"""
import struct
import socket
from .utils import get_mac_addr, ipv4_to_string

def parse_ethernet_frame(data):
    """Parse Ethernet frame"""
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def parse_ipv4_packet(data):
    """Parse IPv4 packet"""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return version, header_length, ttl, proto, ipv4_to_string(src), ipv4_to_string(target), data[header_length:]

def parse_ipv6_packet(data):
    """Parse IPv6 packet"""
    if len(data) < 40:
        return None
    
    try:
        version_class_label = struct.unpack('!I', data[0:4])[0]
        version = (version_class_label >> 28) & 0xF
        payload_length = struct.unpack('!H', data[4:6])[0]
        next_header = data[6]
        hop_limit = data[7]
        
        src = ':'.join(f'{data[i]:02x}{data[i+1]:02x}' for i in range(8, 24, 2))
        dest = ':'.join(f'{data[i]:02x}{data[i+1]:02x}' for i in range(24, 40, 2))
        
        return {
            'version': version,
            'payload_length': payload_length,
            'next_header': next_header,
            'hop_limit': hop_limit,
            'src': src,
            'dest': dest
        }
    except:
        return None

def parse_arp_packet(data):
    """Parse ARP packet"""
    if len(data) < 28:
        return None
    
    try:
        hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack('!HHBBH', data[0:8])
        src_mac = ':'.join(f'{b:02x}' for b in data[8:14]).upper()
        src_ip = '.'.join(str(b) for b in data[14:18])
        dest_mac = ':'.join(f'{b:02x}' for b in data[18:24]).upper()
        dest_ip = '.'.join(str(b) for b in data[24:28])
        
        return {
            'opcode': opcode,
            'src_mac': src_mac,
            'src_ip': src_ip,
            'dest_mac': dest_mac,
            'dest_ip': dest_ip
        }
    except:
        return None

def parse_icmp_packet(data):
    """Parse ICMP packet"""
    icmp_type, code, check_sum = struct.unpack('!BBH', data[:4])
    return icmp_type, code, check_sum, data[4:]

def parse_tcp_segment(data):
    """Parse TCP segment"""
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_ack, flag_fin, flag_psh, flag_rst, flag_syn, flag_urg, data[offset:]

def parse_udp_segment(data):
    """Parse UDP segment"""
    src_port, dest_port, size = struct.unpack('!HHH', data[:6])
    return src_port, dest_port, size, data[8:]