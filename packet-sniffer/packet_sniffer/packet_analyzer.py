"""
packet_analyzer.py
Module phân tích các loại gói tin (Ethernet, IP, TCP, UDP, ICMP, ARP, IPv6)
"""

import struct
import socket


class PacketAnalyzer:
    """Phân tích các gói tin mạng ở các tầng khác nhau"""
    
    @staticmethod
    def ethernet_frame(data):
        """Phân tích Ethernet frame (Layer 2)"""
        dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
        return (
            PacketAnalyzer.get_mac_addr(dest_mac),
            PacketAnalyzer.get_mac_addr(src_mac),
            socket.htons(proto),
            data[14:]
        )
    
    @staticmethod
    def get_mac_addr(bytes_addr):
        """Chuyển đổi địa chỉ MAC thành chuỗi"""
        return ':'.join(map('{:02x}'.format, bytes_addr)).upper()
    
    @staticmethod
    def ipv4_packet(data):
        """Phân tích IPv4 packet (Layer 3)"""
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
        return (
            version,
            header_length,
            ttl,
            proto,
            PacketAnalyzer.ipv4(src),
            PacketAnalyzer.ipv4(target),
            data[header_length:]
        )
    
    @staticmethod
    def ipv4(addr):
        """Chuyển đổi địa chỉ IPv4"""
        return '.'.join(map(str, addr))
    
    @staticmethod
    def ipv6_packet(data):
        """Phân tích IPv6 packet"""
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
    
    @staticmethod
    def tcp_segment(data):
        """Phân tích TCP segment (Layer 4)"""
        src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack(
            '!HHLLH', data[:14]
        )
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        
        return (
            src_port, dest_port, sequence, acknowledgement,
            flag_ack, flag_fin, flag_psh, flag_rst, flag_syn, flag_urg,
            data[offset:]
        )
    
    @staticmethod
    def udp_segment(data):
        """Phân tích UDP segment (Layer 4)"""
        src_port, dest_port, size = struct.unpack('!HHH', data[:6])
        return src_port, dest_port, size, data[8:]
    
    @staticmethod
    def icmp_packet(data):
        """Phân tích ICMP packet"""
        icmp_type, code, check_sum = struct.unpack('!BBH', data[:4])
        return icmp_type, code, check_sum, data[4:]
    
    @staticmethod
    def arp_packet(data):
        """Phân tích ARP packet"""
        if len(data) < 28:
            return None
        
        try:
            hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack(
                '!HHBBH', data[0:8]
            )
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
    
    @staticmethod
    def decode_dns(data):
        """Decode DNS packet"""
        if len(data) < 12:
            return None
        
        try:
            transaction_id = struct.unpack('!H', data[0:2])[0]
            flags = struct.unpack('!H', data[2:4])[0]
            questions = struct.unpack('!H', data[4:6])[0]
            answers = struct.unpack('!H', data[6:8])[0]
            
            is_response = (flags & 0x8000) >> 15
            
            # Parse query name
            query_name = []
            pos = 12
            while pos < len(data) and data[pos] != 0:
                length = data[pos]
                if length == 0:
                    break
                pos += 1
                if pos + length <= len(data):
                    query_name.append(data[pos:pos+length].decode('utf-8', errors='ignore'))
                    pos += length
                else:
                    break
            
            domain = '.'.join(query_name) if query_name else 'Unknown'
            
            return {
                'transaction_id': transaction_id,
                'is_response': is_response,
                'questions': questions,
                'answers': answers,
                'domain': domain
            }
        except:
            return None