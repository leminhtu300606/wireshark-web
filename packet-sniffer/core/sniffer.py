"""
Main PacketSniffer class - Fixed and refactored
"""
import socket
import time
import json
from datetime import datetime
from collections import defaultdict

from .parsers import (
    parse_ethernet_frame, parse_ipv4_packet, parse_ipv6_packet,
    parse_arp_packet, parse_icmp_packet, parse_icmpv6_packet,
    parse_tcp_segment, parse_udp_segment
)
from .protocols import decode_dns, decode_ftp, decode_smtp, decode_pop3, decode_imap
from .security import SecurityDetector
from .statistics import StatisticsTracker
from .utils import (
    resolve_domain, get_hostname_display, get_protocol_name, get_icmp_type_name,
    get_icmpv6_type_name, identify_application_protocol, get_service_name, 
    is_text, is_encrypted
)

class PacketSniffer:
    """Main packet sniffer class"""
    
    def __init__(self, filter_protocol=None, filter_ip=None, filter_port=None, 
                 max_packets=None, ping_reply_only=False, filter_domain=None, 
                 save_pcap=None, read_pcap=None, interface=None, detect_security=False):
        
        # Filters
        self.filter_protocol = filter_protocol
        self.filter_port = filter_port
        self.max_packets = max_packets
        self.ping_reply_only = ping_reply_only
        self.filter_domain = filter_domain
        self.save_pcap = save_pcap
        self.read_pcap = read_pcap
        self.interface = interface
        self.detect_security = detect_security
        
        # DNS cache
        self.dns_cache = {}
        
        # TCP streams
        self.tcp_streams = defaultdict(lambda: {'data': b'', 'seq': 0})
        
        # Filter IPs
        self.filter_ips = set()
        if filter_ip:
            self.filter_ips.add(filter_ip)
            print(f"[INFO] Lọc theo IP: {filter_ip}")
        
        if filter_domain:
            print(f"[INFO] Đang phân giải domain '{filter_domain}'...")
            resolved_ips = resolve_domain(filter_domain)
            if resolved_ips:
                self.filter_ips.update(resolved_ips)
                print(f"[INFO] Domain '{filter_domain}' resolved to: {', '.join(resolved_ips)}")
            else:
                print(f"[WARNING] Không thể phân giải domain '{filter_domain}', sẽ chỉ lọc theo tên")
        
        # Statistics tracker
        self.stats_tracker = StatisticsTracker()
        self.stats = self.stats_tracker.stats  # Backward compatibility
        self.protocol_stats = self.stats_tracker.protocol_stats
        self.ip_conversations = self.stats_tracker.ip_conversations
        self.start_time = self.stats_tracker.start_time
        
        # Security detector
        self.security_detector = SecurityDetector() if detect_security else None
        
        # PCAP storage
        self.captured_packets = []
    
    def ethernet_frame(self, data):
        """Parse ethernet frame"""
        return parse_ethernet_frame(data)
    
    def ipv4_packet(self, data):
        """Parse IPv4 packet"""
        return parse_ipv4_packet(data)
    
    def ipv6_packet(self, data):
        """Parse IPv6 packet"""
        return parse_ipv6_packet(data)
    
    def arp_packet(self, data):
        """Parse ARP packet"""
        return parse_arp_packet(data)
    
    def icmp_packet(self, data):
        """Parse ICMP packet"""
        return parse_icmp_packet(data)
    
    def icmpv6_packet(self, data):
        """Parse ICMPv6 packet"""
        return parse_icmpv6_packet(data)
    
    def tcp_segment(self, data):
        """Parse TCP segment"""
        return parse_tcp_segment(data)
    
    def udp_segment(self, data):
        """Parse UDP segment"""
        return parse_udp_segment(data)
    
    def decode_dns(self, data):
        """Decode DNS"""
        return decode_dns(data)
    
    def decode_ftp(self, data):
        """Decode FTP"""
        return decode_ftp(data)
    
    def decode_smtp(self, data):
        """Decode SMTP"""
        return decode_smtp(data)
    
    def decode_pop3(self, data):
        """Decode POP3"""
        return decode_pop3(data)
    
    def decode_imap(self, data):
        """Decode IMAP"""
        return decode_imap(data)
    
    def get_protocol_name(self, proto):
        """Get protocol name"""
        return get_protocol_name(proto)
    
    def get_icmp_type_name(self, icmp_type):
        """Get ICMP type name"""
        return get_icmp_type_name(icmp_type)
    
    def get_icmpv6_type_name(self, icmpv6_type):
        """Get ICMPv6 type name"""
        return get_icmpv6_type_name(icmpv6_type)
    
    def identify_application_protocol(self, src_port, dest_port, data):
        """Identify application protocol"""
        return identify_application_protocol(src_port, dest_port, data)
    
    def get_service_name(self, src_port, dest_port):
        """Get service name"""
        return get_service_name(src_port, dest_port)
    
    def is_text(self, data):
        """Check if text"""
        return is_text(data)
    
    def is_encrypted(self, data):
        """Check if encrypted"""
        return is_encrypted(data)
    
    def get_hostname_display(self, ip):
        """Get hostname display"""
        return get_hostname_display(ip, self.dns_cache)
    
    def print_statistics(self):
        """Print statistics"""
        self.stats_tracker.print_statistics()
        
        if self.security_detector:
            sec_stats = self.security_detector.get_stats()
            print(f"\n🔒 PHÁT HIỆN BẢO MẬT:")
            print(f"  Port Scan phát hiện: {sec_stats['port_scans']}")
            print(f"  SYN Flood phát hiện: {sec_stats['syn_floods']}")
    
    def process_packet(self, raw_data, packet_num, offline=False):
        """Process packet - Main logic with IPv6 and SMTP support"""
        self.stats_tracker.update('total')
        
        dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)
        
        if not eth_proto:
            return False
        
        # ARP
        if eth_proto == 0x0806:
            self.stats_tracker.update('arp')
            arp_info = self.arp_packet(data)
            
            if self.security_detector and arp_info:
                if self.security_detector.detect_arp_spoofing(arp_info['src_mac'], arp_info['src_ip']):
                    print(f"\n⚠️  [CẢNH BÁO BẢO MẬT] ARP SPOOFING từ {arp_info['src_ip']}")
            
            if self.filter_protocol and self.filter_protocol.upper() != 'ARP':
                return False
            
            if self.filter_ips and arp_info:
                if arp_info['src_ip'] not in self.filter_ips and arp_info['dest_ip'] not in self.filter_ips:
                    return False
            
            return True
        
        # IPv4
        elif eth_proto == 8:
            self.stats_tracker.update('ipv4')
            version, header_length, ttl, proto, src, target, data = self.ipv4_packet(data)
            
            if not src or not target:
                return False
            
            # Check IP filter
            if self.filter_ips:
                if src not in self.filter_ips and target not in self.filter_ips:
                    return False
            
            # Update statistics
            self.stats_tracker.update_conversation(src, target)
            proto_name = self.get_protocol_name(proto)
            self.stats_tracker.update_protocol(proto_name)
            
            # ICMP
            if proto == 1:
                self.stats_tracker.update('icmp')
                icmp_type, code, check_sum, data = self.icmp_packet(data)
                
                if icmp_type is None:
                    return False
                
                if self.ping_reply_only and icmp_type != 0:
                    return False
                
                if self.filter_protocol and self.filter_protocol.upper() != 'ICMP':
                    return False
                
                return True
            
            # TCP
            elif proto == 6:
                self.stats_tracker.update('tcp')
                
                result = self.tcp_segment(data)
                if result[0] is None:
                    return False
                
                (src_port, dest_port, sequence, acknowledgement, flag_ack, flag_fin, 
                 flag_psh, flag_rst, flag_syn, flag_urg, data) = result
                
                # Port filter
                if self.filter_port and (self.filter_port != src_port and self.filter_port != dest_port):
                    return False
                
                # Application protocol
                app_proto = self.identify_application_protocol(src_port, dest_port, data)
                
                # Protocol filter
                if self.filter_protocol:
                    filter_upper = self.filter_protocol.upper()
                    if filter_upper == 'TCP':
                        pass
                    elif filter_upper in ['FTP', 'SMTP', 'POP3', 'IMAP', 'HTTP', 'HTTPS', 'SSH']:
                        if filter_upper not in app_proto.upper():
                            return False
                    else:
                        return False
                
                # SMTP detection
                if (src_port == 25 or dest_port == 25 or src_port == 587 or dest_port == 587) and data:
                    smtp_data = self.decode_smtp(data)
                    if smtp_data:
                        pass  # SMTP packet detected
                
                # Security detection
                if self.security_detector:
                    if flag_syn and not flag_ack:
                        if self.security_detector.detect_port_scan(src, dest_port):
                            print(f"\n⚠️  [CẢNH BÁO] PORT SCAN từ {src}")
                        
                        if self.security_detector.detect_syn_flood(src):
                            print(f"\n⚠️  [CẢNH BÁO] SYN FLOOD từ {src}")
                
                return True
            
            # UDP
            elif proto == 17:
                self.stats_tracker.update('udp')
                
                result = self.udp_segment(data)
                if result[0] is None:
                    return False
                
                src_port, dest_port, size, data = result
                
                # Port filter
                if self.filter_port and (self.filter_port != src_port and self.filter_port != dest_port):
                    return False
                
                app_proto = self.identify_application_protocol(src_port, dest_port, data)
                
                # Protocol filter
                if self.filter_protocol:
                    filter_upper = self.filter_protocol.upper()
                    if filter_upper == 'UDP':
                        pass
                    elif filter_upper == 'DNS':
                        if src_port != 53 and dest_port != 53:
                            return False
                    else:
                        if filter_upper not in ['UDP', 'DNS']:
                            return False
                
                return True
            
            else:
                self.stats_tracker.update('other')
                return False
        
        # IPv6
        elif eth_proto == 0x86DD:
            self.stats_tracker.update('ipv6')
            ipv6_info = self.ipv6_packet(data)
            
            if not ipv6_info:
                return False
            
            # Check IP filter
            if self.filter_ips:
                if ipv6_info['src'] not in self.filter_ips and ipv6_info['dest'] not in self.filter_ips:
                    return False
            
            # Update statistics
            self.stats_tracker.update_conversation(ipv6_info['src'], ipv6_info['dest'])
            
            # Handle next header (protocol)
            next_header = ipv6_info['next_header']
            
            # ICMPv6
            if next_header == 58:
                self.stats_tracker.update('icmp')
                icmpv6_info = self.icmpv6_packet(ipv6_info['data'])
                
                if icmpv6_info:
                    if self.ping_reply_only and icmpv6_info['type'] != 129:  # Echo Reply
                        return False
            
            # TCP over IPv6
            elif next_header == 6:
                self.stats_tracker.update('tcp')
                result = self.tcp_segment(ipv6_info['data'])
                
                if result[0] is not None:
                    src_port, dest_port = result[0], result[1]
                    
                    # Port filter
                    if self.filter_port and (self.filter_port != src_port and self.filter_port != dest_port):
                        return False
            
            # UDP over IPv6
            elif next_header == 17:
                self.stats_tracker.update('udp')
                result = self.udp_segment(ipv6_info['data'])
                
                if result[0] is not None:
                    src_port, dest_port = result[0], result[1]
                    
                    # Port filter
                    if self.filter_port and (self.filter_port != src_port and self.filter_port != dest_port):
                        return False
            
            if self.filter_protocol:
                filter_upper = self.filter_protocol.upper()
                if filter_upper not in ['IPV6', 'ICMPV6']:
                    return False
            
            return True
        
        else:
            self.stats_tracker.update('other')
            return False
    
    # Placeholder methods for compatibility
    def print_arp_packet(self, *args, **kwargs):
        pass
    
    def print_ipv6_packet(self, *args, **kwargs):
        pass
    
    def print_osi_packet(self, *args, **kwargs):
        pass
    
    def analyze_application_data(self, *args, **kwargs):
        pass
    
    def start(self):
        """Start packet capture"""
        pass  # Will be implemented based on needs