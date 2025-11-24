"""
packet_sniffer.py
File chính - Packet Sniffer nâng cao hỗ trợ OSI 7 layers

Cách sử dụng:
    sudo python3 packet_sniffer.py
    sudo python3 packet_sniffer.py -p tcp -P 80 -n 100
    sudo python3 packet_sniffer.py -d google.com --security
"""

import socket
import sys
import argparse
from datetime import datetime
from collections import defaultdict

# Import các module
from packet_analyzer import PacketAnalyzer
from protocol_decoder import ProtocolDecoder
from security_detector import SecurityDetector
from network_utils import NetworkUtils
from packet_printer import PacketPrinter
from pcap_manager import PcapManager
from statistics_manager import StatisticsManager


class PacketSniffer:
    """Lớp chính để bắt và phân tích gói tin"""
    
    def __init__(self, filter_protocol=None, filter_ip=None, filter_port=None,
                 max_packets=None, ping_reply_only=False, filter_domain=None,
                 save_pcap=None, read_pcap=None, interface=None, detect_security=False):
        
        # Filters
        self.filter_protocol = filter_protocol
        self.filter_port = filter_port
        self.max_packets = max_packets
        self.ping_reply_only = ping_reply_only
        self.filter_domain = filter_domain
        self.interface = interface
        self.detect_security = detect_security
        
        # Filter IPs
        self.filter_ips = set()
        if filter_ip:
            self.filter_ips.add(filter_ip)
            print(f"[INFO] Lọc theo IP: {filter_ip}")
        
        if filter_domain:
            resolved_ips = NetworkUtils.resolve_domain(filter_domain)
            self.filter_ips.update(resolved_ips)
            print(f"[INFO] Domain '{filter_domain}' resolved to: {', '.join(resolved_ips)}")
        
        # Managers
        self.statistics = StatisticsManager()
        self.pcap_manager = PcapManager(save_pcap)
        self.security_detector = SecurityDetector() if detect_security else None
        
        # TCP stream reassembly
        self.tcp_streams = defaultdict(lambda: {'data': b'', 'seq': 0})
        
        # Read from file mode
        self.read_pcap = read_pcap
    
    def start(self):
        """Bắt đầu bắt gói tin"""
        
        # Nếu đọc từ file
        if self.read_pcap:
            self._read_and_process_pcap()
            return
        
        try:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            if self.interface:
                conn.bind((self.interface, 0))
                print(f"[INFO] Đang bắt gói tin trên interface: {self.interface}")
            
            self._print_header()
            
            packet_count = 0
            
            while True:
                if self.max_packets and packet_count >= self.max_packets:
                    break
                
                raw_data, addr = conn.recvfrom(65535)
                
                # Lưu vào PCAP nếu cần
                if self.pcap_manager.filename:
                    self.pcap_manager.save_packet(raw_data)
                
                if self.process_packet(raw_data, packet_count + 1):
                    packet_count += 1
        
        except KeyboardInterrupt:
            print("\n\n⏹ Đang dừng bắt gói tin...")
            if self.pcap_manager.filename:
                self.pcap_manager.write_to_file()
            self._print_final_statistics()
        
        except PermissionError:
            print("❌ Lỗi: Chương trình cần quyền root/administrator!")
            print("Vui lòng chạy với: sudo python3 packet_sniffer.py")
            sys.exit(1)
        
        except Exception as e:
            print(f"❌ Lỗi: {e}")
            sys.exit(1)
    
    def _read_and_process_pcap(self):
        """Đọc và xử lý file PCAP"""
        packets = self.pcap_manager.read_from_file(self.read_pcap)
        
        if not packets:
            return
        
        print("="*100)
        
        for i, packet in enumerate(packets, 1):
            raw_data = bytes.fromhex(packet['data'])
            print(f"\n[Packet #{i}] Timestamp: {packet['timestamp']}, Length: {packet['length']} bytes")
            self.process_packet(raw_data, i, offline=True)
            
            if self.max_packets and i >= self.max_packets:
                break
        
        self._print_final_statistics()
    
    def process_packet(self, raw_data, packet_num, offline=False):
        """Xử lý từng gói tin"""
        self.statistics.increment('total')
        
        dest_mac, src_mac, eth_proto, data = PacketAnalyzer.ethernet_frame(raw_data)
        
        # ARP
        if eth_proto == 0x0806:
            return self._process_arp(raw_data, packet_num, dest_mac, src_mac, data)
        
        # IPv4
        elif eth_proto == 8:
            return self._process_ipv4(raw_data, packet_num, dest_mac, src_mac, data)
        
        # IPv6
        elif eth_proto == 0x86DD:
            return self._process_ipv6(raw_data, packet_num, dest_mac, src_mac, data)
        
        else:
            self.statistics.increment('other')
            return False
    
    def _process_arp(self, raw_data, packet_num, dest_mac, src_mac, data):
        """Xử lý gói ARP"""
        self.statistics.increment('arp')
        arp_info = PacketAnalyzer.arp_packet(data)
        
        # Security detection
        if self.security_detector and arp_info:
            is_spoofing, old_mac = self.security_detector.detect_arp_spoofing(
                arp_info['src_mac'], arp_info['src_ip']
            )
            if is_spoofing:
                print(f"\n⚠️  [CẢNH BÁO BẢO MẬT] ARP SPOOFING phát hiện!")
                print(f"    IP {arp_info['src_ip']} đổi MAC từ {old_mac} → {arp_info['src_mac']}")
        
        # Filters
        if self.filter_protocol and self.filter_protocol.upper() != 'ARP':
            return False
        
        if self.filter_ips and arp_info:
            if arp_info['src_ip'] not in self.filter_ips and arp_info['dest_ip'] not in self.filter_ips:
                return False
        
        PacketPrinter.print_arp_packet(packet_num, dest_mac, src_mac, arp_info, len(raw_data))
        return True
    
    def _process_ipv4(self, raw_data, packet_num, dest_mac, src_mac, data):
        """Xử lý gói IPv4"""
        self.statistics.increment('ipv4')
        
        version, header_length, ttl, proto, src, target, data = PacketAnalyzer.ipv4_packet(data)
        
        # IP filter
        if self.filter_ips:
            if src not in self.filter_ips and target not in self.filter_ips:
                return False
        
        # Statistics
        self.statistics.add_conversation(src, target)
        proto_name = NetworkUtils.get_protocol_name(proto)
        self.statistics.add_protocol(proto_name)
        
        # ICMP
        if proto == 1:
            return self._process_icmp(raw_data, packet_num, dest_mac, src_mac,
                                     version, header_length, ttl, src, target, data)
        
        # TCP
        elif proto == 6:
            return self._process_tcp(raw_data, packet_num, dest_mac, src_mac,
                                    version, header_length, ttl, src, target, data)
        
        # UDP
        elif proto == 17:
            return self._process_udp(raw_data, packet_num, dest_mac, src_mac,
                                    version, header_length, ttl, src, target, data)
        
        else:
            self.statistics.increment('other')
            return False
    
    def _process_icmp(self, raw_data, packet_num, dest_mac, src_mac,
                     version, header_length, ttl, src, target, data):
        """Xử lý gói ICMP"""
        self.statistics.increment('icmp')
        
        icmp_type, code, check_sum, data = PacketAnalyzer.icmp_packet(data)
        
        # Filter
        if self.ping_reply_only and icmp_type != 0:
            return False
        
        if self.filter_protocol and self.filter_protocol.upper() != 'ICMP':
            return False
        
        PacketPrinter.print_osi_packet(
            packet_num, dest_mac, src_mac, version, header_length, ttl,
            src, target, proto='ICMP', icmp_type=icmp_type, code=code,
            check_sum=check_sum, payload=data, raw_size=len(raw_data)
        )
        return True
    
    def _process_tcp(self, raw_data, packet_num, dest_mac, src_mac,
                    version, header_length, ttl, src, target, data):
        """Xử lý gói TCP"""
        self.statistics.increment('tcp')
        
        (src_port, dest_port, sequence, acknowledgement, flag_ack, flag_fin,
         flag_psh, flag_rst, flag_syn, flag_urg, data) = PacketAnalyzer.tcp_segment(data)
        
        # Port filter
        if self.filter_port and (self.filter_port != src_port and self.filter_port != dest_port):
            return False
        
        # Identify application protocol
        app_proto = NetworkUtils.identify_application_protocol(src_port, dest_port, data)
        
        # Protocol filter
        if not self._check_protocol_filter(app_proto):
            return False
        
        # Security detection
        if self.security_detector and flag_syn and not flag_ack:
            if self.security_detector.detect_port_scan(src, dest_port):
                count = self.security_detector.get_scanned_ports_count(src)
                print(f"\n⚠️  [CẢNH BÁO BẢO MẬT] PORT SCAN phát hiện từ {src}!")
                print(f"    Đã quét {count} ports")
            
            if self.security_detector.detect_syn_flood(src):
                count = self.security_detector.get_syn_count(src)
                print(f"\n⚠️  [CẢNH BÁO BẢO MẬT] SYN FLOOD phát hiện từ {src}!")
                print(f"    Số SYN packets: {count}")
        
        # Decode application data
        app_data = self._decode_application_data(app_proto, data)
        
        flags = {
            'ACK': flag_ack, 'FIN': flag_fin, 'PSH': flag_psh,
            'RST': flag_rst, 'SYN': flag_syn, 'URG': flag_urg
        }
        
        PacketPrinter.print_osi_packet(
            packet_num, dest_mac, src_mac, version, header_length, ttl,
            src, target, proto='TCP', src_port=src_port, dest_port=dest_port,
            sequence=sequence, acknowledgement=acknowledgement, flags=flags,
            payload=data, app_proto=app_proto, raw_size=len(raw_data),
            app_data=app_data
        )
        return True
    
    def _process_udp(self, raw_data, packet_num, dest_mac, src_mac,
                    version, header_length, ttl, src, target, data):
        """Xử lý gói UDP"""
        self.statistics.increment('udp')
        
        src_port, dest_port, size, data = PacketAnalyzer.udp_segment(data)
        
        # Port filter
        if self.filter_port and (self.filter_port != src_port and self.filter_port != dest_port):
            return False
        
        app_proto = NetworkUtils.identify_application_protocol(src_port, dest_port, data)
        
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
        
        # Decode DNS
        dns_info = None
        if src_port == 53 or dest_port == 53:
            dns_info = PacketAnalyzer.decode_dns(data)
        
        PacketPrinter.print_osi_packet(
            packet_num, dest_mac, src_mac, version, header_length, ttl,
            src, target, proto='UDP', src_port=src_port, dest_port=dest_port,
            udp_size=size, payload=data, app_proto=app_proto,
            raw_size=len(raw_data), dns_info=dns_info
        )
        return True
    
    def _process_ipv6(self, raw_data, packet_num, dest_mac, src_mac, data):
        """Xử lý gói IPv6"""
        self.statistics.increment('ipv6')
        
        ipv6_info = PacketAnalyzer.ipv6_packet(data)
        
        # IP filter
        if self.filter_ips and ipv6_info:
            if ipv6_info['src'] not in self.filter_ips and ipv6_info['dest'] not in self.filter_ips:
                return False
        
        if self.filter_protocol and self.filter_protocol.upper() != 'IPV6':
            return False
        
        PacketPrinter.print_ipv6_packet(packet_num, dest_mac, src_mac, ipv6_info, len(raw_data))
        return True
    
    def _check_protocol_filter(self, app_proto):
        """Kiểm tra filter protocol"""
        if not self.filter_protocol:
            return True
        
        filter_upper = self.filter_protocol.upper()
        if filter_upper == 'TCP':
            return True
        elif filter_upper in ['FTP', 'SMTP', 'POP3', 'IMAP', 'HTTP', 'HTTPS', 'SSH']:
            return filter_upper in app_proto.upper()
        
        return False
    
    def _decode_application_data(self, app_proto, data):
        """Giải mã dữ liệu tầng application"""
        if not data:
            return None
        
        if app_proto == 'FTP':
            return ProtocolDecoder.decode_ftp(data)
        elif app_proto == 'SMTP':
            return ProtocolDecoder.decode_smtp(data)
        elif app_proto == 'POP3':
            return ProtocolDecoder.decode_pop3(data)
        elif app_proto == 'IMAP':
            return ProtocolDecoder.decode_imap(data)
        
        return None
    
    def _print_header(self):
        """In header khi bắt đầu"""
        print("="*100)
        print("PACKET SNIFFER - WIRESHARK CLONE - OSI 7 LAYERS".center(100))
        print("="*100)
        print(f"Thời gian: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if self.ping_reply_only:
            print(f"Chế độ: CHỈ BẮT PING REPLY (ICMP Echo Reply - Type 0)")
        if self.filter_protocol:
            print(f"Lọc Protocol: {self.filter_protocol}")
        if self.filter_domain:
            print(f"Lọc Domain: {self.filter_domain} → IPs: {', '.join(self.filter_ips)}")
        elif self.filter_ips:
            print(f"Lọc IP: {', '.join(self.filter_ips)}")
        if self.filter_port:
            print(f"Lọc Port: {self.filter_port}")
        if self.pcap_manager.filename:
            print(f"Lưu vào file: {self.pcap_manager.filename}")
        if self.detect_security:
            print(f"🔒 Bật phát hiện bảo mật: Port Scan, SYN Flood, ARP Spoofing")
        
        print("="*100)
        print("\nẤn Ctrl+C để dừng và xem thống kê\n")
    
    def _print_final_statistics(self):
        """In thống kê cuối cùng"""
        self.statistics.print_statistics()
        
        if self.security_detector:
            print(f"\n🔒 PHÁT HIỆN BẢO MẬT:")
            security_stats = self.security_detector.get_statistics()
            print(f"  Port Scan phát hiện: {security_stats['port_scan_detected']}")
            print(f"  SYN Flood phát hiện: {security_stats['syn_flood_detected']}")
            print("="*100)


def main():
    """Hàm chính"""
    parser = argparse.ArgumentParser(
        description='🔍 Packet Sniffer Nâng Cao - Clone Wireshark - Hỗ trợ OSI 7 tầng',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
VÍ DỤ SỬ DỤNG:
══════════════════════════════════════════════════════════════════════════

🔹 CƠ BẢN:
  sudo python3 packet_sniffer.py                        # Bắt tất cả gói tin
  sudo python3 packet_sniffer.py -n 10                  # Bắt 10 gói rồi dừng

🔹 LỌC THEO GIAO THỨC:
  sudo python3 packet_sniffer.py -p tcp                 # Chỉ bắt TCP
  sudo python3 packet_sniffer.py -p udp                 # Chỉ bắt UDP
  sudo python3 packet_sniffer.py -p ftp                 # Chỉ bắt FTP

🔹 LỌC THEO IP/DOMAIN:
  sudo python3 packet_sniffer.py -i 8.8.8.8             # Lọc theo IP
  sudo python3 packet_sniffer.py -d google.com          # Lọc theo domain

🔹 LƯU & ĐỌC FILE:
  sudo python3 packet_sniffer.py -s capture.json        # Lưu vào file
  sudo python3 packet_sniffer.py -r capture.json        # Đọc từ file

🔹 PHÁT HIỆN BẢO MẬT:
  sudo python3 packet_sniffer.py --security             # Bật phát hiện tấn công
        '''
    )
    
    parser.add_argument('-p', '--protocol', type=str,
                       help='Lọc theo giao thức')
    parser.add_argument('-i', '--ip', type=str,
                       help='Lọc theo địa chỉ IP')
    parser.add_argument('-d', '--domain', type=str,
                       help='Lọc theo tên miền')
    parser.add_argument('-P', '--port', type=int,
                       help='Lọc theo số cổng')
    parser.add_argument('-n', '--number', type=int,
                       help='Số lượng gói tin cần bắt')
    parser.add_argument('--ping-reply-only', action='store_true',
                       help='CHỈ bắt ICMP Echo Reply')
    parser.add_argument('-s', '--save', type=str,
                       help='Lưu gói tin vào file JSON')
    parser.add_argument('-r', '--read', type=str,
                       help='Đọc và phân tích file đã lưu')
    parser.add_argument('-I', '--interface', type=str,
                       help='Chọn network interface')
    parser.add_argument('--security', action='store_true',
                       help='Bật phát hiện bảo mật')
    
    args = parser.parse_args()
    
    print("\n" + "="*100)
    print("🔍 PACKET SNIFFER - WIRESHARK CLONE".center(100))
    print(" Hỗ trợ OSI 7 tầng + FTP/SMTP/POP3/IMAP".center(100))
    print("="*100 + "\n")
    
    sniffer = PacketSniffer(
        filter_protocol=args.protocol,
        filter_ip=args.ip,
        filter_domain=args.domain,
        filter_port=args.port,
        max_packets=args.number,
        ping_reply_only=args.ping_reply_only,
        save_pcap=args.save,
        read_pcap=args.read,
        interface=args.interface,
        detect_security=args.security
    )
    
    sniffer.start()


if __name__ == "__main__":
    main()