import socket
import struct
import textwrap
import time
from datetime import datetime
from collections import defaultdict
import argparse
import sys
import json

TAB_1 = '  '
TAB_2 = '    '
TAB_3 = '      '
TAB_4 = '        '

class PacketSniffer:
    def __init__(self, filter_protocol=None, filter_ip=None, filter_port=None, max_packets=None, 
                 ping_reply_only=False, filter_domain=None, save_pcap=None, read_pcap=None,
                 interface=None, detect_security=False):
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
        
        # TCP stream reassembly
        self.tcp_streams = defaultdict(lambda: {'data': b'', 'seq': 0})
        
        # Security detection
        self.port_scan_tracker = defaultdict(set)
        self.syn_tracker = defaultdict(int)
        self.arp_cache = {}
        
        # Filter IPs - FIXED: Thay đổi cách lưu trữ filter IPs
        self.filter_ips = set()  # Dùng set để tìm kiếm nhanh hơn
        if filter_ip:
            self.filter_ips.add(filter_ip)
            print(f"[INFO] Lọc theo IP: {filter_ip}")
        
        if filter_domain:
            resolved_ips = self.resolve_domain(filter_domain)
            self.filter_ips.update(resolved_ips)
            print(f"[INFO] Domain '{filter_domain}' resolved to: {', '.join(resolved_ips)}")
        
        # Statistics
        self.stats = {
            'total': 0,
            'ipv4': 0,
            'ipv6': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'arp': 0,
            'other': 0
        }
        self.protocol_stats = defaultdict(int)
        self.ip_conversations = defaultdict(int)
        self.start_time = time.time()
        
        # PCAP storage
        self.captured_packets = []
        
    def resolve_domain(self, domain):
        """Phân giải tên miền thành IP - FIXED"""
        try:
            # Loại bỏ http://, https://, www.
            domain = domain.replace('http://', '').replace('https://', '')
            domain = domain.replace('www.', '')
            domain = domain.split('/')[0]  # Loại bỏ path
            
            result = socket.getaddrinfo(domain, None)
            # Lấy cả IPv4 và IPv6
            ips = list(set([addr[4][0] for addr in result]))
            return ips
        except socket.gaierror as e:
            print(f"[WARNING] Không thể phân giải domain: {domain} - {e}")
            return []
    
    def reverse_dns_lookup(self, ip):
        """Tra cứu ngược IP thành hostname"""
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = hostname
            return hostname
        except (socket.herror, socket.gaierror):
            self.dns_cache[ip] = None
            return None
    
    def get_hostname_display(self, ip):
        """Hiển thị IP với hostname"""
        hostname = self.reverse_dns_lookup(ip)
        if hostname:
            return f"{ip} ({hostname})"
        return ip
    
    def save_packet_to_pcap(self, raw_data, timestamp):
        """Lưu gói tin vào định dạng PCAP"""
        packet_info = {
            'timestamp': timestamp,
            'length': len(raw_data),
            'data': raw_data.hex()
        }
        self.captured_packets.append(packet_info)
    
    def write_pcap_file(self):
        """Ghi file PCAP"""
        if not self.save_pcap or not self.captured_packets:
            return
        
        try:
            with open(self.save_pcap, 'w') as f:
                json.dump(self.captured_packets, f, indent=2)
            print(f"\n[✓] Đã lưu {len(self.captured_packets)} gói tin vào {self.save_pcap}")
        except Exception as e:
            print(f"[✗] Lỗi khi ghi file: {e}")
    
    def read_pcap_file(self):
        """Đọc file PCAP"""
        try:
            with open(self.read_pcap, 'r') as f:
                packets = json.load(f)
            
            print(f"\n[✓] Đã đọc {len(packets)} gói tin từ {self.read_pcap}")
            print("="*100)
            
            for i, packet in enumerate(packets, 1):
                raw_data = bytes.fromhex(packet['data'])
                print(f"\n[Packet #{i}] Timestamp: {packet['timestamp']}, Length: {packet['length']} bytes")
                self.process_packet(raw_data, i, offline=True)
                
                if self.max_packets and i >= self.max_packets:
                    break
                    
        except FileNotFoundError:
            print(f"[✗] Không tìm thấy file: {self.read_pcap}")
        except Exception as e:
            print(f"[✗] Lỗi khi đọc file: {e}")
    
    def detect_port_scan(self, src_ip, dest_port):
        """Phát hiện Port Scan"""
        self.port_scan_tracker[src_ip].add(dest_port)
        
        if len(self.port_scan_tracker[src_ip]) > 10:
            return True
        return False
    
    def detect_syn_flood(self, src_ip):
        """Phát hiện SYN Flood"""
        self.syn_tracker[src_ip] += 1
        
        if self.syn_tracker[src_ip] > 50:
            return True
        return False
    
    def detect_arp_spoofing(self, src_mac, src_ip):
        """Phát hiện ARP Spoofing"""
        if src_ip in self.arp_cache:
            if self.arp_cache[src_ip] != src_mac:
                return True
        else:
            self.arp_cache[src_ip] = src_mac
        return False
    
    def decode_ftp(self, data):
        """Decode FTP commands/responses - ENHANCED"""
        try:
            text = data.decode('utf-8', errors='ignore').strip()
            lines = text.split('\r\n')
            
            # FTP commands - expanded list
            ftp_commands = ['USER', 'PASS', 'LIST', 'RETR', 'STOR', 'PWD', 'CWD', 'QUIT', 
                           'PORT', 'PASV', 'TYPE', 'ABOR', 'DELE', 'RMD', 'MKD', 'RNFR', 
                           'RNTO', 'SYST', 'STAT', 'HELP', 'NOOP', 'FEAT', 'OPTS', 'SIZE',
                           'MDTM', 'REST', 'APPE', 'ALLO']
            
            result = {
                'type': 'unknown',
                'raw': text[:200]
            }
            
            for line in lines:
                if not line:
                    continue
                    
                # Check if it's a command
                for cmd in ftp_commands:
                    if line.upper().startswith(cmd):
                        result['type'] = 'command'
                        result['command'] = cmd
                        result['full'] = line[:150]
                        
                        # Parse specific commands
                        if cmd == 'USER':
                            result['username'] = line[5:].strip()
                        elif cmd == 'RETR' or cmd == 'STOR':
                            result['filename'] = line[5:].strip()
                        elif cmd == 'CWD':
                            result['directory'] = line[4:].strip()
                        
                        return result
                
                # Check if it's a response (starts with 3-digit code)
                if len(line) >= 3 and line[:3].isdigit():
                    result['type'] = 'response'
                    result['code'] = line[:3]
                    result['message'] = line[4:150] if len(line) > 4 else ''
                    
                    # Interpret response codes
                    code_int = int(result['code'])
                    if code_int < 200:
                        result['status'] = 'preliminary'
                    elif code_int < 300:
                        result['status'] = 'success'
                    elif code_int < 400:
                        result['status'] = 'intermediate'
                    elif code_int < 500:
                        result['status'] = 'transient_error'
                    else:
                        result['status'] = 'permanent_error'
                    
                    return result
            
            return result if result['type'] != 'unknown' else None
        except:
            return None
    
    def decode_smtp(self, data):
        """Decode SMTP commands/responses - ENHANCED"""
        try:
            text = data.decode('utf-8', errors='ignore').strip()
            lines = text.split('\r\n')
            
            # SMTP commands - expanded
            smtp_commands = ['HELO', 'EHLO', 'MAIL FROM', 'RCPT TO', 'DATA', 'QUIT', 
                           'AUTH', 'STARTTLS', 'RSET', 'VRFY', 'EXPN', 'HELP', 'NOOP']
            
            result = {
                'type': 'unknown',
                'raw': text[:200]
            }
            
            for line in lines:
                if not line:
                    continue
                
                # Check commands
                for cmd in smtp_commands:
                    if line.upper().startswith(cmd):
                        result['type'] = 'command'
                        result['command'] = cmd
                        result['full'] = line[:150]
                        
                        # Parse specific commands
                        if 'MAIL FROM' in cmd or 'RCPT TO' in cmd:
                            # Extract email address
                            if '<' in line and '>' in line:
                                email_start = line.index('<') + 1
                                email_end = line.index('>')
                                result['email'] = line[email_start:email_end]
                        elif cmd == 'HELO' or cmd == 'EHLO':
                            result['domain'] = line.split()[1] if len(line.split()) > 1 else ''
                        
                        return result
                
                # Check response codes
                if len(line) >= 3 and line[:3].isdigit():
                    result['type'] = 'response'
                    result['code'] = line[:3]
                    result['message'] = line[4:150] if len(line) > 4 else ''
                    
                    # Interpret SMTP response codes
                    code_int = int(result['code'])
                    if code_int < 300:
                        result['status'] = 'success'
                    elif code_int < 400:
                        result['status'] = 'intermediate'
                    elif code_int < 500:
                        result['status'] = 'transient_error'
                    else:
                        result['status'] = 'permanent_error'
                    
                    return result
            
            return result if result['type'] != 'unknown' else None
        except:
            return None
    
    def decode_pop3(self, data):
        """Decode POP3 commands/responses - ENHANCED"""
        try:
            text = data.decode('utf-8', errors='ignore').strip()
            lines = text.split('\r\n')
            
            # POP3 commands - complete list
            pop3_commands = ['USER', 'PASS', 'STAT', 'LIST', 'RETR', 'DELE', 'NOOP', 
                           'RSET', 'QUIT', 'TOP', 'UIDL', 'APOP', 'AUTH', 'CAPA']
            
            result = {
                'type': 'unknown',
                'raw': text[:200]
            }
            
            for line in lines:
                if not line:
                    continue
                
                # Check commands
                for cmd in pop3_commands:
                    if line.upper().startswith(cmd):
                        result['type'] = 'command'
                        result['command'] = cmd
                        result['full'] = line[:150]
                        
                        # Parse specific commands
                        if cmd == 'USER':
                            result['username'] = line[5:].strip()
                        elif cmd in ['RETR', 'DELE', 'TOP']:
                            parts = line.split()
                            if len(parts) > 1:
                                result['message_id'] = parts[1]
                        
                        return result
                
                # Check responses (+OK, -ERR)
                if line.startswith('+OK') or line.startswith('-ERR'):
                    result['type'] = 'response'
                    result['status'] = line[:3]
                    result['message'] = line[4:150] if len(line) > 4 else ''
                    result['success'] = line.startswith('+OK')
                    
                    return result
            
            return result if result['type'] != 'unknown' else None
        except:
            return None
    
    def decode_imap(self, data):
        """Decode IMAP commands/responses - NEW"""
        try:
            text = data.decode('utf-8', errors='ignore').strip()
            lines = text.split('\r\n')
            
            # IMAP commands
            imap_commands = ['LOGIN', 'SELECT', 'EXAMINE', 'CREATE', 'DELETE', 'RENAME',
                           'SUBSCRIBE', 'UNSUBSCRIBE', 'LIST', 'LSUB', 'STATUS', 'APPEND',
                           'CHECK', 'CLOSE', 'EXPUNGE', 'SEARCH', 'FETCH', 'STORE', 'COPY',
                           'UID', 'LOGOUT', 'CAPABILITY', 'NOOP', 'IDLE']
            
            result = {
                'type': 'unknown',
                'raw': text[:200]
            }
            
            for line in lines:
                if not line:
                    continue
                
                # IMAP commands have format: tag COMMAND arguments
                parts = line.split()
                if len(parts) >= 2:
                    command = parts[1].upper()
                    
                    if command in imap_commands:
                        result['type'] = 'command'
                        result['tag'] = parts[0]
                        result['command'] = command
                        result['full'] = line[:150]
                        
                        # Parse specific commands
                        if command == 'LOGIN' and len(parts) >= 4:
                            result['username'] = parts[2]
                        elif command == 'SELECT' and len(parts) >= 3:
                            result['mailbox'] = parts[2]
                        
                        return result
                
                # Check responses
                if line.startswith('* ') or line.startswith('+ '):
                    result['type'] = 'response'
                    result['untagged'] = True
                    result['message'] = line[2:150]
                    return result
                
                # Tagged response
                if len(parts) >= 2 and (parts[1] == 'OK' or parts[1] == 'NO' or parts[1] == 'BAD'):
                    result['type'] = 'response'
                    result['tag'] = parts[0]
                    result['status'] = parts[1]
                    result['message'] = ' '.join(parts[2:])[:150]
                    return result
            
            return result if result['type'] != 'unknown' else None
        except:
            return None
        
    def start(self):
        """Bắt đầu bắt gói tin"""
        
        # Nếu đọc từ file
        if self.read_pcap:
            self.read_pcap_file()
            return
        
        try:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            if self.interface:
                conn.bind((self.interface, 0))
                print(f"[INFO] Đang bắt gói tin trên interface: {self.interface}")
            
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
            if self.save_pcap:
                print(f"Lưu vào file: {self.save_pcap}")
            if self.detect_security:
                print(f"🔒 Bật phát hiện bảo mật: Port Scan, SYN Flood, ARP Spoofing")
            
            print("="*100)
            print("\nẤn Ctrl+C để dừng và xem thống kê\n")
            
            packet_count = 0
            
            while True:
                if self.max_packets and packet_count >= self.max_packets:
                    break
                    
                raw_data, addr = conn.recvfrom(65535)
                
                # Lưu vào PCAP nếu cần
                if self.save_pcap:
                    self.save_packet_to_pcap(raw_data, time.time())
                
                if self.process_packet(raw_data, packet_count + 1):
                    packet_count += 1
                    
        except KeyboardInterrupt:
            print("\n\n⏹ Đang dừng bắt gói tin...")
            if self.save_pcap:
                self.write_pcap_file()
            self.print_statistics()
        except PermissionError:
            print("❌ Lỗi: Chương trình cần quyền root/administrator!")
            print("Vui lòng chạy với: sudo python3 packet_sniffer.py")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Lỗi: {e}")
            sys.exit(1)
    
    def process_packet(self, raw_data, packet_num, offline=False):
        """Xử lý từng gói tin - FIXED"""
        self.stats['total'] += 1
        
        dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)
        
        # ARP
        if eth_proto == 0x0806:
            self.stats['arp'] += 1
            arp_info = self.arp_packet(data)
            
            if self.detect_security and arp_info:
                if self.detect_arp_spoofing(arp_info['src_mac'], arp_info['src_ip']):
                    print(f"\n⚠️  [CẢNH BÁO BẢO MẬT] ARP SPOOFING phát hiện!")
                    print(f"    IP {arp_info['src_ip']} đổi MAC từ {self.arp_cache[arp_info['src_ip']]} → {arp_info['src_mac']}")
            
            if self.filter_protocol and self.filter_protocol.upper() != 'ARP':
                return False
            
            # FIXED: Kiểm tra IP filter cho ARP
            if self.filter_ips and arp_info:
                if arp_info['src_ip'] not in self.filter_ips and arp_info['dest_ip'] not in self.filter_ips:
                    return False
            
            self.print_arp_packet(packet_num, dest_mac, src_mac, arp_info, len(raw_data))
            return True
        
        # IPv4
        elif eth_proto == 8:
            self.stats['ipv4'] += 1
            version, header_length, ttl, proto, src, target, data = self.ipv4_packet(data)
            
            # FIXED: Kiểm tra IP filter - PHẢI KIỂM TRA TRƯỚC KHI LỌC PROTOCOL
            if self.filter_ips:
                if src not in self.filter_ips and target not in self.filter_ips:
                    return False
            
            # Thống kê
            conversation = f"{src} <-> {target}"
            self.ip_conversations[conversation] += 1
            
            proto_name = self.get_protocol_name(proto)
            self.protocol_stats[proto_name] += 1
            
            # ICMP
            if proto == 1:
                self.stats['icmp'] += 1
                icmp_type, code, check_sum, data = self.icmp_packet(data)
                
                if self.ping_reply_only and icmp_type != 0:
                    return False
                
                if self.filter_protocol and self.filter_protocol.upper() != 'ICMP':
                    return False
                    
                self.print_osi_packet(packet_num, dest_mac, src_mac, version, header_length, 
                                     ttl, src, target, proto='ICMP', 
                                     icmp_type=icmp_type, code=code, check_sum=check_sum, 
                                     payload=data, raw_size=len(raw_data))
                return True
            
            # TCP
            elif proto == 6:
                self.stats['tcp'] += 1
                
                (src_port, dest_port, sequence, acknowledgement, flag_ack, flag_fin, 
                 flag_psh, flag_rst, flag_syn, flag_urg, data) = self.tcp_segment(data)
                
                # Lọc port TRƯỚC KHI lọc protocol
                if self.filter_port and (self.filter_port != src_port and self.filter_port != dest_port):
                    return False
                
                # Identify application protocol
                app_proto = self.identify_application_protocol(src_port, dest_port, data)
                
                # FIXED: Lọc theo application protocol
                if self.filter_protocol:
                    filter_upper = self.filter_protocol.upper()
                    if filter_upper == 'TCP':
                        pass  # Accept all TCP
                    elif filter_upper in ['FTP', 'SMTP', 'POP3', 'IMAP', 'HTTP', 'HTTPS', 'SSH']:
                        if filter_upper not in app_proto.upper():
                            return False
                    else:
                        return False
                
                # Phát hiện bảo mật
                if self.detect_security:
                    if flag_syn and not flag_ack:
                        if self.detect_port_scan(src, dest_port):
                            print(f"\n⚠️  [CẢNH BÁO BẢO MẬT] PORT SCAN phát hiện từ {src}!")
                            print(f"    Đã quét {len(self.port_scan_tracker[src])} ports")
                        
                        if self.detect_syn_flood(src):
                            print(f"\n⚠️  [CẢNH BÁO BẢO MẬT] SYN FLOOD phát hiện từ {src}!")
                            print(f"    Số SYN packets: {self.syn_tracker[src]}")
                
                # TCP Stream Reassembly
                stream_key = f"{src}:{src_port}-{target}:{dest_port}"
                if data and flag_psh:
                    self.tcp_streams[stream_key]['data'] += data
                
                # Decode application data
                app_data = None
                if app_proto == 'FTP' and data:
                    app_data = self.decode_ftp(data)
                elif app_proto == 'SMTP' and data:
                    app_data = self.decode_smtp(data)
                elif app_proto == 'POP3' and data:
                    app_data = self.decode_pop3(data)
                elif app_proto == 'IMAP' and data:
                    app_data = self.decode_imap(data)
                
                self.print_osi_packet(packet_num, dest_mac, src_mac, version, header_length, ttl,
                                     src, target, proto='TCP', src_port=src_port, dest_port=dest_port,
                                     sequence=sequence, acknowledgement=acknowledgement,
                                     flags={'ACK': flag_ack, 'FIN': flag_fin, 'PSH': flag_psh,
                                           'RST': flag_rst, 'SYN': flag_syn, 'URG': flag_urg},
                                     payload=data, app_proto=app_proto, raw_size=len(raw_data),
                                     app_data=app_data)
                return True
            
            # UDP
            elif proto == 17:
                self.stats['udp'] += 1
                
                src_port, dest_port, size, data = self.udp_segment(data)
                
                # Lọc port
                if self.filter_port and (self.filter_port != src_port and self.filter_port != dest_port):
                    return False
                
                app_proto = self.identify_application_protocol(src_port, dest_port, data)
                
                # FIXED: Lọc theo protocol
                if self.filter_protocol:
                    filter_upper = self.filter_protocol.upper()
                    if filter_upper == 'UDP':
                        pass  # Accept all UDP
                    elif filter_upper == 'DNS':
                        if src_port != 53 and dest_port != 53:
                            return False
                    else:
                        if filter_upper not in ['UDP', 'DNS']:
                            return False
                
                # Decode DNS nếu là port 53
                dns_info = None
                if src_port == 53 or dest_port == 53:
                    dns_info = self.decode_dns(data)
                
                self.print_osi_packet(packet_num, dest_mac, src_mac, version, header_length, ttl,
                                     src, target, proto='UDP', src_port=src_port, dest_port=dest_port,
                                     udp_size=size, payload=data, app_proto=app_proto, 
                                     raw_size=len(raw_data), dns_info=dns_info)
                return True
            
            else:
                self.stats['other'] += 1
                return False
                
        # IPv6
        elif eth_proto == 0x86DD:
            self.stats['ipv6'] += 1
            ipv6_info = self.ipv6_packet(data)
            
            # FIXED: Kiểm tra IPv6 filter
            if self.filter_ips and ipv6_info:
                if ipv6_info['src'] not in self.filter_ips and ipv6_info['dest'] not in self.filter_ips:
                    return False
            
            if self.filter_protocol and self.filter_protocol.upper() != 'IPV6':
                return False
            
            self.print_ipv6_packet(packet_num, dest_mac, src_mac, ipv6_info, len(raw_data))
            return True
        
        else:
            self.stats['other'] += 1
            return False
    
    def decode_dns(self, data):
        """Decode DNS packet"""
        if len(data) < 12:
            return None
        
        try:
            transaction_id = struct.unpack('!H', data[0:2])[0]
            flags = struct.unpack('!H', data[2:4])[0]
            questions = struct.unpack('!H', data[4:6])[0]
            answers = struct.unpack('!H', data[6:8])[0]
            
            is_response = (flags & 0x8000) >> 15
            opcode = (flags & 0x7800) >> 11
            
            # Parse query name (simplified)
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
    
    def arp_packet(self, data):
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
    
    def ipv6_packet(self, data):
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
    
    def print_arp_packet(self, num, dest_mac, src_mac, arp_info, raw_size):
        """In thông tin gói ARP"""
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        
        print(f"\n{'='*100}")
        print(f"PACKET #{num} - ARP - {timestamp}".center(100))
        print(f"{'='*100}")
        
        print(f"\n┌─ LAYER 2: DATA LINK (ARP)")
        print(f"│  ├─ Source MAC: {src_mac}")
        print(f"│  ├─ Destination MAC: {dest_mac}")
        print(f"│  └─ EtherType: 0x0806 (ARP)")
        
        if arp_info:
            opcode_name = "Request" if arp_info['opcode'] == 1 else "Reply"
            print(f"│")
            print(f"┌─ ARP PROTOCOL")
            print(f"│  ├─ Opcode: {arp_info['opcode']} ({opcode_name})")
            print(f"│  ├─ Sender MAC: {arp_info['src_mac']}")
            print(f"│  ├─ Sender IP: {arp_info['src_ip']}")
            print(f"│  ├─ Target MAC: {arp_info['dest_mac']}")
            print(f"│  └─ Target IP: {arp_info['dest_ip']}")
        
        print(f"│")
        print(f"└─ END OF PACKET #{num}")
        print(f"{'='*100}")
    
    def print_ipv6_packet(self, num, dest_mac, src_mac, ipv6_info, raw_size):
        """In thông tin gói IPv6"""
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        
        print(f"\n{'='*100}")
        print(f"PACKET #{num} - IPv6 - {timestamp}".center(100))
        print(f"{'='*100}")
        
        print(f"\n┌─ LAYER 2: DATA LINK")
        print(f"│  ├─ Source MAC: {src_mac}")
        print(f"│  └─ Destination MAC: {dest_mac}")
        
        if ipv6_info:
            print(f"│")
            print(f"┌─ LAYER 3: NETWORK (IPv6)")
            print(f"│  ├─ Version: {ipv6_info['version']}")
            print(f"│  ├─ Source IPv6: {ipv6_info['src']}")
            print(f"│  ├─ Destination IPv6: {ipv6_info['dest']}")
            print(f"│  ├─ Hop Limit: {ipv6_info['hop_limit']}")
            print(f"│  └─ Payload Length: {ipv6_info['payload_length']} bytes")
        
        print(f"│")
        print(f"└─ END OF PACKET #{num}")
        print(f"{'='*100}")
    
    def print_osi_packet(self, num, dest_mac, src_mac, version, header_length, ttl, 
                         src_ip, target_ip, proto, raw_size, **kwargs):
        """In thông tin gói tin theo OSI 7 layers"""
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        
        src_display = self.get_hostname_display(src_ip)
        target_display = self.get_hostname_display(target_ip)
        
        print(f"\n{'='*100}")
        print(f"PACKET #{num} - {proto} - {timestamp}".center(100))
        print(f"{'='*100}")
        
        # LAYER 1: PHYSICAL
        print(f"\n┌─ LAYER 1: PHYSICAL LAYER (Tầng Vật Lý)")
        print(f"│  └─ Kích thước gói tin thô: {raw_size} bytes")
        print(f"│     Phương tiện: Cáp Ethernet/Không dây")
        print(f"│     Truyền tải: Tín hiệu điện/sóng radio → Dữ liệu nhị phân")
        
        # LAYER 2: DATA LINK
        print(f"│")
        print(f"┌─ LAYER 2: DATA LINK LAYER (Tầng Liên Kết Dữ Liệu)")
        print(f"│  Giao thức: Ethernet Frame")
        print(f"│  ├─ Địa chỉ MAC nguồn: {src_mac}")
        print(f"│  ├─ Địa chỉ MAC đích: {dest_mac}")
        print(f"│  └─ EtherType: 0x0800 (IPv4)")
        
        # LAYER 3: NETWORK
        print(f"│")
        print(f"┌─ LAYER 3: NETWORK LAYER (Tầng Mạng)")
        print(f"│  Giao thức: IPv{version}")
        print(f"│  ├─ IP nguồn: {src_display}")
        print(f"│  ├─ IP đích: {target_display}")
        print(f"│  ├─ TTL (Thời gian sống): {ttl} bước nhảy")
        print(f"│  ├─ Độ dài header: {header_length} bytes")
        print(f"│  └─ Giao thức tầng trên: {proto}")
        
        # LAYER 4: TRANSPORT
        print(f"│")
        print(f"┌─ LAYER 4: TRANSPORT LAYER (Tầng Giao Vận)")
        print(f"│  Giao thức: {proto}")
        
        if proto == 'TCP':
            src_port = kwargs.get('src_port')
            dest_port = kwargs.get('dest_port')
            sequence = kwargs.get('sequence')
            acknowledgement = kwargs.get('acknowledgement')
            flags = kwargs.get('flags', {})
            
            print(f"│  ├─ Cổng nguồn: {src_port}")
            print(f"│  ├─ Cổng đích: {dest_port}")
            print(f"│  ├─ Số thứ tự: {sequence}")
            print(f"│  ├─ Số xác nhận: {acknowledgement}")
            
            active_flags = [name for name, value in flags.items() if value]
            print(f"│  ├─ Cờ (Flags): {', '.join(active_flags) if active_flags else 'Không có'}")
            
            if flags.get('SYN') and not flags.get('ACK'):
                print(f"│  │  └─ Kết nối: Đang khởi tạo (SYN)")
            elif flags.get('SYN') and flags.get('ACK'):
                print(f"│  │  └─ Kết nối: Đang chấp nhận (SYN-ACK)")
            elif flags.get('ACK') and not flags.get('SYN'):
                print(f"│  │  └─ Kết nối: Đã thiết lập/Truyền dữ liệu")
            elif flags.get('FIN'):
                print(f"│  │  └─ Kết nối: Đang đóng (FIN)")
            elif flags.get('RST'):
                print(f"│  │  └─ Kết nối: Bị reset (RST)")
            
            print(f"│  └─ Kết nối: {src_ip}:{src_port} ⟷ {target_ip}:{dest_port}")
            
        elif proto == 'UDP':
            src_port = kwargs.get('src_port')
            dest_port = kwargs.get('dest_port')
            udp_size = kwargs.get('udp_size')
            dns_info = kwargs.get('dns_info')
            
            print(f"│  ├─ Cổng nguồn: {src_port}")
            print(f"│  ├─ Cổng đích: {dest_port}")
            print(f"│  ├─ Độ dài: {udp_size} bytes")
            print(f"│  └─ Kết nối: {src_ip}:{src_port} → {target_ip}:{dest_port} (Không kết nối)")
            
            if dns_info:
                print(f"│")
                print(f"│  🌐 DNS INFORMATION:")
                query_type = "Response (Trả lời)" if dns_info['is_response'] else "Query (Truy vấn)"
                print(f"│  ├─ Loại: {query_type}")
                print(f"│  ├─ Domain: {dns_info['domain']}")
                print(f"│  ├─ Câu hỏi: {dns_info['questions']}")
                print(f"│  └─ Câu trả lời: {dns_info['answers']}")
            
        elif proto == 'ICMP':
            icmp_type = kwargs.get('icmp_type')
            code = kwargs.get('code')
            check_sum = kwargs.get('check_sum')
            
            print(f"│  ├─ Loại (Type): {icmp_type} ({self.get_icmp_type_name(icmp_type)})")
            print(f"│  ├─ Mã (Code): {code}")
            print(f"│  ├─ Checksum: {check_sum}")
            print(f"│  └─ Hướng: {src_ip} → {target_ip}")
            
            if icmp_type == 8:
                print(f"│     Info: Yêu cầu Ping (Echo Request)")
            elif icmp_type == 0:
                print(f"│     Info: Trả lời Ping (Echo Reply) ✓")
        
        # LAYER 5: SESSION
        print(f"│")
        print(f"┌─ LAYER 5: SESSION LAYER (Tầng Phiên)")
        
        if proto == 'TCP':
            flags = kwargs.get('flags', {})
            if flags.get('SYN'):
                print(f"│  └─ Phiên: Đang thiết lập phiên mới")
            elif flags.get('FIN'):
                print(f"│  └─ Phiên: Đang đóng phiên")
            elif flags.get('RST'):
                print(f"│  └─ Phiên: Đang kết thúc phiên")
            else:
                print(f"│  └─ Phiên: Phiên đang hoạt động")
        elif proto == 'UDP':
            print(f"│  └─ Phiên: Không trạng thái (không quản lý phiên)")
        elif proto == 'ICMP':
            print(f"│  └─ Phiên: Phiên Yêu cầu-Trả lời")
        
        # LAYER 6: PRESENTATION
        print(f"│")
        print(f"┌─ LAYER 6: PRESENTATION LAYER (Tầng Trình Diễn)")
        payload = kwargs.get('payload', b'')
        
        if payload:
            if self.is_encrypted(payload):
                print(f"│  ├─ Định dạng dữ liệu: Đã mã hóa/Nhị phân")
                print(f"│  ├─ Mã hóa: Có thể là TLS/SSL")
            elif self.is_text(payload):
                print(f"│  ├─ Định dạng dữ liệu: Văn bản thuần")
                print(f"│  ├─ Mã hóa: ASCII/UTF-8")
            else:
                print(f"│  ├─ Định dạng dữ liệu: Nhị phân")
                print(f"│  ├─ Mã hóa: Dữ liệu nhị phân thô")
            print(f"│  └─ Kích thước dữ liệu: {len(payload)} bytes")
        else:
            print(f"│  └─ Không có dữ liệu payload")
        
        # LAYER 7: APPLICATION
        print(f"│")
        print(f"┌─ LAYER 7: APPLICATION LAYER (Tầng Ứng Dụng)")
        app_proto = kwargs.get('app_proto', 'Unknown')
        app_data = kwargs.get('app_data')
        
        if proto == 'TCP' or proto == 'UDP':
            src_port = kwargs.get('src_port')
            dest_port = kwargs.get('dest_port')
            print(f"│  ├─ Giao thức ứng dụng: {app_proto}")
            print(f"│  ├─ Dịch vụ: {self.get_service_name(src_port, dest_port)}")
            
            # Display FTP/SMTP/POP3/IMAP specific data
            if app_data:
                print(f"│  │")
                if app_proto == 'FTP':
                    print(f"│  │  📁 FTP Protocol:")
                    if app_data['type'] == 'command':
                        print(f"│  │  ├─ Type: Command")
                        print(f"│  │  ├─ Command: {app_data['command']}")
                        print(f"│  │  └─ Full: {app_data['full']}")
                        if 'filename' in app_data:
                            print(f"│  │  └─ Filename: {app_data['filename']}")
                    elif app_data['type'] == 'response':
                        print(f"│  │  ├─ Type: Response")
                        print(f"│  │  ├─ Code: {app_data['code']}")
                        print(f"│  │  ├─ Status: {app_data.get('status', 'unknown')}")
                        print(f"│  │  └─ Message: {app_data['message']}")
                elif app_proto == 'SMTP':
                    print(f"│  │  📧 SMTP Protocol:")
                    if app_data['type'] == 'command':
                        print(f"│  │  ├─ Type: Command")
                        print(f"│  │  ├─ Command: {app_data['command']}")
                        print(f"│  │  └─ Full: {app_data['full']}")
                        if 'email' in app_data:
                            print(f"│  │  └─ Email: {app_data['email']}")
                    elif app_data['type'] == 'response':
                        print(f"│  │  ├─ Type: Response")
                        print(f"│  │  ├─ Code: {app_data['code']}")
                        print(f"│  │  ├─ Status: {app_data.get('status', 'unknown')}")
                        print(f"│  │  └─ Message: {app_data['message']}")
                elif app_proto == 'POP3':
                    print(f"│  │  📬 POP3 Protocol:")
                    if app_data['type'] == 'command':
                        print(f"│  │  ├─ Type: Command")
                        print(f"│  │  ├─ Command: {app_data['command']}")
                        print(f"│  │  └─ Full: {app_data['full']}")
                        if 'message_id' in app_data:
                            print(f"│  │  └─ Message ID: {app_data['message_id']}")
                    elif app_data['type'] == 'response':
                        print(f"│  │  ├─ Type: Response")
                        print(f"│  │  ├─ Status: {app_data['status']}")
                        print(f"│  │  ├─ Success: {app_data.get('success', False)}")
                        print(f"│  │  └─ Message: {app_data['message']}")
                elif app_proto == 'IMAP':
                    print(f"│  │  📮 IMAP Protocol:")
                    if app_data['type'] == 'command':
                        print(f"│  │  ├─ Type: Command")
                        print(f"│  │  ├─ Tag: {app_data['tag']}")
                        print(f"│  │  ├─ Command: {app_data['command']}")
                        print(f"│  │  └─ Full: {app_data['full']}")
                    elif app_data['type'] == 'response':
                        print(f"│  │  ├─ Type: Response")
                        if 'tag' in app_data:
                            print(f"│  │  ├─ Tag: {app_data['tag']}")
                        if 'status' in app_data:
                            print(f"│  │  ├─ Status: {app_data['status']}")
                        print(f"│  │  └─ Message: {app_data['message']}")
            
            if payload and app_proto not in ['FTP', 'SMTP', 'POP3', 'IMAP'] and app_proto != 'Unknown':
                self.analyze_application_data(payload, app_proto)
            elif payload and not app_data:
                print(f"│  └─ Payload: {len(payload)} bytes")
                if len(payload) > 0 and self.is_text(payload):
                    preview = payload[:100].decode('utf-8', errors='ignore')
                    print(f"│     Xem trước: {preview[:50]}...")
        elif proto == 'ICMP':
            print(f"│  ├─ Ứng dụng: ICMP (Chẩn đoán mạng)")
            print(f"│  ├─ Công cụ: ping/traceroute")
            print(f"│  └─ Mục đích: Kiểm tra kết nối mạng")
        
        print(f"│")
        print(f"└─ KẾT THÚC PACKET #{num}")
        print(f"{'='*100}")
    
    def identify_application_protocol(self, src_port, dest_port, data):
        """Xác định protocol tầng application"""
        port_protocols = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 587: 'SMTP',
            3389: 'RDP', 5060: 'SIP', 5061: 'SIPS'
        }
        
        if dest_port in port_protocols:
            return port_protocols[dest_port]
        elif src_port in port_protocols:
            return port_protocols[src_port]
        
        if data:
            if data.startswith(b'GET ') or data.startswith(b'POST ') or data.startswith(b'HTTP/'):
                return 'HTTP'
            elif data.startswith(b'\x16\x03'):
                return 'TLS/SSL'
            elif b'SSH-' in data[:10]:
                return 'SSH'
        
        return 'Unknown'
    
    def get_service_name(self, src_port, dest_port):
        """Lấy tên service"""
        services = {
            20: 'File Transfer Protocol (Data)',
            21: 'File Transfer Protocol (Control)',
            22: 'Secure Shell',
            23: 'Telnet',
            25: 'Simple Mail Transfer Protocol',
            53: 'Domain Name System',
            67: 'DHCP Server',
            68: 'DHCP Client',
            80: 'HyperText Transfer Protocol',
            110: 'Post Office Protocol v3',
            143: 'Internet Message Access Protocol',
            443: 'HTTP Secure (HTTPS)',
            445: 'Server Message Block',
            587: 'SMTP (Mail Submission)',
            993: 'IMAP over SSL',
            995: 'POP3 over SSL',
            3389: 'Remote Desktop Protocol',
            5060: 'Session Initiation Protocol',
        }
        
        port = dest_port if dest_port in services else src_port
        return services.get(port, f'Port {dest_port}')
    
    def is_text(self, data):
        """Kiểm tra xem data có phải text không"""
        if not data:
            return False
        try:
            sample = data[:100]
            sample.decode('utf-8')
            printable = sum(32 <= b < 127 or b in [9, 10, 13] for b in sample)
            return printable / len(sample) > 0.7
        except:
            return False
    
    def is_encrypted(self, data):
        """Kiểm tra xem data có bị mã hóa không"""
        if not data or len(data) < 10:
            return False
        
        if data[0:3] in [b'\x16\x03\x00', b'\x16\x03\x01', b'\x16\x03\x02', b'\x16\x03\x03']:
            return True
        
        if len(data) >= 100:
            unique_bytes = len(set(data[:100]))
            if unique_bytes > 80:
                return True
        
        return False
    
    def analyze_application_data(self, data, protocol):
        """Phân tích dữ liệu tầng application"""
        print(f"│  ├─ Phân tích dữ liệu:")
        
        if protocol == 'HTTP' and self.is_text(data):
            text = data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            if lines:
                print(f"│  │  └─ Request/Response: {lines[0][:70]}")
        elif protocol == 'HTTPS' or protocol == 'TLS/SSL':
            print(f"│  │  └─ Dữ liệu đã mã hóa (TLS/SSL)")
        elif protocol == 'DNS':
            print(f"│  │  └─ Truy vấn/phản hồi DNS")
        else:
            print(f"│  │  └─ Dữ liệu nhị phân: {len(data)} bytes")
    
    def print_statistics(self):
        """In thống kê chi tiết"""
        duration = time.time() - self.start_time
        
        print("\n" + "="*100)
        print("THỐNG KÊ BẮT GÓI TIN".center(100))
        print("="*100)
        print(f"Thời gian: {duration:.2f} giây")
        print(f"Tổng số gói tin: {self.stats['total']}")
        print(f"\nGói tin mỗi giây: {self.stats['total']/max(duration,0.001):.2f}")
        
        print(f"\nPhân bổ giao thức:")
        print(f"{TAB_1}IPv4: {self.stats['ipv4']} ({self.stats['ipv4']/max(self.stats['total'],1)*100:.1f}%)")
        print(f"{TAB_1}IPv6: {self.stats['ipv6']} ({self.stats['ipv6']/max(self.stats['total'],1)*100:.1f}%)")
        print(f"{TAB_1}TCP: {self.stats['tcp']} ({self.stats['tcp']/max(self.stats['total'],1)*100:.1f}%)")
        print(f"{TAB_1}UDP: {self.stats['udp']} ({self.stats['udp']/max(self.stats['total'],1)*100:.1f}%)")
        print(f"{TAB_1}ICMP: {self.stats['icmp']} ({self.stats['icmp']/max(self.stats['total'],1)*100:.1f}%)")
        print(f"{TAB_1}ARP: {self.stats['arp']} ({self.stats['arp']/max(self.stats['total'],1)*100:.1f}%)")
        print(f"{TAB_1}Khác: {self.stats['other']} ({self.stats['other']/max(self.stats['total'],1)*100:.1f}%)")
        
        if self.protocol_stats:
            print(f"\nThống kê giao thức chi tiết:")
            for proto, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"{TAB_1}{proto}: {count}")
        
        if self.ip_conversations:
            print(f"\nTop 10 cuộc hội thoại IP:")
            for conv, count in sorted(self.ip_conversations.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"{TAB_1}{conv}: {count} gói tin")
        
        if self.detect_security:
            print(f"\n🔒 PHÁT HIỆN BẢO MẬT:")
            print(f"{TAB_1}Port Scan phát hiện: {len([ip for ip, ports in self.port_scan_tracker.items() if len(ports) > 10])}")
            print(f"{TAB_1}SYN Flood phát hiện: {len([ip for ip, count in self.syn_tracker.items() if count > 50])}")
        
        print("="*100)
    
    # Các hàm phân tích gói tin cơ bản
    def ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]
    
    def get_mac_addr(self, bytes_addr):
        return ':'.join(map('{:02x}'.format, bytes_addr)).upper()
    
    def ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
        return version, header_length, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_length:]
    
    def ipv4(self, addr):
        return '.'.join(map(str, addr))
    
    def icmp_packet(self, data):
        icmp_type, code, check_sum = struct.unpack('!BBH', data[:4])
        return icmp_type, code, check_sum, data[4:]
    
    def tcp_segment(self, data):
        src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        return src_port, dest_port, sequence, acknowledgement, flag_ack, flag_fin, flag_psh, flag_rst, flag_syn, flag_urg, data[offset:]
    
    def udp_segment(self, data):
        src_port, dest_port, size = struct.unpack('!HHH', data[:6])
        return src_port, dest_port, size, data[8:]
    
    def get_protocol_name(self, proto):
        """Trả về tên protocol"""
        protocols = {
            1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP',
            41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH', 89: 'OSPF',
        }
        return protocols.get(proto, f'Unknown({proto})')
    
    def get_icmp_type_name(self, icmp_type):
        """Trả về tên ICMP type"""
        types = {
            0: 'Echo Reply', 3: 'Destination Unreachable',
            8: 'Echo Request', 11: 'Time Exceeded',
            13: 'Timestamp Request', 14: 'Timestamp Reply',
        }
        return types.get(icmp_type, 'Unknown')


def main():
    parser = argparse.ArgumentParser(
        description='🔍 Packet Sniffer Nâng Cao - Clone Wireshark - Hỗ trợ OSI 7 tầng',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
 VÍ DỤ SỬ DỤNG:
═══════════════════════════════════════════════════════════════

🔹 CƠ BẢN:
  sudo python3 packet_sniffer.py                        # Bắt tất cả gói tin
  sudo python3 packet_sniffer.py -n 10                  # Bắt 10 gói rồi dừng
  
🔹 LỌC THEO GIAO THỨC:
  sudo python3 packet_sniffer.py -p tcp                 # Chỉ bắt TCP
  sudo python3 packet_sniffer.py -p udp                 # Chỉ bắt UDP
  sudo python3 packet_sniffer.py -p icmp                # Chỉ bắt ICMP (ping)
  sudo python3 packet_sniffer.py -p arp                 # Chỉ bắt ARP
  sudo python3 packet_sniffer.py -p ipv6                # Chỉ bắt IPv6
  sudo python3 packet_sniffer.py -p ftp                 # Chỉ bắt FTP
  sudo python3 packet_sniffer.py -p smtp                # Chỉ bắt SMTP
  sudo python3 packet_sniffer.py -p pop3                # Chỉ bắt POP3
  sudo python3 packet_sniffer.py -p imap                # Chỉ bắt IMAP
  
🔹 LỌC THEO IP/DOMAIN:
  sudo python3 packet_sniffer.py -i 8.8.8.8             # Lọc theo IP
  sudo python3 packet_sniffer.py -d google.com          # Lọc theo domain
  sudo python3 packet_sniffer.py -d youtube.com -p tcp  # TCP traffic với YouTube
  
🔹 LỌC THEO PORT:
  sudo python3 packet_sniffer.py -P 80                  # HTTP traffic
  sudo python3 packet_sniffer.py -P 443                 # HTTPS traffic
  sudo python3 packet_sniffer.py -P 53 -p udp           # DNS queries
  sudo python3 packet_sniffer.py -p tcp -P 22           # SSH connections
  sudo python3 packet_sniffer.py -P 21                  # FTP traffic
  sudo python3 packet_sniffer.py -P 25                  # SMTP traffic
  sudo python3 packet_sniffer.py -P 110                 # POP3 traffic
  sudo python3 packet_sniffer.py -P 143                 # IMAP traffic
  
🔹 PING & ICMP:
  sudo python3 packet_sniffer.py --ping-reply-only      # CHỈ bắt ping reply
  sudo python3 packet_sniffer.py -d google.com -p icmp  # Ping đến/đi Google
  
🔹 LƯU & ĐỌC FILE:
  sudo python3 packet_sniffer.py -s capture.json        # Lưu vào file
  sudo python3 packet_sniffer.py -r capture.json        # Đọc từ file
  sudo python3 packet_sniffer.py -s data.json -n 100    # Lưu 100 gói
  
🔹 PHÁT HIỆN BẢO MẬT:
  sudo python3 packet_sniffer.py --security             # Bật phát hiện tấn công
  sudo python3 packet_sniffer.py --security -p tcp      # Phát hiện port scan
  
🔹 CHỌN INTERFACE:
  sudo python3 packet_sniffer.py -I eth0                # Bắt trên eth0
  sudo python3 packet_sniffer.py -I wlan0               # Bắt trên WiFi
  
🔹 KẾT HỢP NHIỀU THAM SỐ:
  sudo python3 packet_sniffer.py -p tcp -P 443 -d facebook.com -n 50
  # Bắt 50 gói HTTPS đến/từ Facebook
  
  sudo python3 packet_sniffer.py --security -s attack.json
  # Phát hiện tấn công và lưu vào file
  
        '''
    )
    
    # Filter options
    parser.add_argument('-p', '--protocol', type=str, 
                       help='Lọc theo giao thức (tcp, udp, icmp, arp, ipv6, ftp, smtp, pop3, imap)')
    parser.add_argument('-i', '--ip', type=str,
                       help='Lọc theo địa chỉ IP')
    parser.add_argument('-d', '--domain', type=str,
                       help='Lọc theo tên miền (sẽ tự động phân giải sang IP)')
    parser.add_argument('-P', '--port', type=int,
                       help='Lọc theo số cổng (port)')
    parser.add_argument('-n', '--number', type=int,
                       help='Số lượng gói tin cần bắt')
    
    # Special modes
    parser.add_argument('--ping-reply-only', action='store_true',
                       help='CHỈ bắt ICMP Echo Reply (phản hồi ping)')
    
    # File operations
    parser.add_argument('-s', '--save', type=str,
                       help='Lưu gói tin vào file JSON')
    parser.add_argument('-r', '--read', type=str,
                       help='Đọc và phân tích file đã lưu')
    
    # Advanced options
    parser.add_argument('-I', '--interface', type=str,
                       help='Chọn network interface (eth0, wlan0, ...)')
    parser.add_argument('--security', action='store_true',
                       help='Bật phát hiện bảo mật (Port Scan, SYN Flood, ARP Spoofing)')
    
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