from flask import Flask, render_template, request, jsonify, Response
from flask_cors import CORS
import threading
import queue
import json
import time
from datetime import datetime
import sys
import os

# Import PacketSniffer từ core module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core import PacketSniffer

app = Flask(__name__)
CORS(app)

# Queue để lưu trữ packets
packet_queue = queue.Queue()
sniffer_thread = None
sniffer_instance = None
is_sniffing = False

class WebPacketSniffer(PacketSniffer):
    """Mở rộng PacketSniffer để gửi data qua web"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.web_packets = []
        self.web_packets_details = {}
        self.web_packet_counter = 0
    
    def process_packet(self, raw_data, packet_num, offline=False):
        """Override để capture packet info - FIXED FILTERING"""
        # Tạo summary TRƯỚC KHI filter
        packet_info = self.create_packet_summary(raw_data, packet_num)
        
        # Gọi parent process_packet để áp dụng filter
        result = super().process_packet(raw_data, packet_num, offline)
        
        # Chỉ thêm vào web nếu packet PASS filter
        if result and packet_info:
            self.web_packet_counter += 1
            packet_info['num'] = self.web_packet_counter
            
            self.web_packets.append(packet_info)
            self.web_packets_details[self.web_packet_counter] = packet_info
            packet_queue.put(packet_info)
        
        return result
    
    def create_packet_summary(self, raw_data, packet_num):
        """Tạo summary của packet"""
        try:
            dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)
            
            packet_info = {
                'num': packet_num,
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'length': len(raw_data),
                'src_mac': src_mac,
                'dest_mac': dest_mac,
                'protocol': 'Unknown',
                'src_ip': '',
                'dest_ip': '',
                'src_port': '',
                'dest_port': '',
                'info': '',
                'raw_data': raw_data.hex(),
                'osi_layers': {}
            }
            
            # ARP
            if eth_proto == 0x0806:
                return self._handle_arp_packet(packet_info, data, src_mac, dest_mac, raw_data)
            
            # IPv4
            elif eth_proto == 8:
                return self._handle_ipv4_packet(packet_info, data, src_mac, dest_mac, raw_data)
            
            # IPv6
            elif eth_proto == 0x86DD:
                return self._handle_ipv6_packet(packet_info, data, src_mac, dest_mac, raw_data)
            
            return packet_info
            
        except Exception as e:
            print(f"Error in create_packet_summary: {e}")
            return None
    
    def _handle_arp_packet(self, packet_info, data, src_mac, dest_mac, raw_data):
        """Handle ARP packet"""
        packet_info['protocol'] = 'ARP'
        arp_info = self.arp_packet(data)
        if arp_info:
            packet_info['src_ip'] = arp_info['src_ip']
            packet_info['dest_ip'] = arp_info['dest_ip']
            packet_info['info'] = f"{'Request' if arp_info['opcode'] == 1 else 'Reply'}: Who has {arp_info['dest_ip']}? Tell {arp_info['src_ip']}"
            packet_info['osi_layers'] = self._build_arp_layers(raw_data, src_mac, dest_mac, arp_info)
        return packet_info
    
    def _handle_ipv4_packet(self, packet_info, data, src_mac, dest_mac, raw_data):
        """Handle IPv4 packet"""
        version, header_length, ttl, proto, src, target, ip_data = self.ipv4_packet(data)
        packet_info['src_ip'] = src
        packet_info['dest_ip'] = target
        
        # Base layers
        packet_info['osi_layers'] = self._build_ipv4_base_layers(raw_data, src_mac, dest_mac, version, header_length, ttl, proto, src, target)
        
        # ICMP
        if proto == 1:
            return self._handle_icmp(packet_info, ip_data)
        
        # TCP
        elif proto == 6:
            return self._handle_tcp(packet_info, ip_data, src, target)
        
        # UDP
        elif proto == 17:
            return self._handle_udp(packet_info, ip_data, src, target)
        
        return packet_info
    
    def _handle_ipv6_packet(self, packet_info, data, src_mac, dest_mac, raw_data):
        """Handle IPv6 packet - ENHANCED"""
        packet_info['protocol'] = 'IPv6'
        ipv6_info = self.ipv6_packet(data)
        
        if not ipv6_info:
            return packet_info
        
        packet_info['src_ip'] = ipv6_info['src']
        packet_info['dest_ip'] = ipv6_info['dest']
        
        # Build base IPv6 layers
        packet_info['osi_layers'] = {
            'layer1': {
                'name': 'Physical Layer',
                'info': f"Kích thước: {len(raw_data)} bytes, Truyền tải tín hiệu"
            },
            'layer2': {
                'name': 'Data Link Layer',
                'protocol': 'Ethernet',
                'src_mac': src_mac,
                'dest_mac': dest_mac,
                'details': {'EtherType': '0x86DD (IPv6)'}
            },
            'layer3': {
                'name': 'Network Layer',
                'protocol': 'IPv6',
                'src_ip': ipv6_info['src'],
                'dest_ip': ipv6_info['dest'],
                'details': {
                    'Version': str(ipv6_info['version']),
                    'Hop Limit': str(ipv6_info['hop_limit']),
                    'Payload Length': f"{ipv6_info['payload_length']} bytes",
                    'Next Header': self.get_protocol_name(ipv6_info['next_header'])
                }
            }
        }
        
        # Handle IPv6 payload based on next header
        payload = data[40:]  # IPv6 header is 40 bytes
        next_header = ipv6_info['next_header']
        
        # ICMPv6
        if next_header == 58:
            packet_info['protocol'] = 'ICMPv6'
            if len(payload) >= 4:
                icmpv6_type = payload[0]
                from .utils import get_icmpv6_type_name
                packet_info['info'] = get_icmpv6_type_name(icmpv6_type)
                
                packet_info['osi_layers']['layer4'] = {
                    'name': 'Transport Layer',
                    'protocol': 'ICMPv6',
                    'details': {
                        'Type': f"{icmpv6_type} ({get_icmpv6_type_name(icmpv6_type)})",
                        'Code': str(payload[1]) if len(payload) > 1 else 'N/A'
                    }
                }
        
        # TCP over IPv6
        elif next_header == 6:
            return self._handle_tcp_ipv6(packet_info, payload, ipv6_info['src'], ipv6_info['dest'])
        
        # UDP over IPv6
        elif next_header == 17:
            return self._handle_udp_ipv6(packet_info, payload, ipv6_info['src'], ipv6_info['dest'])
        
        return packet_info
    
    def _handle_tcp_ipv6(self, packet_info, data, src_ip, dest_ip):
        """Handle TCP over IPv6"""
        src_port, dest_port, sequence, acknowledgement, flag_ack, flag_fin, flag_psh, flag_rst, flag_syn, flag_urg, tcp_payload = self.tcp_segment(data)
        
        packet_info['protocol'] = 'TCP/IPv6'
        packet_info['src_port'] = src_port
        packet_info['dest_port'] = dest_port
        
        flags = []
        if flag_syn: flags.append('SYN')
        if flag_ack: flags.append('ACK')
        if flag_fin: flags.append('FIN')
        if flag_rst: flags.append('RST')
        if flag_psh: flags.append('PSH')
        
        packet_info['info'] = f"[{','.join(flags)}] {src_ip}:{src_port} → {dest_ip}:{dest_port}"
        
        # Identify application protocol
        app_proto = self.identify_application_protocol(src_port, dest_port, tcp_payload)
        if app_proto != 'Unknown':
            packet_info['protocol'] = f"TCP/IPv6/{app_proto}"
        
        # Decode application data
        app_data = self._decode_application_data(app_proto, tcp_payload)
        
        # Build OSI layers
        self._build_tcp_layers(packet_info, src_port, dest_port, sequence, acknowledgement, flags, src_ip, dest_ip, tcp_payload, app_proto, app_data)
        
        return packet_info
    
    def _handle_udp_ipv6(self, packet_info, data, src_ip, dest_ip):
        """Handle UDP over IPv6"""
        src_port, dest_port, size, udp_payload = self.udp_segment(data)
        
        packet_info['protocol'] = 'UDP/IPv6'
        packet_info['src_port'] = src_port
        packet_info['dest_port'] = dest_port
        packet_info['info'] = f"{src_ip}:{src_port} → {dest_ip}:{dest_port} Len={size}"
        
        # Check for DNS
        dns_info = None
        if src_port == 53 or dest_port == 53:
            packet_info['protocol'] = 'DNS/IPv6'
            dns_info = self.decode_dns(udp_payload)
            if dns_info:
                packet_info['info'] = f"DNS {'Response' if dns_info['is_response'] else 'Query'}: {dns_info['domain']}"
        
        # Build OSI layers
        self._build_udp_layers(packet_info, src_port, dest_port, size, src_ip, dest_ip, udp_payload, dns_info)
        
        return packet_info
    
    def _decode_application_data(self, app_proto, payload):
        """Decode application layer data"""
        if not payload:
            return None
        
        if app_proto == 'FTP':
            return self.decode_ftp(payload)
        elif app_proto == 'SMTP':
            return self.decode_smtp(payload)
        elif app_proto == 'POP3':
            return self.decode_pop3(payload)
        elif app_proto == 'IMAP':
            return self.decode_imap(payload)
        elif app_proto == 'HTTP':
            from .protocols import decode_http
            return decode_http(payload)
        elif app_proto == 'DNS':
            return self.decode_dns(payload)
        
        return None
    
    def _build_tcp_layers(self, packet_info, src_port, dest_port, sequence, acknowledgement, flags, src_ip, dest_ip, tcp_payload, app_proto, app_data):
        """Build OSI layers for TCP"""
        packet_info['osi_layers']['layer4'] = {
            'name': 'Transport Layer',
            'protocol': 'TCP',
            'details': {
                'Source Port': str(src_port),
                'Destination Port': str(dest_port),
                'Sequence Number': str(sequence),
                'Acknowledgement': str(acknowledgement),
                'Flags': ', '.join(flags) if flags else 'None',
                'Connection': f"{src_ip}:{src_port} ⟷ {dest_ip}:{dest_port}"
            }
        }
        
        # Session Layer
        session_info = 'Phiên đang hoạt động'
        if 'SYN' in flags and 'ACK' not in flags:
            session_info = 'Đang thiết lập phiên mới (SYN)'
        elif 'FIN' in flags:
            session_info = 'Đang đóng phiên (FIN)'
        elif 'RST' in flags:
            session_info = 'Kết thúc phiên đột ngột (RST)'
        
        packet_info['osi_layers']['layer5'] = {
            'name': 'Session Layer',
            'info': session_info
        }
        
        # Presentation Layer
        if tcp_payload:
            if self.is_encrypted(tcp_payload):
                pres_info = 'Dữ liệu đã mã hóa (TLS/SSL)'
            elif self.is_text(tcp_payload):
                pres_info = f'Văn bản thuần (ASCII/UTF-8), {len(tcp_payload)} bytes'
            else:
                pres_info = f'Dữ liệu nhị phân, {len(tcp_payload)} bytes'
        else:
            pres_info = 'Không có payload'
        
        packet_info['osi_layers']['layer6'] = {
            'name': 'Presentation Layer',
            'info': pres_info
        }
        
        # Application Layer
        app_layer = {
            'name': 'Application Layer',
            'protocol': app_proto,
            'info': self.get_service_name(src_port, dest_port)
        }
        
        # Add protocol-specific data
        if app_data and app_data.get('type') != 'unknown':
            if app_proto == 'FTP':
                app_layer['ftp'] = app_data
            elif app_proto == 'SMTP':
                app_layer['smtp'] = app_data
            elif app_proto == 'POP3':
                app_layer['pop3'] = app_data
            elif app_proto == 'IMAP':
                app_layer['imap'] = app_data
            elif app_proto == 'HTTP':
                app_layer['http'] = app_data
        
        # Add text preview
        if tcp_payload and self.is_text(tcp_payload) and not app_data:
            preview = tcp_payload[:100].decode('utf-8', errors='ignore')
            app_layer['preview'] = preview[:50] + ('...' if len(preview) > 50 else '')
        
        packet_info['osi_layers']['layer7'] = app_layer
    
    def _build_udp_layers(self, packet_info, src_port, dest_port, size, src_ip, dest_ip, udp_payload, dns_info=None):
        """Build OSI layers for UDP"""
        packet_info['osi_layers']['layer4'] = {
            'name': 'Transport Layer',
            'protocol': 'UDP',
            'details': {
                'Source Port': str(src_port),
                'Destination Port': str(dest_port),
                'Length': f'{size} bytes',
                'Connection': f"{src_ip}:{src_port} → {dest_ip}:{dest_port} (Connectionless)"
            }
        }
        
        packet_info['osi_layers']['layer5'] = {
            'name': 'Session Layer',
            'info': 'Không trạng thái (không quản lý phiên)'
        }
        
        packet_info['osi_layers']['layer6'] = {
            'name': 'Presentation Layer',
            'info': f'Dữ liệu UDP, {len(udp_payload)} bytes' if udp_payload else 'Không có payload'
        }
        
        app_proto = self.identify_application_protocol(src_port, dest_port, udp_payload)
        app_layer = {
            'name': 'Application Layer',
            'protocol': app_proto,
            'info': self.get_service_name(src_port, dest_port)
        }
        
        if dns_info:
            app_layer['dns'] = {
                'Type': 'Response' if dns_info['is_response'] else 'Query',
                'Domain': dns_info['domain'],
                'Questions': str(dns_info['questions']),
                'Answers': str(dns_info['answers']),
                'Transaction ID': f"0x{dns_info['transaction_id']:04x}"
            }
        
        packet_info['osi_layers']['layer7'] = app_layer
    
    # Helper methods for other packet types
    def _build_arp_layers(self, raw_data, src_mac, dest_mac, arp_info):
        """Build OSI layers for ARP"""
        return {
            'layer1': {
                'name': 'Physical Layer',
                'info': f"Kích thước: {len(raw_data)} bytes, Truyền tải qua cáp Ethernet/Wireless"
            },
            'layer2': {
                'name': 'Data Link Layer',
                'protocol': 'Ethernet/ARP',
                'src_mac': src_mac,
                'dest_mac': dest_mac,
                'details': {
                    'ARP Opcode': f"{arp_info['opcode']} ({'Request' if arp_info['opcode'] == 1 else 'Reply'})",
                    'Sender MAC': arp_info['src_mac'],
                    'Sender IP': arp_info['src_ip'],
                    'Target MAC': arp_info['dest_mac'],
                    'Target IP': arp_info['dest_ip']
                }
            }
        }
    
    def _build_ipv4_base_layers(self, raw_data, src_mac, dest_mac, version, header_length, ttl, proto, src, target):
        """Build base OSI layers for IPv4"""
        return {
            'layer1': {
                'name': 'Physical Layer',
                'info': f"Kích thước: {len(raw_data)} bytes, Truyền tải tín hiệu điện/sóng radio"
            },
            'layer2': {
                'name': 'Data Link Layer',
                'protocol': 'Ethernet',
                'src_mac': src_mac,
                'dest_mac': dest_mac,
                'details': {'EtherType': '0x0800 (IPv4)'}
            },
            'layer3': {
                'name': 'Network Layer',
                'protocol': f'IPv{version}',
                'src_ip': src,
                'dest_ip': target,
                'details': {
                    'TTL': f'{ttl} hops',
                    'Header Length': f'{header_length} bytes',
                    'Protocol': self.get_protocol_name(proto)
                }
            }
        }
    
    def _handle_icmp(self, packet_info, ip_data):
        """Handle ICMP packet"""
        packet_info['protocol'] = 'ICMP'
        icmp_type, code, check_sum, icmp_data = self.icmp_packet(ip_data)
        packet_info['info'] = self.get_icmp_type_name(icmp_type)
        
        packet_info['osi_layers']['layer4'] = {
            'name': 'Transport Layer',
            'protocol': 'ICMP',
            'details': {
                'Type': f"{icmp_type} ({self.get_icmp_type_name(icmp_type)})",
                'Code': str(code),
                'Checksum': f"0x{check_sum:04x}"
            }
        }
        packet_info['osi_layers']['layer5'] = {
            'name': 'Session Layer',
            'info': 'Phiên Yêu cầu-Trả lời ICMP'
        }
        packet_info['osi_layers']['layer6'] = {
            'name': 'Presentation Layer',
            'info': 'Dữ liệu nhị phân ICMP'
        }
        packet_info['osi_layers']['layer7'] = {
            'name': 'Application Layer',
            'protocol': 'ICMP',
            'info': 'Chẩn đoán mạng (ping/traceroute)'
        }
        
        return packet_info
    
    def _handle_tcp(self, packet_info, ip_data, src, target):
        """Handle TCP packet"""
        packet_info['protocol'] = 'TCP'
        src_port, dest_port, sequence, acknowledgement, flag_ack, flag_fin, flag_psh, flag_rst, flag_syn, flag_urg, tcp_payload = self.tcp_segment(ip_data)
        packet_info['src_port'] = src_port
        packet_info['dest_port'] = dest_port
        
        flags = []
        if flag_syn: flags.append('SYN')
        if flag_ack: flags.append('ACK')
        if flag_fin: flags.append('FIN')
        if flag_rst: flags.append('RST')
        if flag_psh: flags.append('PSH')
        
        packet_info['info'] = f"[{','.join(flags)}] Seq={sequence} Ack={acknowledgement}"
        
        # Identify app protocol
        app_proto = self.identify_application_protocol(src_port, dest_port, tcp_payload)
        if app_proto != 'Unknown':
            packet_info['protocol'] = f"TCP/{app_proto}"
        
        # Decode app data
        app_data = self._decode_application_data(app_proto, tcp_payload)
        
        # Update info
        if app_data and app_data.get('type') != 'unknown':
            if app_data['type'] == 'command':
                packet_info['info'] += f" | {app_proto} {app_data.get('command', '')}"
            elif app_data['type'] == 'response':
                code = app_data.get('code', app_data.get('status_code', app_data.get('status', '')))
                packet_info['info'] += f" | {app_proto} {code}"
            elif app_data['type'] == 'request' and app_proto == 'HTTP':
                packet_info['info'] += f" | HTTP {app_data.get('method', '')} {app_data.get('uri', '')[:30]}"
        
        # Build OSI layers
        self._build_tcp_layers(packet_info, src_port, dest_port, sequence, acknowledgement, flags, src, target, tcp_payload, app_proto, app_data)
        
        return packet_info
    
    def _handle_udp(self, packet_info, ip_data, src, target):
        """Handle UDP packet"""
        packet_info['protocol'] = 'UDP'
        src_port, dest_port, size, udp_payload = self.udp_segment(ip_data)
        packet_info['src_port'] = src_port
        packet_info['dest_port'] = dest_port
        packet_info['info'] = f"Len={size}"
        
        # DNS
        dns_info = None
        if src_port == 53 or dest_port == 53:
            packet_info['protocol'] = 'DNS'
            dns_info = self.decode_dns(udp_payload)
            if dns_info:
                packet_info['info'] = f"{'Response' if dns_info['is_response'] else 'Query'}: {dns_info['domain']}"
        
        self._build_udp_layers(packet_info, src_port, dest_port, size, src, target, udp_payload, dns_info)
        
        return packet_info


# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start_sniffing():
    global sniffer_thread, sniffer_instance, is_sniffing
    
    if is_sniffing:
        return jsonify({'status': 'error', 'message': 'Sniffer đã đang chạy!'})
    
    try:
        params = request.json
        
        filter_ip = params.get('ip', '').strip() if params.get('ip') else None
        filter_domain = params.get('domain', '').strip() if params.get('domain') else None
        filter_protocol = params.get('protocol', '').strip() if params.get('protocol') else None
        
        sniffer_instance = WebPacketSniffer(
            filter_protocol=filter_protocol,
            filter_ip=filter_ip,
            filter_domain=filter_domain,
            filter_port=int(params['port']) if params.get('port') and str(params.get('port')).strip() else None,
            max_packets=int(params['max_packets']) if params.get('max_packets') and str(params.get('max_packets')).strip() else None,
            ping_reply_only=params.get('ping_reply_only', False),
            interface=params.get('interface', '').strip() if params.get('interface') else None,
            detect_security=params.get('detect_security', False)
        )
        
        is_sniffing = True
        sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
        sniffer_thread.start()
        
        info_parts = []
        if filter_protocol:
            info_parts.append(f"Protocol: {filter_protocol}")
        if filter_domain:
            info_parts.append(f"Domain: {filter_domain}")
        if filter_ip:
            info_parts.append(f"IP: {filter_ip}")
        if params.get('port'):
            info_parts.append(f"Port: {params.get('port')}")
        
        message = '🚀 Bắt đầu bắt gói tin!'
        if info_parts:
            message += ' (' + ', '.join(info_parts) + ')'
        
        return jsonify({'status': 'success', 'message': message})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'❌ Lỗi: {str(e)}'})

@app.route('/stop', methods=['POST'])
def stop_sniffing():
    global is_sniffing, sniffer_instance
    
    is_sniffing = False
    
    stats = None
    if sniffer_instance:
        stats = {
            'total': sniffer_instance.stats['total'],
            'ipv4': sniffer_instance.stats['ipv4'],
            'ipv6': sniffer_instance.stats['ipv6'],
            'tcp': sniffer_instance.stats['tcp'],
            'udp': sniffer_instance.stats['udp'],
            'icmp': sniffer_instance.stats['icmp'],
            'arp': sniffer_instance.stats['arp'],
            'other': sniffer_instance.stats['other']
        }
    
    return jsonify({'status': 'success', 'message': '⏹ Đã dừng bắt gói tin!', 'stats': stats})

@app.route('/stream')
def stream():
    def generate():
        while True:
            try:
                packet = packet_queue.get(timeout=1)
                yield f"data: {json.dumps(packet)}\n\n"
            except queue.Empty:
                yield f": heartbeat\n\n"
            except Exception as e:
                break
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/packet/<int:packet_num>', methods=['GET'])
def get_packet_details(packet_num):
    if sniffer_instance and packet_num in sniffer_instance.web_packets_details:
        packet = sniffer_instance.web_packets_details[packet_num]
        return jsonify({'status': 'success', 'packet': packet})
    else:
        return jsonify({'status': 'error', 'message': 'Packet not found'})

@app.route('/statistics', methods=['GET'])
def get_statistics():
    if sniffer_instance:
        duration = time.time() - sniffer_instance.start_time
        return jsonify({
            'stats': sniffer_instance.stats,
            'duration': duration,
            'packets_per_second': sniffer_instance.stats['total'] / max(duration, 0.001),
            'protocol_stats': dict(sniffer_instance.protocol_stats),
            'ip_conversations': dict(list(sniffer_instance.ip_conversations.items())[:10])
        })
    return jsonify({'stats': {}})

def run_sniffer():
    global is_sniffing
    try:
        import socket
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        
        if sniffer_instance.interface:
            conn.bind((sniffer_instance.interface, 0))
        
        packet_count = 0
        
        while is_sniffing:
            if sniffer_instance.max_packets and packet_count >= sniffer_instance.max_packets:
                is_sniffing = False
                break
            
            raw_data, addr = conn.recvfrom(65535)
            
            if sniffer_instance.process_packet(raw_data, packet_count + 1):
                packet_count += 1
                
    except Exception as e:
        print(f"❌ Lỗi trong sniffer thread: {e}")
        is_sniffing = False

if __name__ == '__main__':
    print("\n" + "="*80)
    print("🌐 PACKET SNIFFER WEB INTERFACE - ENHANCED VERSION".center(80))
    print("="*80)
    print("\n📌 Mở trình duyệt và truy cập: http://localhost:5000")
    print("⚠️  Lưu ý: Cần chạy với quyền root/sudo!\n")
    print("   sudo python3 d.py")
    print("\n🔍 Hỗ trợ lọc:")
    print("   • Protocol: TCP, UDP, ICMP, ARP, IPv6, FTP, SMTP, POP3, IMAP, HTTP")
    print("   • IP Address: Hỗ trợ cả IPv4 và IPv6")
    print("   • Domain: VD: google.com, facebook.com (tự động resolve IPv4 & IPv6)")
    print("   • Port: VD: 80, 443, 21, 25, 110, 143")
    print("\n✨ Tính năng mới:")
    print("   • Hỗ trợ đầy đủ IPv6 và ICMPv6")
    print("   • Phân tích HTTP requests/responses")
    print("   • Giao diện được làm mới hoàn toàn")
    print("   • Phát hiện bảo mật nâng cao")
    print("\n" + "="*80 + "\n")
    
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)