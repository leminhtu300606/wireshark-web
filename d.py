from flask import Flask, render_template, request, jsonify, Response
from flask_cors import CORS
import threading
import queue
import json
import time
from datetime import datetime
import sys
import os

# Import PacketSniffer từ file a.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a import PacketSniffer

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
        self.web_packets_details = {}  # Lưu chi tiết packet
        self.web_packet_counter = 0  # Counter riêng cho web
    
    def process_packet(self, raw_data, packet_num, offline=False):
        """Override để capture packet info - FIXED để hiển thị đúng trên web"""
        # Tạo packet summary TRƯỚC KHI lọc
        packet_info = self.create_packet_summary(raw_data, packet_num)
        
        # Gọi parent process để áp dụng filters
        result = super().process_packet(raw_data, packet_num, offline)
        
        # NẾU packet pass qua filter, gửi lên web
        if result and packet_info:
            self.web_packet_counter += 1
            # Update packet number cho web display
            packet_info['num'] = self.web_packet_counter
            
            self.web_packets.append(packet_info)
            # Lưu chi tiết packet theo số thứ tự web
            self.web_packets_details[self.web_packet_counter] = packet_info
            packet_queue.put(packet_info)
        
        return result
    
    def create_packet_summary(self, raw_data, packet_num):
        """Tạo summary của packet để hiển thị trên web - FIXED & ENHANCED"""
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
                packet_info['protocol'] = 'ARP'
                arp_info = self.arp_packet(data)
                if arp_info:
                    packet_info['src_ip'] = arp_info['src_ip']
                    packet_info['dest_ip'] = arp_info['dest_ip']
                    packet_info['info'] = f"{'Request' if arp_info['opcode'] == 1 else 'Reply'}"
                    
                    # OSI Layers for ARP
                    packet_info['osi_layers'] = {
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
            
            # IPv4
            elif eth_proto == 8:
                version, header_length, ttl, proto, src, target, ip_data = self.ipv4_packet(data)
                packet_info['src_ip'] = src
                packet_info['dest_ip'] = target
                
                # Base OSI layers for IPv4
                packet_info['osi_layers'] = {
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
                
                # ICMP
                if proto == 1:
                    packet_info['protocol'] = 'ICMP'
                    icmp_type, code, check_sum, icmp_data = self.icmp_packet(ip_data)
                    packet_info['info'] = self.get_icmp_type_name(icmp_type)
                    
                    packet_info['osi_layers']['layer4'] = {
                        'name': 'Transport Layer',
                        'protocol': 'ICMP',
                        'details': {
                            'Type': f"{icmp_type} ({self.get_icmp_type_name(icmp_type)})",
                            'Code': str(code),
                            'Checksum': str(check_sum)
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
                
                # TCP
                elif proto == 6:
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
                    
                    # Identify application protocol
                    app_proto = self.identify_application_protocol(src_port, dest_port, tcp_payload)
                    if app_proto != 'Unknown':
                        packet_info['protocol'] = f"TCP/{app_proto}"
                    
                    # Decode application data - ENHANCED
                    app_data = None
                    if app_proto == 'FTP' and tcp_payload:
                        app_data = self.decode_ftp(tcp_payload)
                    elif app_proto == 'SMTP' and tcp_payload:
                        app_data = self.decode_smtp(tcp_payload)
                    elif app_proto == 'POP3' and tcp_payload:
                        app_data = self.decode_pop3(tcp_payload)
                    elif app_proto == 'IMAP' and tcp_payload:
                        app_data = self.decode_imap(tcp_payload)
                    
                    # Update info if we decoded app data
                    if app_data and app_data['type'] != 'unknown':
                        if app_data['type'] == 'command':
                            packet_info['info'] += f" | {app_proto} {app_data['command']}"
                        elif app_data['type'] == 'response':
                            code = app_data.get('code', app_data.get('status', ''))
                            packet_info['info'] += f" | {app_proto} {code}"
                    
                    packet_info['osi_layers']['layer4'] = {
                        'name': 'Transport Layer',
                        'protocol': 'TCP',
                        'details': {
                            'Source Port': str(src_port),
                            'Destination Port': str(dest_port),
                            'Sequence Number': str(sequence),
                            'Acknowledgement': str(acknowledgement),
                            'Flags': ', '.join(flags) if flags else 'None',
                            'Connection': f"{src}:{src_port} ⟷ {target}:{dest_port}"
                        }
                    }
                    
                    # Session layer
                    session_info = 'Phiên đang hoạt động'
                    if flag_syn:
                        session_info = 'Đang thiết lập phiên mới'
                    elif flag_fin:
                        session_info = 'Đang đóng phiên'
                    elif flag_rst:
                        session_info = 'Đang kết thúc phiên'
                    
                    packet_info['osi_layers']['layer5'] = {
                        'name': 'Session Layer',
                        'info': session_info
                    }
                    
                    # Presentation layer
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
                    
                    # Application layer - ENHANCED
                    app_layer = {
                        'name': 'Application Layer',
                        'protocol': app_proto,
                        'info': self.get_service_name(src_port, dest_port)
                    }
                    
                    # Add protocol specific details
                    if app_data and app_data['type'] != 'unknown':
                        if app_proto == 'FTP':
                            app_layer['ftp'] = app_data
                        elif app_proto == 'SMTP':
                            app_layer['smtp'] = app_data
                        elif app_proto == 'POP3':
                            app_layer['pop3'] = app_data
                        elif app_proto == 'IMAP':
                            app_layer['imap'] = app_data
                    
                    if tcp_payload and self.is_text(tcp_payload) and not app_data:
                        preview = tcp_payload[:100].decode('utf-8', errors='ignore')
                        app_layer['preview'] = preview[:50] + ('...' if len(preview) > 50 else '')
                    
                    packet_info['osi_layers']['layer7'] = app_layer
                
                # UDP
                elif proto == 17:
                    packet_info['protocol'] = 'UDP'
                    src_port, dest_port, size, udp_payload = self.udp_segment(ip_data)
                    packet_info['src_port'] = src_port
                    packet_info['dest_port'] = dest_port
                    packet_info['info'] = f"Len={size}"
                    
                    # DNS
                    dns_info = None
                    app_proto = self.identify_application_protocol(src_port, dest_port, udp_payload)
                    if src_port == 53 or dest_port == 53:
                        packet_info['protocol'] = 'DNS'
                        dns_info = self.decode_dns(udp_payload)
                        if dns_info:
                            packet_info['info'] = f"{'Response' if dns_info['is_response'] else 'Query'}: {dns_info['domain']}"
                    
                    packet_info['osi_layers']['layer4'] = {
                        'name': 'Transport Layer',
                        'protocol': 'UDP',
                        'details': {
                            'Source Port': str(src_port),
                            'Destination Port': str(dest_port),
                            'Length': f'{size} bytes',
                            'Connection': f"{src}:{src_port} → {target}:{dest_port} (Connectionless)"
                        }
                    }
                    
                    packet_info['osi_layers']['layer5'] = {
                        'name': 'Session Layer',
                        'info': 'Không trạng thái (không quản lý phiên)'
                    }
                    
                    if udp_payload:
                        pres_info = f'Dữ liệu UDP, {len(udp_payload)} bytes'
                    else:
                        pres_info = 'Không có payload'
                    
                    packet_info['osi_layers']['layer6'] = {
                        'name': 'Presentation Layer',
                        'info': pres_info
                    }
                    
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
                            'Answers': str(dns_info['answers'])
                        }
                    
                    packet_info['osi_layers']['layer7'] = app_layer
            
            # IPv6
            elif eth_proto == 0x86DD:
                packet_info['protocol'] = 'IPv6'
                ipv6_info = self.ipv6_packet(data)
                if ipv6_info:
                    packet_info['src_ip'] = ipv6_info['src']
                    packet_info['dest_ip'] = ipv6_info['dest']
                    
                    packet_info['osi_layers'] = {
                        'layer1': {
                            'name': 'Physical Layer',
                            'info': f"Kích thước: {len(raw_data)} bytes"
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
                                'Payload Length': f"{ipv6_info['payload_length']} bytes"
                            }
                        }
                    }
            
            return packet_info
            
        except Exception as e:
            print(f"Error in create_packet_summary: {e}")
            return None

@app.route('/')
def index():
    """Serve giao diện chính"""
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start_sniffing():
    """Bắt đầu bắt gói tin - FIXED"""
    global sniffer_thread, sniffer_instance, is_sniffing
    
    if is_sniffing:
        return jsonify({'status': 'error', 'message': 'Sniffer đã đang chạy!'})
    
    try:
        params = request.json
        
        # Clean up parameters - FIXED
        filter_ip = params.get('ip', '').strip() if params.get('ip') else None
        filter_domain = params.get('domain', '').strip() if params.get('domain') else None
        filter_protocol = params.get('protocol', '').strip() if params.get('protocol') else None
        
        # Tạo sniffer instance mới
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
        
        # Chạy trong thread riêng
        is_sniffing = True
        sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
        sniffer_thread.start()
        
        # Build info message
        info_parts = []
        if filter_protocol:
            info_parts.append(f"Protocol: {filter_protocol}")
        if filter_domain:
            info_parts.append(f"Domain: {filter_domain}")
        if filter_ip:
            info_parts.append(f"IP: {filter_ip}")
        if params.get('port'):
            info_parts.append(f"Port: {params.get('port')}")
        
        message = 'Bắt đầu bắt gói tin!'
        if info_parts:
            message += ' (' + ', '.join(info_parts) + ')'
        
        return jsonify({'status': 'success', 'message': message})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Lỗi: {str(e)}'})

@app.route('/stop', methods=['POST'])
def stop_sniffing():
    """Dừng bắt gói tin"""
    global is_sniffing, sniffer_instance
    
    is_sniffing = False
    
    # Lấy thống kê trước khi dừng
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
    
    return jsonify({'status': 'success', 'message': 'Đã dừng bắt gói tin!', 'stats': stats})

@app.route('/stream')
def stream():
    """Stream packets real-time qua Server-Sent Events"""
    def generate():
        while True:
            try:
                # Lấy packet từ queue với timeout
                packet = packet_queue.get(timeout=1)
                yield f"data: {json.dumps(packet)}\n\n"
            except queue.Empty:
                # Gửi heartbeat để giữ kết nối
                yield f": heartbeat\n\n"
            except Exception as e:
                break
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/packet/<int:packet_num>', methods=['GET'])
def get_packet_details(packet_num):
    """Lấy chi tiết packet theo số thứ tự"""
    if sniffer_instance and packet_num in sniffer_instance.web_packets_details:
        packet = sniffer_instance.web_packets_details[packet_num]
        return jsonify({'status': 'success', 'packet': packet})
    else:
        return jsonify({'status': 'error', 'message': 'Packet not found'})

@app.route('/statistics', methods=['GET'])
def get_statistics():
    """Lấy thống kê"""
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
    """Chạy sniffer trong thread riêng"""
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
        print(f"Lỗi trong sniffer thread: {e}")
        is_sniffing = False

if __name__ == '__main__':
    print("\n" + "="*80)
    print("🌐 PACKET SNIFFER WEB INTERFACE".center(80))
    print("="*80)
    print("\n📌 Mở trình duyệt và truy cập: http://localhost:5000")
    print("⚠️  Lưu ý: Cần chạy với quyền root/sudo!\n")
    print("   sudo python3 d.py")
    print("\n🔍 Hỗ trợ lọc:")
    print("   • Protocol: TCP, UDP, ICMP, ARP, IPv6, FTP, SMTP, POP3, IMAP")
    print("   • IP Address: VD: 8.8.8.8")
    print("   • Domain: VD: google.com, facebook.com")
    print("   • Port: VD: 80, 443, 21, 25, 110, 143")
    print("\n" + "="*80 + "\n")
    
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)