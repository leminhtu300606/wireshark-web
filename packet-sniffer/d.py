"""
Flask Web Application for Packet Sniffer
FIXED VERSION - Enhanced IPv6 & Domain Resolution Support
"""
from flask import Flask, render_template, request, jsonify, Response
from flask_cors import CORS
import threading
import queue
import json
import time
import sys
import os

# Import our web packet handler
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from web_packet_handler import WebPacketSniffer
from core.utils import validate_filter_inputs, resolve_domain

app = Flask(__name__)
CORS(app)

# Global variables
packet_queue = queue.Queue()
sniffer_thread = None
sniffer_instance = None
is_sniffing = False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start_sniffing():
    global sniffer_thread, sniffer_instance, is_sniffing
    
    if is_sniffing:
        return jsonify({'status': 'error', 'message': '⚠️ Sniffer đã đang chạy!'})
    
    try:
        params = request.json
        
        # Get and clean filter parameters
        filter_ip = params.get('ip', '').strip() if params.get('ip') else None
        filter_domain = params.get('domain', '').strip() if params.get('domain') else None
        filter_protocol = params.get('protocol', '').strip().upper() if params.get('protocol') else None
        filter_port = int(params['port']) if params.get('port') and str(params.get('port')).strip() else None
        max_packets = int(params['max_packets']) if params.get('max_packets') and str(params.get('max_packets')).strip() else None
        interface = params.get('interface', '').strip() if params.get('interface') else None
        ping_reply_only = params.get('ping_reply_only', False)
        detect_security = params.get('detect_security', False)
        
        # Validate inputs
        valid, error_msg, normalized = validate_filter_inputs(
            filter_protocol=filter_protocol,
            filter_ip=filter_ip,
            filter_domain=filter_domain,
            filter_port=filter_port
        )
        
        if not valid:
            return jsonify({'status': 'error', 'message': f'❌ Lỗi validate: {error_msg}'})
        
        # Use normalized values
        if normalized:
            filter_protocol = normalized['protocol']
            filter_ip = normalized['ip']
            filter_domain = normalized['domain']
            filter_port = normalized['port']
        
        print(f"\n{'='*80}")
        print(f"🚀 STARTING PACKET SNIFFER")
        print(f"{'='*80}")
        print(f"[FILTERS]")
        print(f"  • Protocol: {filter_protocol or 'All'}")
        print(f"  • IP Address: {filter_ip or 'All'}")
        print(f"  • Domain: {filter_domain or 'None'}")
        print(f"  • Port: {filter_port or 'All'}")
        print(f"  • Max Packets: {max_packets or 'Unlimited'}")
        print(f"  • Interface: {interface or 'All interfaces'}")
        print(f"  • Ping Reply Only: {ping_reply_only}")
        print(f"  • Security Detection: {detect_security}")
        
        # Pre-resolve domain if specified
        resolved_ips = []
        if filter_domain:
            print(f"\n[INFO] Resolving domain '{filter_domain}'...")
            resolved_ips = resolve_domain(filter_domain)
            if resolved_ips:
                print(f"[INFO] ✅ Resolved to {len(resolved_ips)} IP(s):")
                for ip in resolved_ips:
                    print(f"       • {ip}")
            else:
                print(f"[WARNING] ⚠️ Could not resolve domain '{filter_domain}'")
                return jsonify({
                    'status': 'warning',
                    'message': f'⚠️ Không thể phân giải domain "{filter_domain}". Kiểm tra lại tên miền!'
                })
        
        print(f"{'='*80}\n")
        
        # Create sniffer instance
        sniffer_instance = WebPacketSniffer(
            filter_protocol=filter_protocol,
            filter_ip=filter_ip,
            filter_domain=filter_domain,
            filter_port=filter_port,
            max_packets=max_packets,
            ping_reply_only=ping_reply_only,
            interface=interface,
            detect_security=detect_security
        )
        
        # Start sniffing thread
        is_sniffing = True
        sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
        sniffer_thread.start()
        
        # Build info message
        info_parts = []
        if filter_protocol:
            info_parts.append(f"Protocol: {filter_protocol}")
        if filter_domain:
            ip_count = len(resolved_ips) if resolved_ips else 0
            info_parts.append(f"Domain: {filter_domain} ({ip_count} IPs)")
        if filter_ip:
            info_parts.append(f"IP: {filter_ip}")
        if filter_port:
            info_parts.append(f"Port: {filter_port}")
        
        message = '🚀 Đã bắt đầu bắt gói tin!'
        if info_parts:
            message += ' (' + ', '.join(info_parts) + ')'
        
        return jsonify({'status': 'success', 'message': message})
        
    except Exception as e:
        print(f"\n❌ [ERROR] Failed to start sniffer: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': f'❌ Lỗi: {str(e)}'})

@app.route('/stop', methods=['POST'])
def stop_sniffing():
    global is_sniffing, sniffer_instance
    
    print(f"\n[INFO] Stopping packet sniffer...")
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
        print(f"[INFO] Final statistics: {stats}")
    
    print(f"[INFO] ✅ Packet sniffer stopped\n")
    
    return jsonify({'status': 'success', 'message': '⏹ Đã dừng bắt gói tin!', 'stats': stats})

@app.route('/stream')
def stream():
    """SSE stream for real-time packet updates"""
    def generate():
        last_heartbeat = time.time()
        while True:
            try:
                # Send packet if available
                packet = packet_queue.get(timeout=0.5)
                yield f"data: {json.dumps(packet)}\n\n"
            except queue.Empty:
                # Send heartbeat every 15 seconds
                now = time.time()
                if now - last_heartbeat > 15:
                    yield f": heartbeat\n\n"
                    last_heartbeat = now
            except Exception as e:
                print(f"[ERROR] Stream error: {e}")
                break
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/packet/<int:packet_num>', methods=['GET'])
def get_packet_details(packet_num):
    """Get detailed information about a specific packet"""
    if sniffer_instance and packet_num in sniffer_instance.web_packets_details:
        packet = sniffer_instance.web_packets_details[packet_num]
        return jsonify({'status': 'success', 'packet': packet})
    else:
        return jsonify({'status': 'error', 'message': 'Packet not found'})

@app.route('/statistics', methods=['GET'])
def get_statistics():
    """Get current statistics"""
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

@app.route('/interfaces', methods=['GET'])
def get_interfaces():
    """Get available network interfaces"""
    try:
        import netifaces
        interfaces = []
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            info = {'name': iface, 'addresses': []}
            
            # Get IPv4 addresses
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    info['addresses'].append({
                        'type': 'IPv4',
                        'address': addr.get('addr')
                    })
            
            # Get IPv6 addresses
            if netifaces.AF_INET6 in addrs:
                for addr in addrs[netifaces.AF_INET6]:
                    info['addresses'].append({
                        'type': 'IPv6',
                        'address': addr.get('addr')
                    })
            
            interfaces.append(info)
        
        return jsonify({'status': 'success', 'interfaces': interfaces})
    except ImportError:
        return jsonify({
            'status': 'error',
            'message': 'netifaces not installed. Run: pip install netifaces'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def run_sniffer():
    """Main sniffer thread - captures packets"""
    global is_sniffing
    
    try:
        import socket
        
        print("[INFO] Creating raw socket...")
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        
        if sniffer_instance.interface:
            print(f"[INFO] Binding to interface: {sniffer_instance.interface}")
            try:
                conn.bind((sniffer_instance.interface, 0))
            except OSError as e:
                print(f"[ERROR] Cannot bind to interface '{sniffer_instance.interface}': {e}")
                print(f"[INFO] Falling back to all interfaces")
        else:
            print("[INFO] Listening on all interfaces")
        
        packet_count = 0
        filtered_count = 0
        
        print("[INFO] ✅ Packet capture started!")
        print("[INFO] Press Ctrl+C or click Stop button to stop...\n")
        
        while is_sniffing:
            try:
                # Check max packets limit
                if sniffer_instance.max_packets and filtered_count >= sniffer_instance.max_packets:
                    print(f"\n[INFO] ✅ Reached max packets limit: {sniffer_instance.max_packets}")
                    is_sniffing = False
                    break
                
                # Receive packet
                raw_data, addr = conn.recvfrom(65535)
                packet_count += 1
                
                # Process packet
                packet_info = sniffer_instance.process_packet(raw_data, filtered_count + 1)
                
                # If packet passed filters, send to web
                if packet_info:
                    packet_queue.put(packet_info)
                    filtered_count += 1
                    
                    # Log every 10 filtered packets
                    if filtered_count % 10 == 0:
                        print(f"[INFO] Captured: {filtered_count} packets (filtered) / {packet_count} total")
            
            except Exception as e:
                if is_sniffing:  # Only log if not intentionally stopped
                    print(f"[WARNING] Packet processing error: {e}")
                continue
        
        conn.close()
        print(f"\n{'='*80}")
        print(f"[INFO] ✅ Sniffer stopped")
        print(f"[INFO] Total packets seen: {packet_count}")
        print(f"[INFO] Packets captured (filtered): {filtered_count}")
        print(f"{'='*80}\n")
                
    except PermissionError:
        print("\n" + "="*80)
        print("❌ [ERROR] PERMISSION DENIED!")
        print("="*80)
        print("You need root/sudo privileges to capture packets.")
        print("\nRun with:")
        print("  sudo python3 app.py")
        print("="*80 + "\n")
        is_sniffing = False
        
    except Exception as e:
        print(f"\n❌ [ERROR] Sniffer thread crashed: {e}")
        import traceback
        traceback.print_exc()
        is_sniffing = False

if __name__ == '__main__':
    print("\n" + "="*80)
    print("🌐 PACKET SNIFFER WEB INTERFACE - ENHANCED VERSION v2.0.1".center(80))
    print("="*80)
    
    print("\n📌 CÁCH SỬ DỤNG:")
    print("   1. Mở trình duyệt và truy cập: http://localhost:5000")
    print("   2. Chọn bộ lọc (Protocol, IP, Domain, Port)")
    print("   3. Click 'Start Capture' để bắt đầu")
    print("   4. Click vào packet để xem chi tiết 7 tầng OSI")
    
    print("\n⚠️  LƯU Ý QUAN TRỌNG:")
    print("   • Phải chạy với quyền root/sudo:")
    print("     sudo python3 app.py")
    print("   • Trên Windows: Chạy CMD/PowerShell as Administrator")
    
    print("\n🔍 BỘ LỌC HỖ TRỢ:")
    print("   • Protocol: TCP, UDP, ICMP, ICMPv6, IPv6, ARP, HTTP, HTTPS, FTP, SMTP, POP3, IMAP, DNS")
    print("   • IP Address: Hỗ trợ cả IPv4 (8.8.8.8) và IPv6 (2001:4860:4860::8888)")
    print("   • Domain: Tự động resolve cả IPv4 & IPv6 (VD: google.com, facebook.com)")
    print("   • Port: 1-65535 (VD: 80, 443, 21, 25, 110, 143)")
    
    print("\n✨ TÍNH NĂNG MỚI v2.0.1:")
    print("   ✅ Fixed domain resolution (hỗ trợ đầy đủ IPv6)")
    print("   ✅ Enhanced IPv6 packet parsing")
    print("   ✅ ICMPv6 ping support (Echo Request/Reply)")
    print("   ✅ Auto-cleanup IPv6 zone IDs (fe80::1%eth0 → fe80::1)")
    print("   ✅ Better input validation")
    print("   ✅ Improved error handling & logging")
    print("   ✅ Real-time statistics")
    
    print("\n📊 VÍ DỤ SỬ DỤNG:")
    print("   • Bắt tất cả traffic từ Google:")
    print("     Domain: google.com")
    print("   • Bắt HTTPS traffic:")
    print("     Protocol: HTTPS (hoặc TCP + Port: 443)")
    print("   • Bắt IPv6 ping:")
    print("     Protocol: ICMPv6, Ping Reply Only: Yes")
    print("   • Bắt DNS queries:")
    print("     Protocol: DNS (hoặc UDP + Port: 53)")
    
    print("\n" + "="*80 + "\n")
    
    # Check if running with sudo
    import os
    if os.geteuid() != 0:
        print("⚠️  WARNING: Not running with root privileges!")
        print("   Packet capture will fail. Please run with sudo.\n")
    
    # Start Flask app
    try:
        app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
    except KeyboardInterrupt:
        print("\n\n[INFO] Shutting down gracefully...")
        is_sniffing = False
    except Exception as e:
        print(f"\n❌ [ERROR] Application crashed: {e}")
        import traceback
        traceback.print_exc()