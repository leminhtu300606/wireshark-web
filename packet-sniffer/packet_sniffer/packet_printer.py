"""
packet_printer.py
Module in thông tin gói tin theo format OSI 7 layers
"""

from datetime import datetime
from network_utils import NetworkUtils


class PacketPrinter:
    """In thông tin gói tin chi tiết"""
    
    @staticmethod
    def print_osi_packet(num, dest_mac, src_mac, version, header_length, ttl,
                        src_ip, target_ip, proto, raw_size, **kwargs):
        """In thông tin gói tin theo OSI 7 layers"""
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        
        src_display = NetworkUtils.get_hostname_display(src_ip)
        target_display = NetworkUtils.get_hostname_display(target_ip)
        
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
        PacketPrinter._print_layer4(proto, src_ip, target_ip, **kwargs)
        
        # LAYER 5: SESSION
        PacketPrinter._print_layer5(proto, **kwargs)
        
        # LAYER 6: PRESENTATION
        PacketPrinter._print_layer6(**kwargs)
        
        # LAYER 7: APPLICATION
        PacketPrinter._print_layer7(proto, **kwargs)
        
        print(f"│")
        print(f"└─ KẾT THÚC PACKET #{num}")
        print(f"{'='*100}")
    
    @staticmethod
    def _print_layer4(proto, src_ip, target_ip, **kwargs):
        """In thông tin Layer 4: Transport"""
        print(f"│")
        print(f"┌─ LAYER 4: TRANSPORT LAYER (Tầng Giao Vận)")
        print(f"│  Giao thức: {proto}")
        
        if proto == 'TCP':
            PacketPrinter._print_tcp_info(src_ip, target_ip, **kwargs)
        elif proto == 'UDP':
            PacketPrinter._print_udp_info(src_ip, target_ip, **kwargs)
        elif proto == 'ICMP':
            PacketPrinter._print_icmp_info(src_ip, target_ip, **kwargs)
    
    @staticmethod
    def _print_tcp_info(src_ip, target_ip, **kwargs):
        """In thông tin TCP"""
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
    
    @staticmethod
    def _print_udp_info(src_ip, target_ip, **kwargs):
        """In thông tin UDP"""
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
    
    @staticmethod
    def _print_icmp_info(src_ip, target_ip, **kwargs):
        """In thông tin ICMP"""
        icmp_type = kwargs.get('icmp_type')
        code = kwargs.get('code')
        check_sum = kwargs.get('check_sum')
        
        print(f"│  ├─ Loại (Type): {icmp_type} ({NetworkUtils.get_icmp_type_name(icmp_type)})")
        print(f"│  ├─ Mã (Code): {code}")
        print(f"│  ├─ Checksum: {check_sum}")
        print(f"│  └─ Hướng: {src_ip} → {target_ip}")
        
        if icmp_type == 8:
            print(f"│     Info: Yêu cầu Ping (Echo Request)")
        elif icmp_type == 0:
            print(f"│     Info: Trả lời Ping (Echo Reply) ✓")
    
    @staticmethod
    def _print_layer5(proto, **kwargs):
        """In thông tin Layer 5: Session"""
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
    
    @staticmethod
    def _print_layer6(**kwargs):
        """In thông tin Layer 6: Presentation"""
        print(f"│")
        print(f"┌─ LAYER 6: PRESENTATION LAYER (Tầng Trình Diễn)")
        payload = kwargs.get('payload', b'')
        
        if payload:
            if NetworkUtils.is_encrypted(payload):
                print(f"│  ├─ Định dạng dữ liệu: Đã mã hóa/Nhị phân")
                print(f"│  ├─ Mã hóa: Có thể là TLS/SSL")
            elif NetworkUtils.is_text(payload):
                print(f"│  ├─ Định dạng dữ liệu: Văn bản thuần")
                print(f"│  ├─ Mã hóa: ASCII/UTF-8")
            else:
                print(f"│  ├─ Định dạng dữ liệu: Nhị phân")
                print(f"│  ├─ Mã hóa: Dữ liệu nhị phân thô")
            print(f"│  └─ Kích thước dữ liệu: {len(payload)} bytes")
        else:
            print(f"│  └─ Không có dữ liệu payload")
    
    @staticmethod
    def _print_layer7(proto, **kwargs):
        """In thông tin Layer 7: Application"""
        print(f"│")
        print(f"┌─ LAYER 7: APPLICATION LAYER (Tầng Ứng Dụng)")
        app_proto = kwargs.get('app_proto', 'Unknown')
        app_data = kwargs.get('app_data')
        
        if proto in ['TCP', 'UDP']:
            src_port = kwargs.get('src_port')
            dest_port = kwargs.get('dest_port')
            print(f"│  ├─ Giao thức ứng dụng: {app_proto}")
            print(f"│  ├─ Dịch vụ: {NetworkUtils.get_service_name(src_port, dest_port)}")
            
            # Display protocol-specific data
            if app_data:
                PacketPrinter._print_app_protocol_data(app_proto, app_data)
            
            payload = kwargs.get('payload', b'')
            if payload and not app_data and app_proto != 'Unknown':
                PacketPrinter._print_payload_preview(payload)
        
        elif proto == 'ICMP':
            print(f"│  ├─ Ứng dụng: ICMP (Chẩn đoán mạng)")
            print(f"│  ├─ Công cụ: ping/traceroute")
            print(f"│  └─ Mục đích: Kiểm tra kết nối mạng")
    
    @staticmethod
    def _print_app_protocol_data(app_proto, app_data):
        """In dữ liệu giao thức ứng dụng"""
        print(f"│  │")
        
        if app_proto == 'FTP':
            print(f"│  │  📁 FTP Protocol:")
            PacketPrinter._print_ftp_data(app_data)
        elif app_proto == 'SMTP':
            print(f"│  │  📧 SMTP Protocol:")
            PacketPrinter._print_smtp_data(app_data)
        elif app_proto == 'POP3':
            print(f"│  │  📬 POP3 Protocol:")
            PacketPrinter._print_pop3_data(app_data)
        elif app_proto == 'IMAP':
            print(f"│  │  📮 IMAP Protocol:")
            PacketPrinter._print_imap_data(app_data)
    
    @staticmethod
    def _print_ftp_data(data):
        """In dữ liệu FTP"""
        if data['type'] == 'command':
            print(f"│  │  ├─ Type: Command")
            print(f"│  │  ├─ Command: {data['command']}")
            print(f"│  │  └─ Full: {data['full']}")
            if 'filename' in data:
                print(f"│  │  └─ Filename: {data['filename']}")
        elif data['type'] == 'response':
            print(f"│  │  ├─ Type: Response")
            print(f"│  │  ├─ Code: {data['code']}")
            print(f"│  │  ├─ Status: {data.get('status', 'unknown')}")
            print(f"│  │  └─ Message: {data['message']}")
    
    @staticmethod
    def _print_smtp_data(data):
        """In dữ liệu SMTP"""
        if data['type'] == 'command':
            print(f"│  │  ├─ Type: Command")
            print(f"│  │  ├─ Command: {data['command']}")
            print(f"│  │  └─ Full: {data['full']}")
            if 'email' in data:
                print(f"│  │  └─ Email: {data['email']}")
        elif data['type'] == 'response':
            print(f"│  │  ├─ Type: Response")
            print(f"│  │  ├─ Code: {data['code']}")
            print(f"│  │  ├─ Status: {data.get('status', 'unknown')}")
            print(f"│  │  └─ Message: {data['message']}")
    
    @staticmethod
    def _print_pop3_data(data):
        """In dữ liệu POP3"""
        if data['type'] == 'command':
            print(f"│  │  ├─ Type: Command")
            print(f"│  │  ├─ Command: {data['command']}")
            print(f"│  │  └─ Full: {data['full']}")
            if 'message_id' in data:
                print(f"│  │  └─ Message ID: {data['message_id']}")
        elif data['type'] == 'response':
            print(f"│  │  ├─ Type: Response")
            print(f"│  │  ├─ Status: {data['status']}")
            print(f"│  │  ├─ Success: {data.get('success', False)}")
            print(f"│  │  └─ Message: {data['message']}")
    
    @staticmethod
    def _print_imap_data(data):
        """In dữ liệu IMAP"""
        if data['type'] == 'command':
            print(f"│  │  ├─ Type: Command")
            print(f"│  │  ├─ Tag: {data['tag']}")
            print(f"│  │  ├─ Command: {data['command']}")
            print(f"│  │  └─ Full: {data['full']}")
        elif data['type'] == 'response':
            print(f"│  │  ├─ Type: Response")
            if 'tag' in data:
                print(f"│  │  ├─ Tag: {data['tag']}")
            if 'status' in data:
                print(f"│  │  ├─ Status: {data['status']}")
            print(f"│  │  └─ Message: {data['message']}")
    
    @staticmethod
    def _print_payload_preview(payload):
        """In preview của payload"""
        print(f"│  └─ Payload: {len(payload)} bytes")
        if len(payload) > 0 and NetworkUtils.is_text(payload):
            preview = payload[:100].decode('utf-8', errors='ignore')
            print(f"│     Xem trước: {preview[:50]}...")
    
    @staticmethod
    def print_arp_packet(num, dest_mac, src_mac, arp_info, raw_size):
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
    
    @staticmethod
    def print_ipv6_packet(num, dest_mac, src_mac, ipv6_info, raw_size):
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