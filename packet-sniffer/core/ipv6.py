# Lưu ý: Đây là mã mô phỏng. Trong ứng dụng thực, bạn sẽ sử dụng thư viện như Scapy
# để truy cập các trường header của gói tin.

from typing import Dict, Any
from dns_resolver import DNSResolver, DNS_CACHE # Import DNS logic
import time

def parse_packet(raw_packet: bytes, packet_num: int) -> Dict[str, Any]:
    """
    Phân tích gói tin thô, hỗ trợ IPv4 và IPv6, và tích hợp phân giải DNS.
    """
    
    # === 1. Phân tích Ethernet Frame để xác định loại Network Layer ===
    # Kiểm tra EtherType (0x0800 cho IPv4, 0x86DD cho IPv6)
    # Giả sử chúng ta đã có thông tin phân tích sơ bộ:
    
    # Dữ liệu mô phỏng
    network_layer_type = "IPv4"
    src_ip = "192.168.1.100"
    dest_ip = "8.8.8.8"
    protocol = "UDP"
    port = 53
    info = "DNS Query for google.com"
    is_dns_response = False
    
    # Để kiểm tra IPv6:
    if packet_num % 10 == 0:
        network_layer_type = "IPv6"
        src_ip = "fe80::100:a123:cdef:1234"
        dest_ip = "2001:4860:4860::8888" # Google Public DNS IPv6
        protocol = "ICMPv6"
        info = "Neighbor Solicitation"

    if packet_num % 5 == 0 and network_layer_type == "IPv4":
        protocol = "DNS"
        port = 53
        info = "DNS Response - 8.8.8.8 -> google.com"
        is_dns_response = True
        
    
    # === 2. Tích hợp DNS Resolver ===
    
    # A. Phân giải IP Nguồn/Đích thành Tên miền (nếu có trong cache)
    src_domain = DNSResolver.resolve_ip(src_ip)
    dest_domain = DNSResolver.resolve_ip(dest_ip)
    
    # Sử dụng tên miền cho hiển thị Info nếu nó là giao thức L7
    if src_domain or dest_domain:
        display_src = src_domain or src_ip
        display_dest = dest_domain or dest_ip
        info = f"{protocol} {display_src} -> {display_dest} ({info})"
    
    # B. Cập nhật Cache nếu đây là DNS Response
    if protocol == 'DNS' and is_dns_response:
        # Trong thực tế, bạn sẽ lấy các bản ghi DNS từ gói tin.
        # Ở đây, chúng ta mô phỏng việc tìm thấy phân giải:
        # Ví dụ: 142.250.76.174 cho 'google.com'
        ip_to_cache = "142.250.76.174" 
        domain_to_cache = "google.com"
        DNSResolver.update_cache(ip_to_cache, domain_to_cache)
        info = f"DNS Response: Cache Updated {domain_to_cache} ({ip_to_cache})"


    # === 3. Xây dựng cấu trúc dữ liệu gói tin trả về Frontend ===
    
    packet_data = {
        'num': packet_num,
        'timestamp': time.strftime("%H:%M:%S", time.localtime()),
        'src_ip': src_ip,
        'dest_ip': dest_ip,
        # Protocol chính (L3/L4/L7)
        'protocol': f"{network_layer_type}/{protocol}", 
        'info': info,
        'length': len(raw_packet),
        'raw_data': raw_packet.hex(),
        'osi_layers': {
            'layer3': {
                'name': 'Network Layer',
                'protocol': network_layer_type, # Có thể là IPv4 hoặc IPv6
                'src_ip': src_ip,
                'dest_ip': dest_ip,
                'info': f"Giao thức: {network_layer_type}. TTL/Hop Limit: 64",
                'details': {
                    'IP Version': '4' if network_layer_type == 'IPv4' else '6',
                    'Source Address': f"{src_ip}{f' ({src_domain})' if src_domain else ''}",
                    'Destination Address': f"{dest_ip}{f' ({dest_domain})' if dest_domain else ''}",
                    'Next Header/Protocol': protocol
                }
            },
            # ... Các Layer khác (L4, L7) cũng cần kiểm tra protocol để phân tích đúng
        }
    }
    
    return packet_data

# Ví dụ về cách kiểm tra DNS Cache sau khi parsing (giả lập)
print("\n--- Kiểm tra DNS Cache ---")
# Giả lập gói tin DNS response
parse_packet(b'\x00'*100, 5) 

# Giả lập gói tin ICMP (Ping)
packet_ping = parse_packet(b'\x00'*100, 6)
print(f"\nGói tin Ping (Num 6):")
print(f"  Source IP: {packet_ping['src_ip']}")
print(f"  Destination IP: {packet_ping['dest_ip']}")
print(f"  Info: {packet_ping['info']}")

# Giả lập gói tin IPv6
packet_v6 = parse_packet(b'\x00'*100, 10)
print(f"\nGói tin IPv6 (Num 10):")
print(f"  Source IP: {packet_v6['src_ip']}")
print(f"  Protocol: {packet_v6['protocol']}")
print(f"  L3 Details (Version): {packet_v6['osi_layers']['layer3']['details']['IP Version']}")
print("\n--- Kết thúc Mô phỏng ---")