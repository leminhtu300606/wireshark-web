import time
from typing import Dict, Optional

# Bộ nhớ đệm DNS toàn cục (Global DNS Cache)
# Key: Địa chỉ IP (chuỗi)
# Value: { 'domain': tên miền (chuỗi), 'expiry': thời gian hết hạn (timestamp) }
DNS_CACHE: Dict[str, Dict] = {}
CACHE_TTL_SECONDS = 300 # Thời gian tồn tại của cache: 5 phút

class DNSResolver:
    """
    Quản lý bộ nhớ đệm (cache) IP <-> Domain được lấy từ gói tin DNS.
    """

    @staticmethod
    def resolve_ip(ip_address: str) -> Optional[str]:
        """
        Tìm tên miền từ bộ nhớ đệm dựa trên IP.
        """
        if ip_address in DNS_CACHE:
            entry = DNS_CACHE[ip_address]
            # Kiểm tra thời gian hết hạn
            if entry['expiry'] > time.time():
                return entry['domain']
            else:
                # Xóa mục đã hết hạn
                del DNS_CACHE[ip_address]
        return None

    @staticmethod
    def update_cache(ip_address: str, domain_name: str):
        """
        Cập nhật bộ nhớ đệm với cặp IP và Domain mới.
        """
        if ip_address and domain_name:
            DNS_CACHE[ip_address] = {
                'domain': domain_name,
                'expiry': time.time() + CACHE_TTL_SECONDS
            }
            # Cập nhật ngược lại (Domain -> IP) để xử lý ping domain
            # Cần cẩn thận với trường hợp 1 domain có nhiều IP
            # Đối với sniffer, IP -> Domain là ưu tiên chính.
            # print(f"DNS Cache updated: {ip_address} -> {domain_name}")

    @staticmethod
    def is_dns_query_response(packet) -> Optional[tuple]:
        """
        Kiểm tra xem gói tin có phải là DNS response (phản hồi) không.
        (Mô phỏng logic kiểm tra lớp L7/UDP/53 trong Scapy)
        """
        # Đây là logic mô phỏng, trong Scapy bạn sẽ kiểm tra 'packet[DNS].qr == 1'
        if packet.get('protocol') == 'DNS' and packet.get('is_response'):
            # Ví dụ: Giả định gói tin có chứa thông tin phân giải
            # Trong thực tế, bạn sẽ duyệt qua phần AN (Answer) của DNS layer
            # và trả về các cặp (IP, Domain) được tìm thấy.
            # Giả sử chúng ta tìm thấy:
            
            # Mô phỏng: lấy IP và Domain từ gói tin (ví dụ: DNS layer)
            resolved_ip = packet.get('resolved_ip', '192.168.1.100')
            resolved_domain = packet.get('resolved_domain', 'example.com')
            
            return (resolved_ip, resolved_domain)
            
        return None

# Khởi tạo cache khi module được load
print("DNS Resolver Initialized.")