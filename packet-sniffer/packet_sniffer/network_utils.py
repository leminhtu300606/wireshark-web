"""
network_utils.py
Module chứa các tiện ích hỗ trợ (DNS lookup, Protocol mapping, Data analysis)
"""

import socket


class NetworkUtils:
    """Các tiện ích mạng"""
    
    # DNS cache để tránh tra cứu lặp lại
    dns_cache = {}
    
    @staticmethod
    def resolve_domain(domain):
        """
        Phân giải tên miền thành danh sách IP
        
        Args:
            domain: Tên miền cần phân giải
        
        Returns:
            list: Danh sách các địa chỉ IP
        """
        try:
            # Loại bỏ http://, https://, www.
            domain = domain.replace('http://', '').replace('https://', '')
            domain = domain.replace('www.', '')
            domain = domain.split('/')[0]
            
            result = socket.getaddrinfo(domain, None)
            # Lấy cả IPv4 và IPv6
            ips = list(set([addr[4][0] for addr in result]))
            return ips
        except socket.gaierror as e:
            print(f"[WARNING] Không thể phân giải domain: {domain} - {e}")
            return []
    
    @staticmethod
    def reverse_dns_lookup(ip):
        """
        Tra cứu ngược IP thành hostname
        
        Args:
            ip: Địa chỉ IP
        
        Returns:
            str: Hostname hoặc None
        """
        if ip in NetworkUtils.dns_cache:
            return NetworkUtils.dns_cache[ip]
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            NetworkUtils.dns_cache[ip] = hostname
            return hostname
        except (socket.herror, socket.gaierror):
            NetworkUtils.dns_cache[ip] = None
            return None
    
    @staticmethod
    def get_hostname_display(ip):
        """
        Hiển thị IP kèm hostname nếu có
        
        Args:
            ip: Địa chỉ IP
        
        Returns:
            str: "IP (hostname)" hoặc chỉ "IP"
        """
        hostname = NetworkUtils.reverse_dns_lookup(ip)
        if hostname:
            return f"{ip} ({hostname})"
        return ip
    
    @staticmethod
    def identify_application_protocol(src_port, dest_port, data):
        """
        Xác định protocol tầng application dựa trên port và data
        
        Args:
            src_port: Port nguồn
            dest_port: Port đích
            data: Dữ liệu payload
        
        Returns:
            str: Tên giao thức
        """
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
        
        # Phân tích dựa trên nội dung data
        if data:
            if data.startswith(b'GET ') or data.startswith(b'POST ') or data.startswith(b'HTTP/'):
                return 'HTTP'
            elif data.startswith(b'\x16\x03'):
                return 'TLS/SSL'
            elif b'SSH-' in data[:10]:
                return 'SSH'
        
        return 'Unknown'
    
    @staticmethod
    def get_service_name(src_port, dest_port):
        """Lấy tên service dựa trên port"""
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
    
    @staticmethod
    def get_protocol_name(proto):
        """Trả về tên protocol từ số"""
        protocols = {
            1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP',
            41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH', 89: 'OSPF',
        }
        return protocols.get(proto, f'Unknown({proto})')
    
    @staticmethod
    def get_icmp_type_name(icmp_type):
        """Trả về tên ICMP type"""
        types = {
            0: 'Echo Reply', 3: 'Destination Unreachable',
            8: 'Echo Request', 11: 'Time Exceeded',
            13: 'Timestamp Request', 14: 'Timestamp Reply',
        }
        return types.get(icmp_type, 'Unknown')
    
    @staticmethod
    def is_text(data):
        """Kiểm tra xem data có phải văn bản không"""
        if not data:
            return False
        try:
            sample = data[:100]
            sample.decode('utf-8')
            printable = sum(32 <= b < 127 or b in [9, 10, 13] for b in sample)
            return printable / len(sample) > 0.7
        except:
            return False
    
    @staticmethod
    def is_encrypted(data):
        """Kiểm tra xem data có bị mã hóa không"""
        if not data or len(data) < 10:
            return False
        
        # Check TLS handshake
        if data[0:3] in [b'\x16\x03\x00', b'\x16\x03\x01', b'\x16\x03\x02', b'\x16\x03\x03']:
            return True
        
        # Check entropy
        if len(data) >= 100:
            unique_bytes = len(set(data[:100]))
            if unique_bytes > 80:
                return True
        
        return False