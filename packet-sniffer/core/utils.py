"""
Utility functions for packet analysis
"""
import socket
import ipaddress

def get_mac_addr(bytes_addr):
    """Convert MAC address bytes to string format"""
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ipv4_to_string(addr):
    """Convert IPv4 bytes to string"""
    return '.'.join(map(str, addr))

def ipv6_to_string(addr):
    """Convert IPv6 bytes to readable string format"""
    try:
        # Convert bytes to IPv6 address object for proper formatting
        ipv6_obj = ipaddress.IPv6Address(addr)
        return str(ipv6_obj)
    except:
        # Fallback to manual formatting
        return ':'.join(f'{addr[i]:02x}{addr[i+1]:02x}' for i in range(0, len(addr), 2))

def is_text(data):
    """Check if data is text"""
    if not data:
        return False
    try:
        sample = data[:100] if len(data) > 100 else data
        sample.decode('utf-8')
        printable = sum(32 <= b < 127 or b in [9, 10, 13] for b in sample)
        return printable / len(sample) > 0.7
    except:
        return False

def is_encrypted(data):
    """Check if data is encrypted"""
    if not data or len(data) < 10:
        return False
    
    # Check for TLS/SSL signature (all versions)
    if data[0:3] in [b'\x16\x03\x00', b'\x16\x03\x01', b'\x16\x03\x02', b'\x16\x03\x03', b'\x16\x03\x04']:
        return True
    
    # Check entropy
    if len(data) >= 100:
        unique_bytes = len(set(data[:100]))
        if unique_bytes > 80:
            return True
    
    return False

def resolve_domain(domain):
    """Resolve domain to IP addresses (both IPv4 and IPv6)"""
    try:
        # Clean domain
        domain = domain.replace('http://', '').replace('https://', '')
        domain = domain.replace('www.', '')
        domain = domain.split('/')[0].split(':')[0]
        
        # Get all addresses (IPv4 and IPv6)
        result = socket.getaddrinfo(domain, None)
        ips = []
        for addr_info in result:
            ip = addr_info[4][0]
            if ip not in ips:
                ips.append(ip)
        
        return ips
    except socket.gaierror as e:
        print(f"[WARNING] Cannot resolve domain: {domain} - {e}")
        return []

def reverse_dns_lookup(ip, dns_cache):
    """Reverse DNS lookup (supports both IPv4 and IPv6)"""
    if ip in dns_cache:
        return dns_cache[ip]
    
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        dns_cache[ip] = hostname
        return hostname
    except (socket.herror, socket.gaierror):
        dns_cache[ip] = None
        return None

def get_hostname_display(ip, dns_cache):
    """Get IP with hostname (supports IPv6)"""
    hostname = reverse_dns_lookup(ip, dns_cache)
    if hostname:
        return f"{ip} ({hostname})"
    return ip

def get_protocol_name(proto):
    """Get protocol name from number"""
    protocols = {
        1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP',
        41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH', 89: 'OSPF',
        58: 'ICMPv6', 132: 'SCTP'
    }
    return protocols.get(proto, f'Unknown({proto})')

def get_icmp_type_name(icmp_type):
    """Get ICMP type name"""
    types = {
        0: 'Echo Reply', 3: 'Destination Unreachable',
        8: 'Echo Request', 11: 'Time Exceeded',
        13: 'Timestamp Request', 14: 'Timestamp Reply',
        5: 'Redirect', 9: 'Router Advertisement',
        10: 'Router Solicitation', 12: 'Parameter Problem'
    }
    return types.get(icmp_type, f'Type {icmp_type}')

def get_icmpv6_type_name(icmpv6_type):
    """Get ICMPv6 type name"""
    types = {
        1: 'Destination Unreachable', 2: 'Packet Too Big',
        3: 'Time Exceeded', 4: 'Parameter Problem',
        128: 'Echo Request', 129: 'Echo Reply',
        133: 'Router Solicitation', 134: 'Router Advertisement',
        135: 'Neighbor Solicitation', 136: 'Neighbor Advertisement',
        137: 'Redirect'
    }
    return types.get(icmpv6_type, f'Type {icmpv6_type}')

def identify_application_protocol(src_port, dest_port, data):
    """Identify application layer protocol"""
    port_protocols = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 587: 'SMTP',
        3389: 'RDP', 5060: 'SIP', 5061: 'SIPS', 8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt', 3306: 'MySQL', 5432: 'PostgreSQL',
        6379: 'Redis', 27017: 'MongoDB'
    }
    
    # Check destination port first
    if dest_port in port_protocols:
        protocol = port_protocols[dest_port]
    elif src_port in port_protocols:
        protocol = port_protocols[src_port]
    else:
        protocol = 'Unknown'
    
    # Verify with payload inspection
    if data:
        data_start = data[:20]
        if data_start.startswith(b'GET ') or data_start.startswith(b'POST ') or \
           data_start.startswith(b'HTTP/') or data_start.startswith(b'HEAD ') or \
           data_start.startswith(b'PUT ') or data_start.startswith(b'DELETE '):
            return 'HTTP'
        elif data_start.startswith(b'\x16\x03'):
            return 'TLS/SSL'
        elif b'SSH-' in data[:10]:
            return 'SSH'
        elif dest_port == 53 or src_port == 53:
            return 'DNS'
    
    return protocol

def get_service_name(src_port, dest_port):
    """Get service name from port"""
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
        8080: 'HTTP Alternate',
        8443: 'HTTPS Alternate',
        3306: 'MySQL Database',
        5432: 'PostgreSQL Database',
        6379: 'Redis Database',
        27017: 'MongoDB Database'
    }
    
    port = dest_port if dest_port in services else src_port
    return services.get(port, f'Port {dest_port}')

def is_ipv6_address(ip_str):
    """Check if string is valid IPv6 address"""
    try:
        ipaddress.IPv6Address(ip_str)
        return True
    except:
        return False

def is_ipv4_address(ip_str):
    """Check if string is valid IPv4 address"""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except:
        return False

def format_bytes(num_bytes):
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"