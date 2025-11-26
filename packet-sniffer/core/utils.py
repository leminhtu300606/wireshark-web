"""
Enhanced utility functions for packet analysis
Fixed: IPv6 handling, domain resolution, zone ID cleanup
"""
import socket
import ipaddress
import re

def get_mac_addr(bytes_addr):
    """Convert MAC address bytes to string format"""
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ipv4_to_string(addr):
    """Convert IPv4 bytes to string"""
    return '.'.join(map(str, addr))

def ipv6_to_string(addr):
    """
    Convert IPv6 bytes to readable string format
    Enhanced version with better error handling
    """
    try:
        # If already string, just clean it
        if isinstance(addr, str):
            return clean_ipv6_address(addr)
        
        # Convert bytes to IPv6 address object for proper formatting
        if len(addr) == 16:
            ipv6_obj = ipaddress.IPv6Address(addr)
            return str(ipv6_obj)
        else:
            raise ValueError(f"Invalid IPv6 address length: {len(addr)} bytes")
    except Exception as e:
        # Fallback to manual formatting
        try:
            if len(addr) >= 16:
                formatted = ':'.join(f'{addr[i]:02x}{addr[i+1]:02x}' 
                                   for i in range(0, 16, 2))
                # Compress zeros
                return str(ipaddress.IPv6Address(formatted.replace(':', '')))
            return 'invalid-ipv6'
        except:
            return f'error-ipv6-{len(addr)}bytes'

def clean_ipv6_address(ipv6_str):
    """
    Clean IPv6 address by removing zone ID and normalizing format
    Example: fe80::1%eth0 -> fe80::1
    """
    if not ipv6_str:
        return ipv6_str
    
    # Remove zone ID (everything after %)
    if '%' in ipv6_str:
        ipv6_str = ipv6_str.split('%')[0]
    
    # Normalize using ipaddress module
    try:
        return str(ipaddress.IPv6Address(ipv6_str))
    except:
        return ipv6_str

def clean_domain_name(domain):
    """
    Clean and normalize domain name
    Removes: protocol, www, port, path, trailing dots, whitespace
    """
    if not domain:
        return ''
    
    # Convert to lowercase and strip whitespace
    domain = domain.strip().lower()
    
    # Remove protocol
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r'^ftp://', '', domain)
    
    # Remove www prefix
    domain = re.sub(r'^www\.', '', domain)
    
    # Remove port (but not if it's part of IPv6)
    if ':' in domain and domain.count(':') < 3:  # Not IPv6
        domain = domain.split(':')[0]
    
    # Remove path
    if '/' in domain:
        domain = domain.split('/')[0]
    
    # Remove trailing dots
    domain = domain.rstrip('.')
    
    # Validate domain format
    if domain and not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$', domain):
        print(f"[WARNING] Invalid domain format: {domain}")
        return ''
    
    return domain

def resolve_domain(domain):
    """
    Resolve domain to IP addresses (both IPv4 and IPv6)
    Enhanced version with better error handling and logging
    """
    try:
        # Clean domain name
        original_domain = domain
        domain = clean_domain_name(domain)
        
        if not domain:
            print(f"[WARNING] Empty domain after cleaning: '{original_domain}'")
            return []
        
        print(f"[INFO] Resolving domain: {domain}")
        
        # Get all addresses (IPv4 and IPv6)
        try:
            result = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as e:
            print(f"[WARNING] Cannot resolve domain '{domain}': {e}")
            return []
        
        ips = []
        seen_ips = set()
        
        for addr_info in result:
            ip = addr_info[4][0]
            
            # Clean IPv6 address (remove zone ID)
            if ':' in ip and '%' in ip:
                ip = clean_ipv6_address(ip)
            
            # Deduplicate
            if ip not in seen_ips:
                seen_ips.add(ip)
                ips.append(ip)
        
        if ips:
            print(f"[INFO] Resolved '{domain}' to {len(ips)} address(es):")
            for ip in ips:
                ip_type = 'IPv4' if is_ipv4_address(ip) else 'IPv6'
                print(f"       • {ip_type}: {ip}")
        else:
            print(f"[WARNING] No addresses found for '{domain}'")
        
        return ips
        
    except Exception as e:
        print(f"[ERROR] Unexpected error resolving '{domain}': {e}")
        import traceback
        traceback.print_exc()
        return []

def reverse_dns_lookup(ip, dns_cache):
    """
    Reverse DNS lookup (supports both IPv4 and IPv6)
    Enhanced with better caching and error handling
    """
    if not ip:
        return None
    
    # Check cache first
    if ip in dns_cache:
        return dns_cache[ip]
    
    try:
        # Clean IPv6 address (remove zone ID if present)
        clean_ip = clean_ipv6_address(ip) if ':' in ip else ip
        
        # Perform reverse lookup
        hostname = socket.gethostbyaddr(clean_ip)[0]
        
        # Cache result
        dns_cache[ip] = hostname
        return hostname
        
    except (socket.herror, socket.gaierror, OSError) as e:
        # Cache negative result to avoid repeated lookups
        dns_cache[ip] = None
        return None
    except Exception as e:
        print(f"[WARNING] Reverse DNS lookup failed for {ip}: {e}")
        dns_cache[ip] = None
        return None

def get_hostname_display(ip, dns_cache):
    """
    Get IP with hostname (supports both IPv4 and IPv6)
    Enhanced formatting
    """
    hostname = reverse_dns_lookup(ip, dns_cache)
    if hostname:
        return f"{ip} ({hostname})"
    return ip

def is_ipv4_address(ip_str):
    """Check if string is valid IPv4 address"""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False

def is_ipv6_address(ip_str):
    """
    Check if string is valid IPv6 address
    Enhanced to handle zone IDs
    """
    try:
        # Remove zone ID if present
        clean_ip = clean_ipv6_address(ip_str) if '%' in ip_str else ip_str
        ipaddress.IPv6Address(clean_ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False

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
    """Check if data is encrypted (TLS/SSL detection)"""
    if not data or len(data) < 10:
        return False
    
    # Check for TLS/SSL signature (all versions)
    tls_signatures = [
        b'\x16\x03\x00',  # SSL 3.0
        b'\x16\x03\x01',  # TLS 1.0
        b'\x16\x03\x02',  # TLS 1.1
        b'\x16\x03\x03',  # TLS 1.2
        b'\x16\x03\x04'   # TLS 1.3
    ]
    
    if data[:3] in tls_signatures:
        return True
    
    # Check entropy for generic encryption detection
    if len(data) >= 100:
        unique_bytes = len(set(data[:100]))
        if unique_bytes > 80:
            return True
    
    return False

def get_protocol_name(proto):
    """Get protocol name from number"""
    protocols = {
        1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP',
        41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH', 
        58: 'ICMPv6', 89: 'OSPF', 132: 'SCTP'
    }
    return protocols.get(proto, f'Unknown({proto})')

def get_icmp_type_name(icmp_type):
    """Get ICMP type name"""
    types = {
        0: 'Echo Reply', 3: 'Destination Unreachable',
        5: 'Redirect', 8: 'Echo Request', 
        9: 'Router Advertisement', 10: 'Router Solicitation',
        11: 'Time Exceeded', 12: 'Parameter Problem',
        13: 'Timestamp Request', 14: 'Timestamp Reply'
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
        137: 'Redirect', 138: 'Router Renumbering',
        139: 'Node Information Query', 140: 'Node Information Response'
    }
    return types.get(icmpv6_type, f'Type {icmpv6_type}')

def identify_application_protocol(src_port, dest_port, data):
    """Identify application layer protocol"""
    port_protocols = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        445: 'SMB', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S',
        3389: 'RDP', 5060: 'SIP', 5061: 'SIPS', 
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
        3306: 'MySQL', 5432: 'PostgreSQL',
        6379: 'Redis', 27017: 'MongoDB'
    }
    
    # Check destination port first (server port)
    if dest_port in port_protocols:
        protocol = port_protocols[dest_port]
    elif src_port in port_protocols:
        protocol = port_protocols[src_port]
    else:
        protocol = 'Unknown'
    
    # Verify with payload inspection
    if data and len(data) >= 10:
        data_start = data[:20]
        
        # HTTP detection
        http_methods = [b'GET ', b'POST ', b'PUT ', b'DELETE ', 
                       b'HEAD ', b'OPTIONS ', b'PATCH ', b'CONNECT ']
        if any(data_start.startswith(method) for method in http_methods) or \
           data_start.startswith(b'HTTP/'):
            return 'HTTP'
        
        # TLS/SSL detection
        if data_start[:3] in [b'\x16\x03\x00', b'\x16\x03\x01', 
                              b'\x16\x03\x02', b'\x16\x03\x03', b'\x16\x03\x04']:
            return 'TLS/SSL'
        
        # SSH detection
        if b'SSH-' in data[:10]:
            return 'SSH'
        
        # DNS (redundant check)
        if dest_port == 53 or src_port == 53:
            return 'DNS'
    
    return protocol

def get_service_name(src_port, dest_port):
    """Get service name from port"""
    services = {
        20: 'File Transfer Protocol (Data)',
        21: 'File Transfer Protocol (Control)',
        22: 'Secure Shell (SSH)',
        23: 'Telnet',
        25: 'Simple Mail Transfer Protocol (SMTP)',
        53: 'Domain Name System (DNS)',
        67: 'DHCP Server',
        68: 'DHCP Client',
        80: 'HyperText Transfer Protocol (HTTP)',
        110: 'Post Office Protocol v3 (POP3)',
        143: 'Internet Message Access Protocol (IMAP)',
        443: 'HTTP Secure (HTTPS)',
        445: 'Server Message Block (SMB)',
        587: 'SMTP (Mail Submission)',
        993: 'IMAP over SSL (IMAPS)',
        995: 'POP3 over SSL (POP3S)',
        3389: 'Remote Desktop Protocol (RDP)',
        5060: 'Session Initiation Protocol (SIP)',
        5061: 'SIP over TLS',
        8080: 'HTTP Alternate',
        8443: 'HTTPS Alternate',
        3306: 'MySQL Database',
        5432: 'PostgreSQL Database',
        6379: 'Redis Database',
        27017: 'MongoDB Database'
    }
    
    # Check server port (destination) first
    port = dest_port if dest_port in services else src_port
    return services.get(port, f'Port {dest_port}')

def format_bytes(num_bytes):
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"

def validate_filter_inputs(filter_protocol=None, filter_ip=None, 
                          filter_domain=None, filter_port=None):
    """
    Validate and normalize filter inputs
    Returns: tuple of (valid, error_message, normalized_values)
    """
    errors = []
    
    # Validate protocol
    valid_protocols = ['TCP', 'UDP', 'ICMP', 'ICMPV6', 'ARP', 'IPV6', 
                       'HTTP', 'HTTPS', 'FTP', 'SMTP', 'POP3', 'IMAP', 'DNS']
    if filter_protocol:
        filter_protocol = filter_protocol.upper()
        if filter_protocol not in valid_protocols:
            errors.append(f"Invalid protocol: {filter_protocol}. Valid: {', '.join(valid_protocols)}")
    
    # Validate IP
    if filter_ip:
        if not (is_ipv4_address(filter_ip) or is_ipv6_address(filter_ip)):
            errors.append(f"Invalid IP address: {filter_ip}")
    
    # Validate domain
    if filter_domain:
        cleaned = clean_domain_name(filter_domain)
        if not cleaned:
            errors.append(f"Invalid domain name: {filter_domain}")
        else:
            filter_domain = cleaned
    
    # Validate port
    if filter_port is not None:
        try:
            port_num = int(filter_port)
            if not (0 <= port_num <= 65535):
                errors.append(f"Port must be between 0-65535: {filter_port}")
        except ValueError:
            errors.append(f"Invalid port number: {filter_port}")
    
    if errors:
        return False, '; '.join(errors), None
    
    return True, None, {
        'protocol': filter_protocol,
        'ip': filter_ip,
        'domain': filter_domain,
        'port': filter_port
    }