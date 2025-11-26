"""
Packet analyzer - Fixed import version
"""
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Now use absolute imports instead of relative imports
from core.utils import (
    get_mac_addr, ipv4_to_string, ipv6_to_string,
    get_protocol_name, get_icmp_type_name, get_icmpv6_type_name,
    identify_application_protocol, get_service_name,
    is_text, is_encrypted, get_hostname_display
)
from core.parsers import (
    parse_ethernet_frame, parse_ipv4_packet, parse_ipv6_packet,
    parse_arp_packet, parse_icmp_packet, parse_icmpv6_packet,
    parse_tcp_segment, parse_udp_segment
)
from core.protocols import decode_dns, decode_ftp, decode_smtp, decode_pop3, decode_imap

def create_packet_summary(raw_data, packet_num, sniffer):
    """
    Create packet summary for display
    Fixed version with absolute imports
    """
    try:
        dest_mac, src_mac, eth_proto, data = parse_ethernet_frame(raw_data)
        
        if not eth_proto:
            return None
        
        summary = {
            'num': packet_num,
            'timestamp': None,
            'protocol': 'Unknown',
            'src': 'Unknown',
            'dest': 'Unknown',
            'length': len(raw_data),
            'info': ''
        }
        
        # ARP
        if eth_proto == 0x0806:
            summary['protocol'] = 'ARP'
            arp_info = parse_arp_packet(data)
            if arp_info:
                summary['src'] = arp_info['src_ip']
                summary['dest'] = arp_info['dest_ip']
                opcode_text = 'Request' if arp_info['opcode'] == 1 else 'Reply'
                summary['info'] = f"Who has {arp_info['dest_ip']}? Tell {arp_info['src_ip']}" if arp_info['opcode'] == 1 else f"{arp_info['src_ip']} is at {arp_info['src_mac']}"
        
        # IPv4
        elif eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = parse_ipv4_packet(data)
            
            if not src or not target:
                return None
            
            summary['src'] = src
            summary['dest'] = target
            proto_name = get_protocol_name(proto)
            
            # ICMP
            if proto == 1:
                summary['protocol'] = 'ICMP'
                icmp_type, code, checksum, icmp_data = parse_icmp_packet(data)
                if icmp_type is not None:
                    type_name = get_icmp_type_name(icmp_type)
                    summary['info'] = f"{type_name} (Type {icmp_type}, Code {code})"
            
            # TCP
            elif proto == 6:
                result = parse_tcp_segment(data)
                if result[0] is not None:
                    src_port, dest_port, seq, ack, flag_ack, flag_fin, flag_psh, flag_rst, flag_syn, flag_urg, tcp_data = result
                    
                    app_proto = identify_application_protocol(src_port, dest_port, tcp_data)
                    summary['protocol'] = app_proto if app_proto != 'Unknown' else 'TCP'
                    
                    flags = []
                    if flag_syn: flags.append('SYN')
                    if flag_ack: flags.append('ACK')
                    if flag_fin: flags.append('FIN')
                    if flag_rst: flags.append('RST')
                    if flag_psh: flags.append('PSH')
                    if flag_urg: flags.append('URG')
                    
                    flag_str = ','.join(flags) if flags else 'None'
                    summary['info'] = f"{src}:{src_port} → {target}:{dest_port} [{flag_str}] Seq={seq} Ack={ack}"
                    
                    # Decode application protocols
                    if tcp_data:
                        if app_proto == 'HTTP':
                            summary['info'] += ' [HTTP]'
                        elif app_proto in ['SMTP', 'FTP', 'POP3', 'IMAP']:
                            summary['info'] += f' [{app_proto}]'
            
            # UDP
            elif proto == 17:
                result = parse_udp_segment(data)
                if result[0] is not None:
                    src_port, dest_port, size, udp_data = result
                    
                    app_proto = identify_application_protocol(src_port, dest_port, udp_data)
                    summary['protocol'] = app_proto if app_proto != 'Unknown' else 'UDP'
                    
                    summary['info'] = f"{src}:{src_port} → {target}:{dest_port} Len={size}"
                    
                    # DNS
                    if (src_port == 53 or dest_port == 53) and udp_data:
                        dns_info = decode_dns(udp_data)
                        if dns_info:
                            dns_type = 'Response' if dns_info['is_response'] else 'Query'
                            summary['info'] += f" [DNS {dns_type}] {dns_info['domain']}"
            
            else:
                summary['protocol'] = proto_name
                summary['info'] = f"Protocol: {proto_name}"
        
        # IPv6
        elif eth_proto == 0x86DD:
            summary['protocol'] = 'IPv6'
            ipv6_info = parse_ipv6_packet(data)
            
            if ipv6_info:
                summary['src'] = ipv6_info['src']
                summary['dest'] = ipv6_info['dest']
                
                next_header = ipv6_info['next_header']
                
                # ICMPv6
                if next_header == 58:
                    summary['protocol'] = 'ICMPv6'
                    icmpv6_info = parse_icmpv6_packet(ipv6_info['data'])
                    if icmpv6_info:
                        type_name = get_icmpv6_type_name(icmpv6_info['type'])
                        summary['info'] = f"{type_name} (Type {icmpv6_info['type']}, Code {icmpv6_info['code']})"
                
                # TCP over IPv6
                elif next_header == 6:
                    result = parse_tcp_segment(ipv6_info['data'])
                    if result[0] is not None:
                        src_port, dest_port = result[0], result[1]
                        summary['protocol'] = 'TCP'
                        summary['info'] = f"{summary['src']}:{src_port} → {summary['dest']}:{dest_port}"
                
                # UDP over IPv6
                elif next_header == 17:
                    result = parse_udp_segment(ipv6_info['data'])
                    if result[0] is not None:
                        src_port, dest_port, size = result[0], result[1], result[2]
                        summary['protocol'] = 'UDP'
                        summary['info'] = f"{summary['src']}:{src_port} → {summary['dest']}:{dest_port}"
                
                else:
                    summary['info'] = f"Next Header: {next_header}"
        
        return summary
        
    except Exception as e:
        print(f"Error in create_packet_summary: {e}")
        return None

def analyze_packet_detailed(raw_data, sniffer):
    """
    Analyze packet in detail
    Fixed version with absolute imports
    """
    try:
        dest_mac, src_mac, eth_proto, data = parse_ethernet_frame(raw_data)
        
        details = {
            'ethernet': {
                'dest_mac': dest_mac,
                'src_mac': src_mac,
                'protocol': f"0x{eth_proto:04x}" if eth_proto else "Unknown"
            }
        }
        
        if eth_proto == 8:  # IPv4
            version, header_length, ttl, proto, src, target, payload = parse_ipv4_packet(data)
            
            details['ipv4'] = {
                'version': version,
                'header_length': header_length,
                'ttl': ttl,
                'protocol': get_protocol_name(proto),
                'src': src,
                'dest': target
            }
            
            if proto == 6:  # TCP
                result = parse_tcp_segment(payload)
                if result[0] is not None:
                    src_port, dest_port, seq, ack, flag_ack, flag_fin, flag_psh, flag_rst, flag_syn, flag_urg, tcp_data = result
                    
                    details['tcp'] = {
                        'src_port': src_port,
                        'dest_port': dest_port,
                        'sequence': seq,
                        'acknowledgement': ack,
                        'flags': {
                            'SYN': bool(flag_syn),
                            'ACK': bool(flag_ack),
                            'FIN': bool(flag_fin),
                            'RST': bool(flag_rst),
                            'PSH': bool(flag_psh),
                            'URG': bool(flag_urg)
                        }
                    }
            
            elif proto == 17:  # UDP
                result = parse_udp_segment(payload)
                if result[0] is not None:
                    src_port, dest_port, size, udp_data = result
                    
                    details['udp'] = {
                        'src_port': src_port,
                        'dest_port': dest_port,
                        'length': size
                    }
        
        elif eth_proto == 0x86DD:  # IPv6
            ipv6_info = parse_ipv6_packet(data)
            if ipv6_info:
                details['ipv6'] = ipv6_info
        
        return details
        
    except Exception as e:
        print(f"Error in analyze_packet_detailed: {e}")
        return None