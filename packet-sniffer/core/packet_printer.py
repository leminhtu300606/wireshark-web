"""
Packet printer - Fixed import version
"""
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Use absolute imports instead of relative imports
from core.utils import (
    get_protocol_name, get_icmp_type_name, get_icmpv6_type_name,
    identify_application_protocol, get_service_name,
    is_text, is_encrypted
)
from core.parsers import (
    parse_ethernet_frame, parse_ipv4_packet, parse_ipv6_packet,
    parse_arp_packet, parse_icmp_packet, parse_icmpv6_packet,
    parse_tcp_segment, parse_udp_segment
)
from core.protocols import decode_dns, decode_ftp, decode_smtp, decode_pop3, decode_imap

def print_packet_summary(packet_num, raw_data, sniffer):
    """Print packet summary - one line"""
    try:
        dest_mac, src_mac, eth_proto, data = parse_ethernet_frame(raw_data)
        
        if not eth_proto:
            return
        
        # IPv4
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, payload = parse_ipv4_packet(data)
            
            if not src or not target:
                return
            
            proto_name = get_protocol_name(proto)
            
            # TCP
            if proto == 6:
                result = parse_tcp_segment(payload)
                if result[0] is not None:
                    src_port, dest_port = result[0], result[1]
                    app_proto = identify_application_protocol(src_port, dest_port, result[10])
                    print(f"#{packet_num} {src}:{src_port} → {target}:{dest_port} [{app_proto}]")
            
            # UDP
            elif proto == 17:
                result = parse_udp_segment(payload)
                if result[0] is not None:
                    src_port, dest_port = result[0], result[1]
                    print(f"#{packet_num} {src}:{src_port} → {target}:{dest_port} [UDP]")
            
            # ICMP
            elif proto == 1:
                icmp_type, code, checksum, icmp_data = parse_icmp_packet(payload)
                if icmp_type is not None:
                    type_name = get_icmp_type_name(icmp_type)
                    print(f"#{packet_num} {src} → {target} [ICMP {type_name}]")
            
            else:
                print(f"#{packet_num} {src} → {target} [{proto_name}]")
        
        # IPv6
        elif eth_proto == 0x86DD:
            ipv6_info = parse_ipv6_packet(data)
            if ipv6_info:
                print(f"#{packet_num} {ipv6_info['src']} → {ipv6_info['dest']} [IPv6]")
        
        # ARP
        elif eth_proto == 0x0806:
            arp_info = parse_arp_packet(data)
            if arp_info:
                print(f"#{packet_num} ARP: {arp_info['src_ip']} → {arp_info['dest_ip']}")
    
    except Exception as e:
        print(f"Error printing packet: {e}")

def print_packet_detailed(packet_num, raw_data, sniffer):
    """Print detailed packet information"""
    try:
        print(f"\n{'='*100}")
        print(f"GÓI TIN #{packet_num}")
        print(f"{'='*100}")
        
        dest_mac, src_mac, eth_proto, data = parse_ethernet_frame(raw_data)
        
        print(f"\n[ETHERNET FRAME]")
        print(f"  Destination MAC: {dest_mac}")
        print(f"  Source MAC: {src_mac}")
        print(f"  Protocol: 0x{eth_proto:04x}")
        
        # IPv4
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, payload = parse_ipv4_packet(data)
            
            print(f"\n[IPv4 PACKET]")
            print(f"  Version: {version}")
            print(f"  Header Length: {header_length} bytes")
            print(f"  TTL: {ttl}")
            print(f"  Protocol: {get_protocol_name(proto)}")
            print(f"  Source IP: {src}")
            print(f"  Destination IP: {target}")
            
            # TCP
            if proto == 6:
                result = parse_tcp_segment(payload)
                if result[0] is not None:
                    src_port, dest_port, seq, ack, flag_ack, flag_fin, flag_psh, flag_rst, flag_syn, flag_urg, tcp_data = result
                    
                    print(f"\n[TCP SEGMENT]")
                    print(f"  Source Port: {src_port}")
                    print(f"  Destination Port: {dest_port}")
                    print(f"  Sequence: {seq}")
                    print(f"  Acknowledgement: {ack}")
                    print(f"  Flags: SYN={flag_syn} ACK={flag_ack} FIN={flag_fin} RST={flag_rst} PSH={flag_psh} URG={flag_urg}")
                    
                    if tcp_data:
                        app_proto = identify_application_protocol(src_port, dest_port, tcp_data)
                        print(f"  Application Protocol: {app_proto}")
                        
                        if len(tcp_data) > 0:
                            print(f"  Payload Length: {len(tcp_data)} bytes")
                            if is_text(tcp_data):
                                print(f"  Payload Preview: {tcp_data[:100].decode('utf-8', errors='ignore')}")
            
            # UDP
            elif proto == 17:
                result = parse_udp_segment(payload)
                if result[0] is not None:
                    src_port, dest_port, size, udp_data = result
                    
                    print(f"\n[UDP SEGMENT]")
                    print(f"  Source Port: {src_port}")
                    print(f"  Destination Port: {dest_port}")
                    print(f"  Length: {size} bytes")
                    
                    # DNS
                    if (src_port == 53 or dest_port == 53) and udp_data:
                        dns_info = decode_dns(udp_data)
                        if dns_info:
                            print(f"\n[DNS]")
                            print(f"  Type: {'Response' if dns_info['is_response'] else 'Query'}")
                            print(f"  Domain: {dns_info['domain']}")
                            print(f"  Questions: {dns_info['questions']}")
                            print(f"  Answers: {dns_info['answers']}")
            
            # ICMP
            elif proto == 1:
                icmp_type, code, checksum, icmp_data = parse_icmp_packet(payload)
                if icmp_type is not None:
                    print(f"\n[ICMP PACKET]")
                    print(f"  Type: {get_icmp_type_name(icmp_type)} ({icmp_type})")
                    print(f"  Code: {code}")
                    print(f"  Checksum: {checksum}")
        
        # IPv6
        elif eth_proto == 0x86DD:
            ipv6_info = parse_ipv6_packet(data)
            if ipv6_info:
                print(f"\n[IPv6 PACKET]")
                print(f"  Version: {ipv6_info['version']}")
                print(f"  Payload Length: {ipv6_info['payload_length']}")
                print(f"  Next Header: {ipv6_info['next_header']}")
                print(f"  Hop Limit: {ipv6_info['hop_limit']}")
                print(f"  Source IP: {ipv6_info['src']}")
                print(f"  Destination IP: {ipv6_info['dest']}")
                
                # ICMPv6
                if ipv6_info['next_header'] == 58:
                    icmpv6_info = parse_icmpv6_packet(ipv6_info['data'])
                    if icmpv6_info:
                        print(f"\n[ICMPv6 PACKET]")
                        print(f"  Type: {get_icmpv6_type_name(icmpv6_info['type'])} ({icmpv6_info['type']})")
                        print(f"  Code: {icmpv6_info['code']}")
        
        # ARP
        elif eth_proto == 0x0806:
            arp_info = parse_arp_packet(data)
            if arp_info:
                print(f"\n[ARP PACKET]")
                print(f"  Operation: {'Request' if arp_info['opcode'] == 1 else 'Reply'}")
                print(f"  Source MAC: {arp_info['src_mac']}")
                print(f"  Source IP: {arp_info['src_ip']}")
                print(f"  Destination MAC: {arp_info['dest_mac']}")
                print(f"  Destination IP: {arp_info['dest_ip']}")
        
        print(f"{'='*100}\n")
    
    except Exception as e:
        print(f"Error printing detailed packet: {e}")