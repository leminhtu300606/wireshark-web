"""
Core package for Packet Sniffer - Fixed Version with Enhanced IPv6 & Domain Resolution
Version: 2.0.1
"""

from .sniffer import PacketSniffer
from .parsers import (
    parse_ethernet_frame,
    parse_ipv4_packet,
    parse_ipv6_packet,
    parse_arp_packet,
    parse_icmp_packet,
    parse_icmpv6_packet,
    parse_tcp_segment,
    parse_udp_segment
)
from .protocols import (
    decode_dns,
    decode_http,
    decode_ftp,
    decode_smtp,
    decode_pop3,
    decode_imap
)
from .utils import (
    get_mac_addr,
    ipv4_to_string,
    ipv6_to_string,
    resolve_domain,
    reverse_dns_lookup,
    get_hostname_display,
    get_protocol_name,
    get_icmp_type_name,
    get_icmpv6_type_name,
    identify_application_protocol,
    get_service_name,
    is_text,
    is_encrypted,
    is_ipv4_address,
    is_ipv6_address,
    format_bytes
)
from .security import SecurityDetector
from .statistics import StatisticsTracker

__all__ = [
    # Core classes
    'PacketSniffer',
    'SecurityDetector',
    'StatisticsTracker',
    
    # Parsers
    'parse_ethernet_frame',
    'parse_ipv4_packet',
    'parse_ipv6_packet',
    'parse_arp_packet',
    'parse_icmp_packet',
    'parse_icmpv6_packet',
    'parse_tcp_segment',
    'parse_udp_segment',
    
    # Protocol decoders
    'decode_dns',
    'decode_http',
    'decode_ftp',
    'decode_smtp',
    'decode_pop3',
    'decode_imap',
    
    # Utility functions
    'get_mac_addr',
    'ipv4_to_string',
    'ipv6_to_string',
    'resolve_domain',
    'reverse_dns_lookup',
    'get_hostname_display',
    'get_protocol_name',
    'get_icmp_type_name',
    'get_icmpv6_type_name',
    'identify_application_protocol',
    'get_service_name',
    'is_text',
    'is_encrypted',
    'is_ipv4_address',
    'is_ipv6_address',
    'format_bytes'
]

__version__ = '2.0.1'
__author__ = 'Packet Sniffer Team'

# Version changelog
__changelog__ = """
2.0.1 - Enhanced IPv6 & Domain Resolution
- Fixed domain resolution for both IPv4 and IPv6
- Improved IPv6 address parsing and formatting
- Enhanced ICMPv6 support (ping6)
- Better handling of IPv6 zone IDs
- Fixed filter logic for domain names
- Added comprehensive IPv6 packet inspection

2.0.0 - Initial modular refactoring
- Separated concerns into modules
- Added security detection
- Added statistics tracking
"""