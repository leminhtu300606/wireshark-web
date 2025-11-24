"""
Security detection module
"""
from collections import defaultdict

class SecurityDetector:
    """Detect network attacks"""
    
    def __init__(self):
        self.port_scan_tracker = defaultdict(set)
        self.syn_tracker = defaultdict(int)
        self.arp_cache = {}
    
    def detect_port_scan(self, src_ip, dest_port):
        """Detect port scanning"""
        self.port_scan_tracker[src_ip].add(dest_port)
        
        if len(self.port_scan_tracker[src_ip]) > 10:
            return True
        return False
    
    def detect_syn_flood(self, src_ip):
        """Detect SYN flood attack"""
        self.syn_tracker[src_ip] += 1
        
        if self.syn_tracker[src_ip] > 50:
            return True
        return False
    
    def detect_arp_spoofing(self, src_mac, src_ip):
        """Detect ARP spoofing"""
        if src_ip in self.arp_cache:
            if self.arp_cache[src_ip] != src_mac:
                return True
        else:
            self.arp_cache[src_ip] = src_mac
        return False
    
    def get_stats(self):
        """Get security statistics"""
        return {
            'port_scans': len([ip for ip, ports in self.port_scan_tracker.items() if len(ports) > 10]),
            'syn_floods': len([ip for ip, count in self.syn_tracker.items() if count > 50])
        }