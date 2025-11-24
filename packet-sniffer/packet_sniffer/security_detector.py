"""
security_detector.py
Module phát hiện các tấn công mạng (Port Scan, SYN Flood, ARP Spoofing)
"""

from collections import defaultdict


class SecurityDetector:
    """Phát hiện các loại tấn công bảo mật"""
    
    def __init__(self):
        self.port_scan_tracker = defaultdict(set)
        self.syn_tracker = defaultdict(int)
        self.arp_cache = {}
    
    def detect_port_scan(self, src_ip, dest_port, threshold=10):
        """
        Phát hiện Port Scan
        
        Args:
            src_ip: IP nguồn
            dest_port: Port đích
            threshold: Số lượng port tối thiểu để coi là scan
        
        Returns:
            bool: True nếu phát hiện port scan
        """
        self.port_scan_tracker[src_ip].add(dest_port)
        
        if len(self.port_scan_tracker[src_ip]) > threshold:
            return True
        return False
    
    def get_scanned_ports_count(self, src_ip):
        """Lấy số lượng port đã quét"""
        return len(self.port_scan_tracker[src_ip])
    
    def detect_syn_flood(self, src_ip, threshold=50):
        """
        Phát hiện SYN Flood Attack
        
        Args:
            src_ip: IP nguồn
            threshold: Số lượng SYN packet tối thiểu
        
        Returns:
            bool: True nếu phát hiện SYN flood
        """
        self.syn_tracker[src_ip] += 1
        
        if self.syn_tracker[src_ip] > threshold:
            return True
        return False
    
    def get_syn_count(self, src_ip):
        """Lấy số lượng SYN packet từ IP"""
        return self.syn_tracker[src_ip]
    
    def detect_arp_spoofing(self, src_mac, src_ip):
        """
        Phát hiện ARP Spoofing
        
        Args:
            src_mac: MAC address nguồn
            src_ip: IP address nguồn
        
        Returns:
            tuple: (is_spoofing, old_mac) - True nếu phát hiện spoofing
        """
        if src_ip in self.arp_cache:
            if self.arp_cache[src_ip] != src_mac:
                old_mac = self.arp_cache[src_ip]
                self.arp_cache[src_ip] = src_mac
                return True, old_mac
        else:
            self.arp_cache[src_ip] = src_mac
        
        return False, None
    
    def get_statistics(self):
        """Lấy thống kê phát hiện bảo mật"""
        port_scan_detected = len([
            ip for ip, ports in self.port_scan_tracker.items() 
            if len(ports) > 10
        ])
        
        syn_flood_detected = len([
            ip for ip, count in self.syn_tracker.items() 
            if count > 50
        ])
        
        return {
            'port_scan_detected': port_scan_detected,
            'syn_flood_detected': syn_flood_detected,
            'total_arp_entries': len(self.arp_cache)
        }
    
    def reset(self):
        """Reset tất cả dữ liệu tracking"""
        self.port_scan_tracker.clear()
        self.syn_tracker.clear()
        self.arp_cache.clear()