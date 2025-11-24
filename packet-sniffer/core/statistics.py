"""
Statistics tracking module
"""
import time
from collections import defaultdict

class StatisticsTracker:
    """Track packet statistics"""
    
    def __init__(self):
        self.stats = {
            'total': 0,
            'ipv4': 0,
            'ipv6': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'arp': 0,
            'other': 0
        }
        self.protocol_stats = defaultdict(int)
        self.ip_conversations = defaultdict(int)
        self.start_time = time.time()
    
    def update(self, packet_type):
        """Update statistics"""
        self.stats['total'] += 1
        if packet_type in self.stats:
            self.stats[packet_type] += 1
    
    def update_protocol(self, protocol):
        """Update protocol statistics"""
        self.protocol_stats[protocol] += 1
    
    def update_conversation(self, src_ip, dest_ip):
        """Update IP conversation statistics"""
        conversation = f"{src_ip} <-> {dest_ip}"
        self.ip_conversations[conversation] += 1
    
    def get_packets_per_second(self):
        """Calculate packets per second"""
        duration = time.time() - self.start_time
        return self.stats['total'] / max(duration, 0.001)
    
    def get_stats(self):
        """Get all statistics"""
        return {
            'stats': self.stats,
            'protocol_stats': dict(self.protocol_stats),
            'ip_conversations': dict(list(self.ip_conversations.items())[:10]),
            'packets_per_second': self.get_packets_per_second()
        }
    
    def print_statistics(self):
        """Print detailed statistics"""
        duration = time.time() - self.start_time
        
        print("\n" + "="*100)
        print("THỐNG KÊ BẮT GÓI TIN".center(100))
        print("="*100)
        print(f"Thời gian: {duration:.2f} giây")
        print(f"Tổng số gói tin: {self.stats['total']}")
        print(f"\nGói tin mỗi giây: {self.get_packets_per_second():.2f}")
        
        print(f"\nPhân bổ giao thức:")
        for proto, count in self.stats.items():
            if proto != 'total':
                percentage = count / max(self.stats['total'], 1) * 100
                print(f"  {proto.upper()}: {count} ({percentage:.1f}%)")
        
        if self.protocol_stats:
            print(f"\nThống kê giao thức chi tiết:")
            for proto, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {proto}: {count}")
        
        if self.ip_conversations:
            print(f"\nTop 10 cuộc hội thoại IP:")
            for conv, count in sorted(self.ip_conversations.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {conv}: {count} gói tin")
        
        print("="*100)