"""
statistics_manager.py
Module quản lý thống kê gói tin
"""

import time
from collections import defaultdict


class StatisticsManager:
    """Quản lý thống kê về các gói tin đã bắt"""
    
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
    
    def increment(self, category):
        """
        Tăng số đếm cho một loại gói tin
        
        Args:
            category: Loại gói tin ('total', 'tcp', 'udp', v.v.)
        """
        if category in self.stats:
            self.stats[category] += 1
    
    def add_protocol(self, protocol_name):
        """
        Thêm một giao thức vào thống kê
        
        Args:
            protocol_name: Tên giao thức
        """
        self.protocol_stats[protocol_name] += 1
    
    def add_conversation(self, src_ip, dest_ip):
        """
        Thêm một cuộc hội thoại IP
        
        Args:
            src_ip: IP nguồn
            dest_ip: IP đích
        """
        conversation = f"{src_ip} <-> {dest_ip}"
        self.ip_conversations[conversation] += 1
    
    def get_duration(self):
        """Lấy thời gian chạy (giây)"""
        return time.time() - self.start_time
    
    def get_packets_per_second(self):
        """Tính số gói tin mỗi giây"""
        duration = self.get_duration()
        return self.stats['total'] / max(duration, 0.001)
    
    def print_statistics(self):
        """In thống kê chi tiết"""
        duration = self.get_duration()
        
        print("\n" + "="*100)
        print("THỐNG KÊ BẮT GÓI TIN".center(100))
        print("="*100)
        print(f"Thời gian: {duration:.2f} giây")
        print(f"Tổng số gói tin: {self.stats['total']}")
        print(f"\nGói tin mỗi giây: {self.get_packets_per_second():.2f}")
        
        # Phân bổ giao thức
        print(f"\nPhân bổ giao thức:")
        total = max(self.stats['total'], 1)
        
        for protocol, count in self.stats.items():
            if protocol != 'total':
                percentage = count / total * 100
                print(f"  {protocol.upper()}: {count} ({percentage:.1f}%)")
        
        # Thống kê chi tiết
        if self.protocol_stats:
            print(f"\nThống kê giao thức chi tiết:")
            sorted_protocols = sorted(
                self.protocol_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )
            for proto, count in sorted_protocols[:10]:
                print(f"  {proto}: {count}")
        
        # Top conversations
        if self.ip_conversations:
            print(f"\nTop 10 cuộc hội thoại IP:")
            sorted_conversations = sorted(
                self.ip_conversations.items(),
                key=lambda x: x[1],
                reverse=True
            )
            for conv, count in sorted_conversations[:10]:
                print(f"  {conv}: {count} gói tin")
        
        print("="*100)
    
    def reset(self):
        """Reset tất cả thống kê"""
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
        self.protocol_stats.clear()
        self.ip_conversations.clear()
        self.start_time = time.time()
    
    def get_summary(self):
        """
        Lấy tóm tắt thống kê
        
        Returns:
            dict: Dictionary chứa thông tin thống kê
        """
        return {
            'total_packets': self.stats['total'],
            'duration': self.get_duration(),
            'packets_per_second': self.get_packets_per_second(),
            'protocol_distribution': self.stats.copy(),
            'top_protocols': dict(sorted(
                self.protocol_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10])
        }