"""
pcap_manager.py
Module quản lý lưu trữ và đọc file PCAP
"""

import json
import time


class PcapManager:
    """Quản lý việc lưu và đọc file PCAP"""
    
    def __init__(self, filename=None):
        self.filename = filename
        self.captured_packets = []
    
    def save_packet(self, raw_data, timestamp=None):
        """
        Lưu gói tin vào buffer
        
        Args:
            raw_data: Dữ liệu thô của gói tin
            timestamp: Thời gian bắt gói tin (mặc định là thời gian hiện tại)
        """
        if timestamp is None:
            timestamp = time.time()
        
        packet_info = {
            'timestamp': timestamp,
            'length': len(raw_data),
            'data': raw_data.hex()
        }
        self.captured_packets.append(packet_info)
    
    def write_to_file(self, filename=None):
        """
        Ghi tất cả gói tin đã lưu vào file
        
        Args:
            filename: Tên file đầu ra (nếu không cung cấp, dùng filename mặc định)
        
        Returns:
            bool: True nếu ghi thành công
        """
        target_file = filename or self.filename
        
        if not target_file:
            print("[✗] Không có tên file để lưu")
            return False
        
        if not self.captured_packets:
            print("[✗] Không có gói tin nào để lưu")
            return False
        
        try:
            with open(target_file, 'w') as f:
                json.dump(self.captured_packets, f, indent=2)
            
            print(f"\n[✓] Đã lưu {len(self.captured_packets)} gói tin vào {target_file}")
            return True
        except Exception as e:
            print(f"[✗] Lỗi khi ghi file: {e}")
            return False
    
    def read_from_file(self, filename=None):
        """
        Đọc các gói tin từ file
        
        Args:
            filename: Tên file đầu vào (nếu không cung cấp, dùng filename mặc định)
        
        Returns:
            list: Danh sách các gói tin, hoặc None nếu có lỗi
        """
        target_file = filename or self.filename
        
        if not target_file:
            print("[✗] Không có tên file để đọc")
            return None
        
        try:
            with open(target_file, 'r') as f:
                packets = json.load(f)
            
            print(f"\n[✓] Đã đọc {len(packets)} gói tin từ {target_file}")
            return packets
        except FileNotFoundError:
            print(f"[✗] Không tìm thấy file: {target_file}")
            return None
        except json.JSONDecodeError:
            print(f"[✗] File không đúng định dạng JSON: {target_file}")
            return None
        except Exception as e:
            print(f"[✗] Lỗi khi đọc file: {e}")
            return None
    
    def get_packet_count(self):
        """Lấy số lượng gói tin đã lưu"""
        return len(self.captured_packets)
    
    def clear(self):
        """Xóa tất cả gói tin đã lưu"""
        self.captured_packets.clear()
    
    def get_packets(self):
        """Lấy danh sách tất cả gói tin đã lưu"""
        return self.captured_packets.copy()