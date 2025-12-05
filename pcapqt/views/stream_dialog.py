# -*- coding: utf-8 -*-

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTextEdit,
    QPushButton, QComboBox, QLabel, QSplitter
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QTextCursor, QColor, QTextCharFormat

from scapy.all import TCP, UDP, IP, Raw


class StreamDialog(QDialog):
    """Dialog for displaying TCP/UDP stream content."""
    
    # Colors for client/server differentiation
    CLIENT_COLOR = QColor(0, 0, 200)  # Blue
    SERVER_COLOR = QColor(200, 0, 0)  # Red
    
    def __init__(self, packets, stream_key, parent=None):
        super().__init__(parent)
        self.packets = packets
        self.stream_key = stream_key  # (src_ip, dst_ip, src_port, dst_port, protocol)
        self.setup_ui()
        self.display_stream()
    
    def setup_ui(self):
        self.setWindowTitle(f"Follow Stream - {self.stream_key[4]}")
        self.setMinimumSize(700, 500)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(12, 12, 12, 12)
        
        # Header with stream info
        header_layout = QHBoxLayout()
        
        src_ip, dst_ip, src_port, dst_port, protocol = self.stream_key
        stream_info = f"{src_ip}:{src_port} ↔ {dst_ip}:{dst_port} ({protocol})"
        header_label = QLabel(stream_info)
        header_label.setFont(QFont("Consolas", 10))
        header_layout.addWidget(header_label)
        
        header_layout.addStretch()
        
        # View mode selector
        header_layout.addWidget(QLabel("View:"))
        self.view_combo = QComboBox()
        self.view_combo.addItems(["ASCII", "Hex", "Raw"])
        self.view_combo.currentIndexChanged.connect(self.display_stream)
        header_layout.addWidget(self.view_combo)
        
        layout.addLayout(header_layout)
        
        # Stream content
        self.stream_text = QTextEdit()
        self.stream_text.setReadOnly(True)
        self.stream_text.setFont(QFont("Consolas", 9))
        self.stream_text.setLineWrapMode(QTextEdit.NoWrap)
        layout.addWidget(self.stream_text)
        
        # Legend
        legend_layout = QHBoxLayout()
        
        client_label = QLabel("● Client")
        client_label.setStyleSheet("color: blue;")
        legend_layout.addWidget(client_label)
        
        server_label = QLabel("● Server")
        server_label.setStyleSheet("color: red;")
        legend_layout.addWidget(server_label)
        
        legend_layout.addStretch()
        
        # Packet count
        self.count_label = QLabel(f"Packets: {len(self.packets)}")
        legend_layout.addWidget(self.count_label)
        
        layout.addLayout(legend_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
    
    def display_stream(self):
        """Display the stream content based on selected view mode."""
        self.stream_text.clear()
        
        view_mode = self.view_combo.currentText()
        src_ip, dst_ip, src_port, dst_port, protocol = self.stream_key
        
        cursor = self.stream_text.textCursor()
        
        for packet in self.packets:
            if not self.packet_in_stream(packet):
                continue
            
            if Raw not in packet:
                continue
            
            payload = bytes(packet[Raw].load)
            if not payload:
                continue
            
            # Determine direction
            if IP in packet:
                pkt_src = packet[IP].src
                pkt_dst = packet[IP].dst
            else:
                continue
            
            if protocol == "TCP" and TCP in packet:
                pkt_sport = packet[TCP].sport
                pkt_dport = packet[TCP].dport
            elif protocol == "UDP" and UDP in packet:
                pkt_sport = packet[UDP].sport
                pkt_dport = packet[UDP].dport
            else:
                continue
            
            # Check if client -> server or server -> client
            is_client = (pkt_src == src_ip and pkt_sport == src_port)
            
            # Set color
            fmt = QTextCharFormat()
            if is_client:
                fmt.setForeground(self.CLIENT_COLOR)
            else:
                fmt.setForeground(self.SERVER_COLOR)
            
            cursor.setCharFormat(fmt)
            
            # Format payload based on view mode
            if view_mode == "ASCII":
                text = self.payload_to_ascii(payload)
            elif view_mode == "Hex":
                text = self.payload_to_hex(payload)
            else:  # Raw
                text = self.payload_to_raw(payload)
            
            cursor.insertText(text)
        
        self.stream_text.setTextCursor(cursor)
        self.stream_text.moveCursor(QTextCursor.Start)
    
    def packet_in_stream(self, packet):
        """Check if packet belongs to this stream."""
        src_ip, dst_ip, src_port, dst_port, protocol = self.stream_key
        
        if IP not in packet:
            return False
        
        pkt_src = packet[IP].src
        pkt_dst = packet[IP].dst
        
        if protocol == "TCP" and TCP in packet:
            pkt_sport = packet[TCP].sport
            pkt_dport = packet[TCP].dport
        elif protocol == "UDP" and UDP in packet:
            pkt_sport = packet[UDP].sport
            pkt_dport = packet[UDP].dport
        else:
            return False
        
        # Check both directions
        forward = (pkt_src == src_ip and pkt_dst == dst_ip and 
                   pkt_sport == src_port and pkt_dport == dst_port)
        reverse = (pkt_src == dst_ip and pkt_dst == src_ip and 
                   pkt_sport == dst_port and pkt_dport == src_port)
        
        return forward or reverse
    
    def payload_to_ascii(self, payload):
        """Convert payload to ASCII representation."""
        result = ""
        for byte in payload:
            if 32 <= byte < 127:
                result += chr(byte)
            elif byte == 10:  # newline
                result += '\n'
            elif byte == 13:  # carriage return
                pass  # skip
            elif byte == 9:  # tab
                result += '\t'
            else:
                result += '.'
        return result
    
    def payload_to_hex(self, payload):
        """Convert payload to hex representation."""
        lines = []
        for i in range(0, len(payload), 16):
            chunk = payload[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{i:04x}  {hex_part:<48}  {ascii_part}')
        return '\n'.join(lines) + '\n'
    
    def payload_to_raw(self, payload):
        """Convert payload to raw bytes representation."""
        return payload.decode('utf-8', errors='replace')
