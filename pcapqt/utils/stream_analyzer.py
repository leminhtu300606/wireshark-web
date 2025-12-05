# -*- coding: utf-8 -*-

from scapy.all import TCP, UDP, IP


class StreamAnalyzer:
    """Utility class for analyzing TCP/UDP streams."""
    
    @staticmethod
    def get_stream_key(packet):
        """
        Get stream identifier for a packet.
        Returns tuple (src_ip, dst_ip, src_port, dst_port, protocol) or None.
        """
        if IP not in packet:
            return None
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
        else:
            return None
        
        # Normalize: always put lower IP first for consistent key
        if (src_ip, src_port) > (dst_ip, dst_port):
            return (dst_ip, src_ip, dst_port, src_port, protocol)
        return (src_ip, dst_ip, src_port, dst_port, protocol)
    
    @staticmethod
    def get_stream_key_for_packet(packet):
        """
        Get stream key maintaining original direction for the first packet.
        Used when following from a specific packet.
        """
        if IP not in packet:
            return None
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
        else:
            return None
        
        return (src_ip, dst_ip, src_port, dst_port, protocol)
    
    @staticmethod
    def filter_stream_packets(packets, stream_key):
        """
        Filter packets belonging to a specific stream.
        
        Args:
            packets: List of all captured packets
            stream_key: Tuple (src_ip, dst_ip, src_port, dst_port, protocol)
        
        Returns:
            List of packets in the stream
        """
        src_ip, dst_ip, src_port, dst_port, protocol = stream_key
        stream_packets = []
        
        for packet in packets:
            if IP not in packet:
                continue
            
            pkt_src = packet[IP].src
            pkt_dst = packet[IP].dst
            
            if protocol == "TCP" and TCP in packet:
                pkt_sport = packet[TCP].sport
                pkt_dport = packet[TCP].dport
            elif protocol == "UDP" and UDP in packet:
                pkt_sport = packet[UDP].sport
                pkt_dport = packet[UDP].dport
            else:
                continue
            
            # Check both directions
            forward = (pkt_src == src_ip and pkt_dst == dst_ip and 
                       pkt_sport == src_port and pkt_dport == dst_port)
            reverse = (pkt_src == dst_ip and pkt_dst == src_ip and 
                       pkt_sport == dst_port and pkt_dport == src_port)
            
            if forward or reverse:
                stream_packets.append(packet)
        
        return stream_packets
    
    @staticmethod
    def get_all_streams(packets):
        """
        Group all packets into streams.
        
        Returns:
            Dict mapping stream_key to list of packets
        """
        streams = {}
        
        for packet in packets:
            key = StreamAnalyzer.get_stream_key(packet)
            if key:
                if key not in streams:
                    streams[key] = []
                streams[key].append(packet)
        
        return streams
