# -*- coding: utf-8 -*-

from PyQt5.QtCore import Qt, QSortFilterProxyModel
import re


class PacketFilterModel(QSortFilterProxyModel):
    """
    Proxy model for filtering packet table.
    
    Supported filter syntax:
        - Protocol: tcp, udp, icmp, arp
        - IP filters: ip.src==192.168.1.1, ip.dst==10.0.0.1
        - Port filters: port==80, tcp.port==443, udp.port==53
        - Combined: tcp and port==80
        - Text search: any text to search in all columns
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.filter_expression = ""
        self.filter_tokens = []
    
    def set_filter(self, expression):
        """Set the filter expression and invalidate the filter."""
        self.filter_expression = expression.strip().lower()
        self.filter_tokens = self.parse_expression(self.filter_expression)
        self.invalidateFilter()
    
    def parse_expression(self, expression):
        """Parse filter expression into tokens."""
        if not expression:
            return []
        
        tokens = []
        
        # Split by 'and' / 'or' but keep them
        parts = re.split(r'\s+(and|or)\s+', expression)
        
        for part in parts:
            part = part.strip()
            if part in ('and', 'or'):
                tokens.append(('operator', part))
            elif part:
                tokens.append(self.parse_token(part))
        
        return tokens
    
    def parse_token(self, token):
        """Parse a single filter token."""
        token = token.strip()
        
        # Protocol filters
        if token in ('tcp', 'udp', 'icmp', 'arp'):
            return ('protocol', token.upper())
        
        # IP source filter: ip.src==x.x.x.x
        match = re.match(r'ip\.src\s*[=:]+\s*(.+)', token)
        if match:
            return ('ip_src', match.group(1).strip())
        
        # IP destination filter: ip.dst==x.x.x.x
        match = re.match(r'ip\.dst\s*[=:]+\s*(.+)', token)
        if match:
            return ('ip_dst', match.group(1).strip())
        
        # IP filter (any): ip==x.x.x.x
        match = re.match(r'ip\s*[=:]+\s*(.+)', token)
        if match:
            return ('ip_any', match.group(1).strip())
        
        # TCP port filter: tcp.port==xxx
        match = re.match(r'tcp\.port\s*[=:]+\s*(\d+)', token)
        if match:
            return ('tcp_port', int(match.group(1)))
        
        # UDP port filter: udp.port==xxx
        match = re.match(r'udp\.port\s*[=:]+\s*(\d+)', token)
        if match:
            return ('udp_port', int(match.group(1)))
        
        # Generic port filter: port==xxx
        match = re.match(r'port\s*[=:]+\s*(\d+)', token)
        if match:
            return ('port', int(match.group(1)))
        
        # Text search (fallback)
        return ('text', token)
    
    def filterAcceptsRow(self, source_row, source_parent):
        """Determine if row should be shown based on filter."""
        if not self.filter_tokens:
            return True
        
        model = self.sourceModel()
        if not model:
            return True
        
        # Get row data
        # Columns: No., Time, Source, Destination, Protocol, Length, Info
        row_data = []
        for col in range(model.columnCount()):
            index = model.index(source_row, col, source_parent)
            row_data.append(str(model.data(index, Qt.DisplayRole) or "").lower())
        
        # Evaluate filter
        return self.evaluate_filter(row_data)
    
    def evaluate_filter(self, row_data):
        """Evaluate filter expression against row data."""
        if not self.filter_tokens:
            return True
        
        # Simple evaluation without complex boolean logic
        # For now, treat all as AND
        results = []
        
        for token_type, token_value in self.filter_tokens:
            if token_type == 'operator':
                continue
            
            result = self.evaluate_token(token_type, token_value, row_data)
            results.append(result)
        
        # Check for OR operator
        has_or = any(t[0] == 'operator' and t[1] == 'or' for t in self.filter_tokens)
        
        if has_or:
            return any(results)
        else:
            return all(results)
    
    def evaluate_token(self, token_type, token_value, row_data):
        """Evaluate a single token against row data."""
        # Columns: 0=No., 1=Time, 2=Source, 3=Destination, 4=Protocol, 5=Length, 6=Info
        
        if token_type == 'protocol':
            return row_data[4] == token_value.lower()
        
        elif token_type == 'ip_src':
            return token_value in row_data[2]
        
        elif token_type == 'ip_dst':
            return token_value in row_data[3]
        
        elif token_type == 'ip_any':
            return token_value in row_data[2] or token_value in row_data[3]
        
        elif token_type == 'port':
            # Check in Info column for port numbers
            port_str = str(token_value)
            return port_str in row_data[6]
        
        elif token_type == 'tcp_port':
            if row_data[4] != 'tcp':
                return False
            port_str = str(token_value)
            return port_str in row_data[6]
        
        elif token_type == 'udp_port':
            if row_data[4] != 'udp':
                return False
            port_str = str(token_value)
            return port_str in row_data[6]
        
        elif token_type == 'text':
            # Search in all columns
            return any(token_value in cell for cell in row_data)
        
        return True
