# -*- coding: utf-8 -*-

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
    QListWidget, QListWidgetItem, QPushButton, QFrame
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QIcon
import platform

try:
    from scapy.all import get_if_list, get_if_hwaddr, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Try to import Windows-specific interface info
try:
    from scapy.arch.windows import get_windows_if_list
    WINDOWS_IF_AVAILABLE = True
except ImportError:
    WINDOWS_IF_AVAILABLE = False


class InterfaceDialog(QDialog):
    """Dialog for selecting network interface before capture."""
    
    # Icons for interface types
    INTERFACE_ICONS = {
        'wifi': '📶',
        'wireless': '📶',
        'wi-fi': '📶',
        'ethernet': '🔌',
        'loopback': '🔄',
        'virtual': '💻',
        'vmware': '💻',
        'virtualbox': '💻',
        'bluetooth': '🔵',
        'default': '🌐'
    }
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_interface = None
        self.selected_friendly_name = None
        self.setup_ui()
        self.load_interfaces()
    
    def setup_ui(self):
        self.setWindowTitle("Select Capture Interface")
        self.setMinimumSize(550, 420)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Header
        header_label = QLabel("Select a network interface to capture packets:")
        header_label.setFont(QFont("Segoe UI", 10))
        layout.addWidget(header_label)
        
        # Interface list
        self.interface_list = QListWidget()
        self.interface_list.setFont(QFont("Segoe UI", 10))
        self.interface_list.setAlternatingRowColors(True)
        self.interface_list.setSpacing(2)
        self.interface_list.itemDoubleClicked.connect(self.accept)
        self.interface_list.itemSelectionChanged.connect(self.on_selection_changed)
        layout.addWidget(self.interface_list)
        
        # Info frame
        info_frame = QFrame()
        info_frame.setFrameStyle(QFrame.StyledPanel)
        info_layout = QVBoxLayout(info_frame)
        
        self.info_label = QLabel("Select an interface to see details")
        self.info_label.setFont(QFont("Segoe UI", 9))
        self.info_label.setWordWrap(True)
        info_layout.addWidget(self.info_label)
        
        layout.addWidget(info_frame)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.load_interfaces)
        button_layout.addWidget(self.refresh_btn)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)
        
        self.start_btn = QPushButton("Start Capture")
        self.start_btn.setEnabled(False)
        self.start_btn.setDefault(True)
        self.start_btn.clicked.connect(self.accept)
        button_layout.addWidget(self.start_btn)
        
        layout.addLayout(button_layout)
        
        # Store interface data
        self.interfaces_data = {}
    
    def get_interface_icon(self, name, description=""):
        """Get appropriate icon for interface type."""
        text = (name + " " + description).lower()
        
        for keyword, icon in self.INTERFACE_ICONS.items():
            if keyword in text:
                return icon
        return self.INTERFACE_ICONS['default']
    
    def load_interfaces(self):
        """Load available network interfaces with friendly names."""
        self.interface_list.clear()
        self.interfaces_data.clear()
        
        if not SCAPY_AVAILABLE:
            item = QListWidgetItem("⚠️ Scapy not available - using default interface")
            self.interface_list.addItem(item)
            return
        
        try:
            # On Windows, use get_windows_if_list for friendly names
            if platform.system() == 'Windows' and WINDOWS_IF_AVAILABLE:
                self._load_windows_interfaces()
            else:
                self._load_generic_interfaces()
            
            # Select first item by default
            if self.interface_list.count() > 0:
                self.interface_list.setCurrentRow(0)
                
        except Exception as e:
            item = QListWidgetItem(f"❌ Error loading interfaces: {e}")
            self.interface_list.addItem(item)
    
    def _load_windows_interfaces(self):
        """Load interfaces using Windows-specific API."""
        interfaces = get_windows_if_list()
        
        for iface in interfaces:
            # Get interface details
            name = iface.get('name', 'Unknown')
            description = iface.get('description', '')
            guid = iface.get('guid', '')
            mac = iface.get('mac', 'N/A')
            ips = iface.get('ips', [])
            
            # Use description as friendly name, fallback to name
            friendly_name = description if description else name
            
            # Get icon
            icon = self.get_interface_icon(friendly_name, description)
            
            # Create display text with icon and friendly name
            display_text = f"{icon}  {friendly_name}"
            
            # Add IP if available
            if ips:
                ipv4_ips = [ip for ip in ips if '.' in ip and not ip.startswith('169.254')]
                if ipv4_ips:
                    display_text += f"  ({ipv4_ips[0]})"
            
            item = QListWidgetItem(display_text)
            item.setData(Qt.UserRole, name)  # Store Scapy interface name
            item.setData(Qt.UserRole + 1, friendly_name)  # Store friendly name
            self.interface_list.addItem(item)
            
            self.interfaces_data[name] = {
                'name': name,
                'friendly_name': friendly_name,
                'description': description,
                'mac': mac,
                'ips': ips,
                'guid': guid
            }
    
    def _load_generic_interfaces(self):
        """Load interfaces using generic Scapy API."""
        interfaces = get_if_list()
        
        for iface in interfaces:
            try:
                mac = get_if_hwaddr(iface)
            except:
                mac = "N/A"
            
            # Try to make name more readable
            friendly_name = iface
            if '\\Device\\NPF_' in iface:
                friendly_name = iface.replace('\\Device\\NPF_', 'Interface ')
            
            icon = self.get_interface_icon(friendly_name)
            display_text = f"{icon}  {friendly_name}"
            
            if mac and mac != "N/A":
                display_text += f"  [{mac}]"
            
            item = QListWidgetItem(display_text)
            item.setData(Qt.UserRole, iface)
            item.setData(Qt.UserRole + 1, friendly_name)
            self.interface_list.addItem(item)
            
            self.interfaces_data[iface] = {
                'name': iface,
                'friendly_name': friendly_name,
                'mac': mac,
                'ips': []
            }
    
    def on_selection_changed(self):
        """Handle interface selection change."""
        current_item = self.interface_list.currentItem()
        if current_item:
            iface = current_item.data(Qt.UserRole)
            friendly_name = current_item.data(Qt.UserRole + 1)
            self.selected_interface = iface
            self.selected_friendly_name = friendly_name
            self.start_btn.setEnabled(True)
            
            if iface in self.interfaces_data:
                data = self.interfaces_data[iface]
                info_lines = [f"Name: {data.get('friendly_name', data['name'])}"]
                
                if data.get('mac') and data['mac'] != 'N/A':
                    info_lines.append(f"MAC: {data['mac']}")
                
                if data.get('ips'):
                    ip_str = ', '.join(data['ips'][:3])  # Show first 3 IPs
                    info_lines.append(f"IP: {ip_str}")
                
                if data.get('description'):
                    info_lines.append(f"Description: {data['description']}")
                
                self.info_label.setText('\n'.join(info_lines))
        else:
            self.start_btn.setEnabled(False)
            self.info_label.setText("Select an interface to see details")
    
    def get_selected_interface(self):
        """Return the selected interface name."""
        return self.selected_interface
    
    @staticmethod
    def get_interface(parent=None):
        """Static method to show dialog and return selected interface."""
        dialog = InterfaceDialog(parent)
        result = dialog.exec_()
        
        if result == QDialog.Accepted:
            return dialog.get_selected_interface()
        return None
