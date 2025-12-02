# PcapQt

PcapQt is a Python-based packet capture and analysis application built with **PyQt5** for the user interface and **Scapy** as the backend for parsing network packets.  
It provides a lightweight, easy-to-use interface similar to Wireshark, allowing you to display, inspect, and analyze captured packets.

---

## ✨ Features

- 📡 Capture or read packets using **Scapy**
- 🖥️ Modern **PyQt5** GUI (Qt Designer `.ui` file included)
- 🔍 Packet table view with protocol, source, destination, timestamp, etc.
- 🧩 Detailed packet decoding for Ethernet, IP, TCP, UDP, ICMP, ARP, Raw data, and more
- 🎨 Icons and UI components included for a polished interface
- 🪟 Windows-friendly batch scripts for setup and execution

---

## 📦 Requirements

- **Python 3.11+**
- Dependencies (auto-installed via `pyproject.toml` / poetry):
  - `pyqt5`
  - `scapy`
  - `pyqt5-tools` (optional for people who want to design the gui)

---

## 🚀 Installation

### Using Poetry (recommended)

```bash
poetry install
poetry run python -m pcapqt

