# Network Monitoring Tool

An extensive Python application for the monitoring of networks using a GUI interface. The application will allow the real-time monitoring of networks using the GUI application. It will also support discovery functions, port scanning techniques, as well as connection tracing.

## Features

### 1. Network Discovery
- Scan entire network ranges (CIDR notation)
- Find active hosts on the network
- Show hostname, MAC address, response time

- Real-time Scanning with Progress Tracking
### 2. Port Scanner
- Scan specified IP addresses for open ports
- Customizable port range (1-65535

- Service scan on common ports
- Live result displays
### 3. Network Statistics
Network
Real-time Bandwidth Measurement (Upload/Download Speeds)

- Network interface details
- Packet statistics: sent, received, errors, dropped
- Interface Status and Configuration Information
### 4. Active Connections Monitor
This device

- Show all active network connections

- Shows the display protocol, local and remote addresses, and ports
- Connection status and process IDs

- Auto-refresh feature (Every 5 seconds)

## Requirements

- python3.7+
tkinter (Typically Included with Python)
- psutil library

# Installation

1. Clone or download this repository
2. Installing required dependencies:
bash

pip install -r requirements.txt
```python
