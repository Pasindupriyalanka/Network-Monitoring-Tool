# Network Monitoring Tool

A comprehensive Python-based network monitoring application with a modern GUI interface. This tool provides real-time network monitoring, device discovery, port scanning, and connection tracking capabilities.

## Features

### 1. Network Discovery
- Scan entire network ranges (CIDR notation)
- Discover active hosts on the network
- Display hostname, MAC address, and response time
- Real-time scanning with progress tracking

### 2. Port Scanner
- Scan specific IP addresses for open ports
- Customizable port range (1-65535)
- Service detection for common ports
- Real-time results display

### 3. Network Statistics
- Real-time bandwidth monitoring (upload/download speeds)
- Network interface information
- Packet statistics (sent, received, errors, dropped)
- Interface status and configuration details

### 4. Active Connections Monitor
- View all active network connections
- Display protocol, local/remote addresses and ports
- Connection status and process IDs
- Auto-refresh capability (every 5 seconds)

## Requirements

- Python 3.7 or higher
- tkinter (usually included with Python)
- psutil library

## Installation

1. Clone or download this repository

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the application:
```bash
python network_monitor.py
```

### Network Discovery
1. Enter a network range in CIDR notation (e.g., `192.168.1.0/24`)
2. Click "Start Scan" to begin network discovery
3. Results will appear in real-time showing online/offline hosts

### Port Scanner
1. Enter the target IP address
2. Specify the port range (start and end ports)
3. Click "Scan Ports" to begin scanning
4. Open ports will be highlighted in green

### Network Statistics
1. Click "Start Monitoring" to begin real-time statistics collection
2. View bandwidth usage, packet statistics, and interface information
3. Click "Stop Monitoring" to pause

### Active Connections
1. Click "Refresh Connections" to view current network connections
2. Enable "Auto-refresh" to automatically update every 5 seconds

## System Compatibility

- **Windows**: Fully supported
- **Linux**: Fully supported
- **macOS**: Fully supported

## Security Note

This tool is designed for network administration and monitoring purposes. Always ensure you have proper authorization before scanning networks or ports that you don't own or manage.

## License

This project is provided as-is for educational and network administration purposes.
