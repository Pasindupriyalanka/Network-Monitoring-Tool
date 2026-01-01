#!/usr/bin/env python3
"""
Network Monitoring Tool
A comprehensive network monitoring application with GUI
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import subprocess
import platform
import time
import psutil
from datetime import datetime
import ipaddress
import queue

class NetworkMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Monitoring Tool")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        self.is_scanning = False
        self.is_monitoring = False
        self.monitor_thread = None
        self.scan_thread = None
        self.message_queue = queue.Queue()
        
        self.setup_ui()
        self.check_queue()
        
    def setup_ui(self):
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#2b2b2b', borderwidth=0)
        style.configure('TNotebook.Tab', background='#3c3c3c', foreground='white', padding=[20, 10])
        style.map('TNotebook.Tab', background=[('selected', '#0078d4')])
        
        # Main notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Network Discovery
        self.setup_discovery_tab(notebook)
        
        # Tab 2: Port Scanner
        self.setup_port_scanner_tab(notebook)
        
        # Tab 3: Network Statistics
        self.setup_statistics_tab(notebook)
        
        # Tab 4: Connection Monitor
        self.setup_connection_tab(notebook)
        
    def setup_discovery_tab(self, notebook):
        discovery_frame = tk.Frame(notebook, bg='#2b2b2b')
        notebook.add(discovery_frame, text="Network Discovery")
        
        # Control panel
        control_panel = tk.Frame(discovery_frame, bg='#2b2b2b')
        control_panel.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(control_panel, text="Network Range:", bg='#2b2b2b', fg='white', font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        
        self.network_entry = tk.Entry(control_panel, width=20, font=('Arial', 10))
        self.network_entry.pack(side=tk.LEFT, padx=5)
        self.network_entry.insert(0, self.get_default_network())
        
        self.scan_button = tk.Button(control_panel, text="Start Scan", command=self.start_network_scan,
                                     bg='#0078d4', fg='white', font=('Arial', 10, 'bold'),
                                     padx=20, pady=5, cursor='hand2')
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = tk.Button(control_panel, text="Stop Scan", command=self.stop_network_scan,
                                     bg='#d32f2f', fg='white', font=('Arial', 10, 'bold'),
                                     padx=20, pady=5, cursor='hand2', state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Results display
        results_frame = tk.Frame(discovery_frame, bg='#2b2b2b')
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Treeview for discovered devices
        columns = ('IP Address', 'Hostname', 'Status', 'MAC Address', 'Response Time')
        self.discovery_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.discovery_tree.heading(col, text=col)
            self.discovery_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.discovery_tree.yview)
        self.discovery_tree.configure(yscrollcommand=scrollbar.set)
        
        self.discovery_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def setup_port_scanner_tab(self, notebook):
        port_frame = tk.Frame(notebook, bg='#2b2b2b')
        notebook.add(port_frame, text="Port Scanner")
        
        # Control panel
        control_panel = tk.Frame(port_frame, bg='#2b2b2b')
        control_panel.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(control_panel, text="Target IP:", bg='#2b2b2b', fg='white', font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        
        self.target_ip_entry = tk.Entry(control_panel, width=20, font=('Arial', 10))
        self.target_ip_entry.pack(side=tk.LEFT, padx=5)
        self.target_ip_entry.insert(0, "127.0.0.1")
        
        tk.Label(control_panel, text="Port Range:", bg='#2b2b2b', fg='white', font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        
        self.port_start_entry = tk.Entry(control_panel, width=10, font=('Arial', 10))
        self.port_start_entry.pack(side=tk.LEFT, padx=5)
        self.port_start_entry.insert(0, "1")
        
        tk.Label(control_panel, text="-", bg='#2b2b2b', fg='white', font=('Arial', 10)).pack(side=tk.LEFT)
        
        self.port_end_entry = tk.Entry(control_panel, width=10, font=('Arial', 10))
        self.port_end_entry.pack(side=tk.LEFT, padx=5)
        self.port_end_entry.insert(0, "1000")
        
        self.port_scan_button = tk.Button(control_panel, text="Scan Ports", command=self.start_port_scan,
                                          bg='#0078d4', fg='white', font=('Arial', 10, 'bold'),
                                          padx=20, pady=5, cursor='hand2')
        self.port_scan_button.pack(side=tk.LEFT, padx=5)
        
        self.port_stop_button = tk.Button(control_panel, text="Stop", command=self.stop_port_scan,
                                          bg='#d32f2f', fg='white', font=('Arial', 10, 'bold'),
                                          padx=20, pady=5, cursor='hand2', state=tk.DISABLED)
        self.port_stop_button.pack(side=tk.LEFT, padx=5)
        
        # Results display
        results_frame = tk.Frame(port_frame, bg='#2b2b2b')
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ('Port', 'Status', 'Service', 'Protocol')
        self.port_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.port_tree.heading(col, text=col)
            self.port_tree.column(col, width=150)
        
        port_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.port_tree.yview)
        self.port_tree.configure(yscrollcommand=port_scrollbar.set)
        
        self.port_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        port_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def setup_statistics_tab(self, notebook):
        stats_frame = tk.Frame(notebook, bg='#2b2b2b')
        notebook.add(stats_frame, text="Network Statistics")
        
        # Control panel
        control_panel = tk.Frame(stats_frame, bg='#2b2b2b')
        control_panel.pack(fill=tk.X, padx=10, pady=10)
        
        self.monitor_button = tk.Button(control_panel, text="Start Monitoring", command=self.start_monitoring,
                                        bg='#0078d4', fg='white', font=('Arial', 10, 'bold'),
                                        padx=20, pady=5, cursor='hand2')
        self.monitor_button.pack(side=tk.LEFT, padx=5)
        
        self.monitor_stop_button = tk.Button(control_panel, text="Stop Monitoring", command=self.stop_monitoring,
                                             bg='#d32f2f', fg='white', font=('Arial', 10, 'bold'),
                                             padx=20, pady=5, cursor='hand2', state=tk.DISABLED)
        self.monitor_stop_button.pack(side=tk.LEFT, padx=5)
        
        # Statistics display
        stats_display = tk.Frame(stats_frame, bg='#2b2b2b')
        stats_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.stats_text = scrolledtext.ScrolledText(stats_display, bg='#1e1e1e', fg='#00ff00',
                                                     font=('Consolas', 10), wrap=tk.WORD)
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
    def setup_connection_tab(self, notebook):
        conn_frame = tk.Frame(notebook, bg='#2b2b2b')
        notebook.add(conn_frame, text="Active Connections")
        
        # Control panel
        control_panel = tk.Frame(conn_frame, bg='#2b2b2b')
        control_panel.pack(fill=tk.X, padx=10, pady=10)
        
        self.refresh_conn_button = tk.Button(control_panel, text="Refresh Connections", command=self.refresh_connections,
                                            bg='#0078d4', fg='white', font=('Arial', 10, 'bold'),
                                            padx=20, pady=5, cursor='hand2')
        self.refresh_conn_button.pack(side=tk.LEFT, padx=5)
        
        # Auto-refresh checkbox
        self.auto_refresh_var = tk.BooleanVar()
        auto_refresh_check = tk.Checkbutton(control_panel, text="Auto-refresh (5s)", variable=self.auto_refresh_var,
                                            bg='#2b2b2b', fg='white', selectcolor='#2b2b2b',
                                            font=('Arial', 10), command=self.toggle_auto_refresh)
        auto_refresh_check.pack(side=tk.LEFT, padx=10)
        
        # Connections display
        conn_display = tk.Frame(conn_frame, bg='#2b2b2b')
        conn_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ('Protocol', 'Local Address', 'Local Port', 'Remote Address', 'Remote Port', 'Status', 'PID')
        self.conn_tree = ttk.Treeview(conn_display, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.conn_tree.heading(col, text=col)
            self.conn_tree.column(col, width=120)
        
        conn_scrollbar = ttk.Scrollbar(conn_display, orient=tk.VERTICAL, command=self.conn_tree.yview)
        self.conn_tree.configure(yscrollcommand=conn_scrollbar.set)
        
        self.conn_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        conn_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Initial load
        self.refresh_connections()
        
    def get_default_network(self):
        """Get the default network range based on local IP"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            return str(network)
        except:
            return "192.168.1.0/24"
    
    def start_network_scan(self):
        if self.is_scanning:
            return
        
        network_range = self.network_entry.get()
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
        except ValueError:
            messagebox.showerror("Error", "Invalid network range format. Use CIDR notation (e.g., 192.168.1.0/24)")
            return
        
        self.is_scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Clear previous results
        for item in self.discovery_tree.get_children():
            self.discovery_tree.delete(item)
        
        self.scan_thread = threading.Thread(target=self.scan_network, args=(network,), daemon=True)
        self.scan_thread.start()
    
    def stop_network_scan(self):
        self.is_scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
    
    def scan_network(self, network):
        """Scan network for active hosts"""
        hosts = list(network.hosts())
        total = len(hosts)
        
        for idx, host in enumerate(hosts):
            if not self.is_scanning:
                break
            
            ip = str(host)
            start_time = time.time()
            
            # Ping the host
            if self.ping_host(ip):
                response_time = (time.time() - start_time) * 1000
                hostname = self.get_hostname(ip)
                mac = self.get_mac_address(ip)
                
                self.root.after(0, self.add_discovery_result, ip, hostname, "Online", mac, f"{response_time:.2f}ms")
            else:
                self.root.after(0, self.add_discovery_result, ip, "N/A", "Offline", "N/A", "N/A")
            
            # Update progress
            if (idx + 1) % 10 == 0:
                self.message_queue.put(("progress", f"Scanned {idx + 1}/{total} hosts"))
        
        self.root.after(0, self.stop_network_scan)
    
    def ping_host(self, ip):
        """Ping a host to check if it's online"""
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip],
                                      capture_output=True, timeout=2)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip],
                                      capture_output=True, timeout=2)
            return result.returncode == 0
        except:
            return False
    
    def get_hostname(self, ip):
        """Get hostname from IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "N/A"
    
    def get_mac_address(self, ip):
        """Get MAC address (requires ARP table)"""
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=2)
                lines = result.stdout.split('\n')
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=2)
                parts = result.stdout.split()
                if len(parts) >= 3:
                    return parts[2]
        except:
            pass
        return "N/A"
    
    def add_discovery_result(self, ip, hostname, status, mac, response_time):
        """Add a result to the discovery tree"""
        tag = 'online' if status == 'Online' else 'offline'
        self.discovery_tree.insert('', tk.END, values=(ip, hostname, status, mac, response_time), tags=(tag,))
        self.discovery_tree.tag_configure('online', foreground='#00ff00')
        self.discovery_tree.tag_configure('offline', foreground='#ff0000')
    
    def start_port_scan(self):
        if self.is_scanning:
            return
        
        target_ip = self.target_ip_entry.get()
        try:
            port_start = int(self.port_start_entry.get())
            port_end = int(self.port_end_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid port range")
            return
        
        if port_start > port_end or port_start < 1 or port_end > 65535:
            messagebox.showerror("Error", "Invalid port range (1-65535)")
            return
        
        self.is_scanning = True
        self.port_scan_button.config(state=tk.DISABLED)
        self.port_stop_button.config(state=tk.NORMAL)
        
        # Clear previous results
        for item in self.port_tree.get_children():
            self.port_tree.delete(item)
        
        self.scan_thread = threading.Thread(target=self.scan_ports, args=(target_ip, port_start, port_end), daemon=True)
        self.scan_thread.start()
    
    def stop_port_scan(self):
        self.is_scanning = False
        self.port_scan_button.config(state=tk.NORMAL)
        self.port_stop_button.config(state=tk.DISABLED)
    
    def scan_ports(self, target_ip, port_start, port_end):
        """Scan ports on target IP"""
        common_ports = {
            20: 'FTP Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Proxy'
        }
        
        for port in range(port_start, port_end + 1):
            if not self.is_scanning:
                break
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                
                if result == 0:
                    service = common_ports.get(port, 'Unknown')
                    self.root.after(0, self.add_port_result, port, 'Open', service, 'TCP')
                else:
                    self.root.after(0, self.add_port_result, port, 'Closed', 'N/A', 'TCP')
            except:
                self.root.after(0, self.add_port_result, port, 'Error', 'N/A', 'TCP')
        
        self.root.after(0, self.stop_port_scan)
    
    def add_port_result(self, port, status, service, protocol):
        """Add a port scan result"""
        tag = 'open' if status == 'Open' else 'closed'
        self.port_tree.insert('', tk.END, values=(port, status, service, protocol), tags=(tag,))
        self.port_tree.tag_configure('open', foreground='#00ff00')
        self.port_tree.tag_configure('closed', foreground='#ff0000')
    
    def start_monitoring(self):
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitor_button.config(state=tk.DISABLED)
        self.monitor_stop_button.config(state=tk.NORMAL)
        
        self.monitor_thread = threading.Thread(target=self.monitor_network_stats, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        self.is_monitoring = False
        self.monitor_button.config(state=tk.NORMAL)
        self.monitor_stop_button.config(state=tk.DISABLED)
    
    def monitor_network_stats(self):
        """Monitor network statistics"""
        prev_sent = 0
        prev_recv = 0
        
        while self.is_monitoring:
            try:
                net_io = psutil.net_io_counters()
                net_if_addrs = psutil.net_if_addrs()
                net_if_stats = psutil.net_if_stats()
                
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Calculate bandwidth
                bytes_sent = net_io.bytes_sent
                bytes_recv = net_io.bytes_recv
                
                sent_speed = (bytes_sent - prev_sent) / 1024 / 1024  # MB/s
                recv_speed = (bytes_recv - prev_recv) / 1024 / 1024  # MB/s
                
                prev_sent = bytes_sent
                prev_recv = bytes_recv
                
                stats_text = f"\n{'='*60}\n"
                stats_text += f"Network Statistics - {current_time}\n"
                stats_text += f"{'='*60}\n\n"
                
                stats_text += f"Total Bytes Sent: {self.format_bytes(bytes_sent)}\n"
                stats_text += f"Total Bytes Received: {self.format_bytes(bytes_recv)}\n"
                stats_text += f"Upload Speed: {sent_speed:.2f} MB/s\n"
                stats_text += f"Download Speed: {recv_speed:.2f} MB/s\n"
                stats_text += f"Packets Sent: {net_io.packets_sent:,}\n"
                stats_text += f"Packets Received: {net_io.packets_recv:,}\n"
                stats_text += f"Errors In: {net_io.errin:,}\n"
                stats_text += f"Errors Out: {net_io.errout:,}\n"
                stats_text += f"Dropped In: {net_io.dropin:,}\n"
                stats_text += f"Dropped Out: {net_io.dropout:,}\n\n"
                
                stats_text += f"{'='*60}\n"
                stats_text += "Network Interfaces:\n"
                stats_text += f"{'='*60}\n\n"
                
                for interface, addrs in net_if_addrs.items():
                    stats_text += f"Interface: {interface}\n"
                    if interface in net_if_stats:
                        stats = net_if_stats[interface]
                        stats_text += f"  Status: {'Up' if stats.isup else 'Down'}\n"
                        stats_text += f"  Speed: {stats.speed} Mbps\n"
                        stats_text += f"  MTU: {stats.mtu}\n"
                    
                    for addr in addrs:
                        stats_text += f"  {addr.family.name}: {addr.address}\n"
                        if addr.netmask:
                            stats_text += f"    Netmask: {addr.netmask}\n"
                        if addr.broadcast:
                            stats_text += f"    Broadcast: {addr.broadcast}\n"
                    stats_text += "\n"
                
                self.root.after(0, self.update_stats_display, stats_text)
                time.sleep(2)
                
            except Exception as e:
                self.root.after(0, self.update_stats_display, f"Error: {str(e)}\n")
                time.sleep(2)
    
    def format_bytes(self, bytes):
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024.0:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024.0
        return f"{bytes:.2f} PB"
    
    def update_stats_display(self, text):
        """Update statistics display"""
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(1.0, text)
        self.stats_text.see(tk.END)
    
    def refresh_connections(self):
        """Refresh active network connections"""
        # Clear previous results
        for item in self.conn_tree.get_children():
            self.conn_tree.delete(item)
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status:
                    protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                    local_addr = conn.laddr.ip if conn.laddr else 'N/A'
                    local_port = conn.laddr.port if conn.laddr else 'N/A'
                    remote_addr = conn.raddr.ip if conn.raddr else 'N/A'
                    remote_port = conn.raddr.port if conn.raddr else 'N/A'
                    status = conn.status
                    pid = conn.pid if conn.pid else 'N/A'
                    
                    self.conn_tree.insert('', tk.END, values=(
                        protocol, local_addr, local_port, remote_addr, remote_port, status, pid
                    ))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get connections: {str(e)}")
    
    def toggle_auto_refresh(self):
        """Toggle auto-refresh for connections"""
        if self.auto_refresh_var.get():
            self.auto_refresh_connections()
        else:
            if hasattr(self, 'auto_refresh_job'):
                self.root.after_cancel(self.auto_refresh_job)
    
    def auto_refresh_connections(self):
        """Auto-refresh connections every 5 seconds"""
        if self.auto_refresh_var.get():
            self.refresh_connections()
            self.auto_refresh_job = self.root.after(5000, self.auto_refresh_connections)
    
    def check_queue(self):
        """Check message queue for updates"""
        try:
            while True:
                msg_type, msg = self.message_queue.get_nowait()
                if msg_type == "progress":
                    # Could update a progress bar here
                    pass
        except queue.Empty:
            pass
        
        self.root.after(100, self.check_queue)

def main():
    root = tk.Tk()
    app = NetworkMonitor(root)
    root.mainloop()

if __name__ == "__main__":
    main()

