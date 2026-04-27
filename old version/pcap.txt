#!/usr/bin/env python3
"""
NetHawk Pro - Part 1: Core Classes and Utilities
Advanced Network Packet Analyzer - Core Components

This file contains:
- Configuration management
- Database operations
- Basic packet capture classes
- Network discovery
- Threat intelligence
- Geolocation services
"""

import sys
import json
import os
import socket
import struct
import time
import csv
import threading
import subprocess
import ipaddress
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, deque
import sqlite3
import gzip
import pickle
import statistics
import concurrent.futures
import asyncio

# Third-party imports (install via pip)
try:
    from PyQt5.QtWidgets import *
    from PyQt5.QtCore import *
    from PyQt5.QtGui import *
except ImportError:
    print("Error: PyQt5 not installed. Run: pip install PyQt5")
    sys.exit(1)

try:
    import psutil
    import requests
    from scapy.all import sniff, get_if_list, get_if_addr, ARP, Ether, IP, TCP, UDP, ICMP
    from scapy.layers.inet import traceroute
except ImportError as e:
    print(f"Error: Missing required packages. Run: pip install psutil requests scapy")
    print(f"Missing: {e}")
    sys.exit(1)

# Configuration
CONFIG_FILE = 'nethawk_config.json'
DB_FILE = 'nethawk_packets.db'
MAX_PACKETS = 10000
REMOTE_AGENTS = {}

# Enhanced protocol colors with modern theme
PROTOCOL_COLORS = {
    'TCP': '#3498db',     # Blue
    'UDP': '#2ecc71',     # Green  
    'ICMP': '#f39c12',    # Orange
    'SIP': '#e74c3c',     # Red
    'HTTP': '#9b59b6',    # Purple
    'HTTPS': '#8e44ad',   # Dark Purple
    'DNS': '#16a085',     # Teal
    'SSH': '#34495e',     # Dark Blue-Gray
    'FTP': '#d35400',     # Dark Orange
    'SMTP': '#27ae60',    # Dark Green
    'Other': '#95a5a6'    # Gray
}

# QoS DSCP mappings (expanded)
DSCP_CLASSES = {
    0: ('Best Effort', 'BE', '#95a5a6'),
    46: ('Expedited Forwarding', 'EF', '#e74c3c'),
    34: ('Assured Forwarding 41', 'AF41', '#3498db'),
    26: ('Assured Forwarding 31', 'AF31', '#2ecc71'),
    18: ('Assured Forwarding 21', 'AF21', '#f39c12'),
    10: ('Assured Forwarding 11', 'AF11', '#9b59b6'),
    8: ('Class Selector 1', 'CS1', '#34495e'),
    16: ('Class Selector 2', 'CS2', '#16a085'),
    24: ('Class Selector 3', 'CS3', '#d35400'),
    32: ('Class Selector 4', 'CS4', '#27ae60'),
    40: ('Class Selector 5', 'CS5', '#8e44ad'),
    48: ('Class Selector 6', 'CS6', '#c0392b')
}

# Threat intelligence feeds (mock for demo)
THREAT_FEEDS = {
    'malware_domains': set(),
    'suspicious_ips': set(),
    'known_attacks': set()
}

def load_config():
    """Load configuration with enhanced defaults"""
    default = {
        'max_packets': MAX_PACKETS,
        'auto_scroll': True,
        'capture_interface': 'auto',
        'remote_agents': {},
        'ml_enabled': False,
        'threat_detection': True,
        'dark_mode': True,
        'update_interval': 1000,
        'export_format': 'csv',
        'geo_location': True,
        'bandwidth_monitoring': True
    }
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return {**default, **json.load(f)}
        except:
            pass
    return default

def save_config(config):
    """Save configuration"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    except:
        pass

class PacketDatabase:
    """SQLite database for packet storage and analysis"""
    
    def __init__(self, db_file=DB_FILE):
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                length INTEGER,
                qos_dscp INTEGER,
                flags TEXT,
                payload_hash TEXT,
                geo_src TEXT,
                geo_dst TEXT,
                threat_score REAL DEFAULT 0,
                raw_data BLOB
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_src_ip ON packets(src_ip)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_protocol ON packets(protocol)
        ''')
        
        conn.commit()
        conn.close()
    
    def insert_packet(self, packet_data):
        """Insert packet into database"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO packets (
                    timestamp, src_ip, dst_ip, src_port, dst_port,
                    protocol, length, qos_dscp, flags, payload_hash,
                    geo_src, geo_dst, threat_score, raw_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', packet_data)
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database insert error: {e}")
    
    def query_packets(self, filters=None, limit=1000):
        """Query packets with filters"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        query = "SELECT * FROM packets"
        params = []
        
        if filters:
            conditions = []
            if 'start_time' in filters:
                conditions.append("timestamp >= ?")
                params.append(filters['start_time'])
            if 'end_time' in filters:
                conditions.append("timestamp <= ?")
                params.append(filters['end_time'])
            if 'src_ip' in filters:
                conditions.append("src_ip = ?")
                params.append(filters['src_ip'])
            if 'protocol' in filters:
                conditions.append("protocol = ?")
                params.append(filters['protocol'])
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        query += f" ORDER BY timestamp DESC LIMIT {limit}"
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        
        return results

class NetworkDiscovery(QThread):
    """Network discovery and scanning thread"""
    
    host_discovered = pyqtSignal(dict)
    scan_progress = pyqtSignal(str, int)
    scan_complete = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        self.running = False
        self.target_networks = []
    
    def discover_networks(self, networks=None):
        """Start network discovery"""
        if networks:
            self.target_networks = networks
        else:
            self.target_networks = self.get_local_networks()
        
        self.running = True
        self.start()
    
    def get_local_networks(self):
        """Get local network ranges"""
        networks = []
        try:
            interfaces = psutil.net_if_addrs()
            for interface, addrs in interfaces.items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        try:
                            network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                            if not network.is_loopback and not network.is_link_local:
                                networks.append(str(network.network_address) + '/' + str(network.prefixlen))
                        except:
                            continue
        except Exception as e:
            print(f"Network discovery error: {e}")
        
        return networks
    
    def run(self):
        """Main discovery loop"""
        total_hosts = 0
        for network in self.target_networks:
            try:
                net = ipaddress.IPv4Network(network)
                total_hosts += len(list(net.hosts()))
            except:
                continue
        
        current_host = 0
        
        for network in self.target_networks:
            if not self.running:
                break
                
            try:
                self.scan_network(network, current_host, total_hosts)
            except Exception as e:
                print(f"Network scan error: {e}")
        
        self.scan_complete.emit()
    
    def scan_network(self, network, start_host, total_hosts):
        """Scan a network for active hosts"""
        try:
            net = ipaddress.IPv4Network(network)
            self.scan_progress.emit(f"Scanning {network}", 0)
            
            # Use concurrent scanning for better performance
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = []
                
                for i, host in enumerate(net.hosts()):
                    if not self.running:
                        break
                    
                    future = executor.submit(self.scan_host, str(host))
                    futures.append(future)
                    
                    # Update progress
                    progress = int((start_host + i) / total_hosts * 100) if total_hosts > 0 else 0
                    self.scan_progress.emit(f"Scanning {host}", progress)
                
                # Collect results
                for future in concurrent.futures.as_completed(futures):
                    if not self.running:
                        break
                    
                    try:
                        result = future.result(timeout=1)
                        if result:
                            self.host_discovered.emit(result)
                    except:
                        continue
                        
        except Exception as e:
            print(f"Network scan error: {e}")
    
    def scan_host(self, host_ip):
        """Scan individual host"""
        try:
            # Ping test
            if sys.platform == "win32":
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', host_ip], 
                                      capture_output=True, text=True, timeout=2)
                alive = result.returncode == 0
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', host_ip], 
                                      capture_output=True, text=True, timeout=2)
                alive = result.returncode == 0
            
            if alive:
                host_info = {
                    'ip': host_ip,
                    'status': 'alive',
                    'hostname': self.get_hostname(host_ip),
                    'mac_address': self.get_mac_address(host_ip),
                    'open_ports': self.scan_common_ports(host_ip),
                    'os_guess': 'Unknown',
                    'services': []
                }
                
                return host_info
                
        except Exception as e:
            pass
        
        return None
    
    def get_hostname(self, ip):
        """Get hostname for IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return 'Unknown'
    
    def get_mac_address(self, ip):
        """Get MAC address for IP (ARP lookup)"""
        try:
            # Send ARP request
            arp_request = ARP(pdst=ip)
            ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether_frame / arp_request
            
            # This would normally require scapy's srp function
            # For now, return placeholder
            return "Unknown"
        except:
            return "Unknown"
    
    def scan_common_ports(self, ip):
        """Scan common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 5060, 8080]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    service = self.identify_service(port)
                    open_ports.append({'port': port, 'service': service})
                    
            except:
                continue
        
        return open_ports
    
    def identify_service(self, port):
        """Identify service by port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            5060: 'SIP', 8080: 'HTTP-Alt'
        }
        return services.get(port, 'Unknown')
    
    def stop_discovery(self):
        """Stop discovery"""
        self.running = False

class UnprivilegedCapture(QThread):
    """Non-privileged packet capture using multiple methods"""
    
    packet_received = pyqtSignal(dict)
    status_changed = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.running = False
        self.packet_count = 0
        self.capture_methods = []
        self.selected_interface = None
    
    def get_available_interfaces(self):
        """Get available network interfaces"""
        try:
            interfaces = []
            
            # Use psutil to get interface info
            net_if = psutil.net_if_addrs()
            net_stats = psutil.net_if_stats()
            
            for interface, addrs in net_if.items():
                if interface in net_stats and net_stats[interface].isup:
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            interfaces.append({
                                'name': interface,
                                'ip': addr.address,
                                'netmask': addr.netmask,
                                'description': f"{interface} ({addr.address})"
                            })
                            break
            
            return interfaces
        except Exception as e:
            print(f"Interface enumeration error: {e}")
            return []
    
    def start_capture(self, interface=None, methods=['scapy', 'socket_monitor']):
        """Start packet capture using specified methods"""
        self.selected_interface = interface
        self.capture_methods = methods
        self.running = True
        self.start()
    
    def run(self):
        """Main capture loop"""
        try:
            if 'scapy' in self.capture_methods:
                self.status_changed.emit("Starting Scapy capture...")
                self.scapy_capture()
            elif 'socket_monitor' in self.capture_methods:
                self.status_changed.emit("Starting socket monitoring...")
                self.socket_monitor()
            elif 'process_monitor' in self.capture_methods:
                self.status_changed.emit("Starting process monitoring...")
                self.process_monitor()
                
        except Exception as e:
            self.error_occurred.emit(f"Capture failed: {str(e)}")
    
    def scapy_capture(self):
        """Capture packets using Scapy (most reliable unprivileged method)"""
        try:
            def packet_handler(packet):
                if not self.running:
                    return
                
                try:
                    packet_info = self.parse_scapy_packet(packet)
                    if packet_info:
                        self.packet_count += 1
                        packet_info['no'] = self.packet_count
                        packet_info['timestamp'] = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                        self.packet_received.emit(packet_info)
                except Exception as e:
                    print(f"Packet parsing error: {e}")
            
            # Start sniffing (Scapy handles privileges automatically)
            interface = self.selected_interface if self.selected_interface else None
            self.status_changed.emit("Scapy capture active...")
            
            sniff(iface=interface, prn=packet_handler, stop_filter=lambda x: not self.running)
            
        except Exception as e:
            self.error_occurred.emit(f"Scapy capture failed: {str(e)}")
    
    def socket_monitor(self):
        """Monitor network connections using socket information"""
        try:
            self.status_changed.emit("Socket monitoring active...")
            
            last_connections = set()
            
            while self.running:
                try:
                    connections = psutil.net_connections(kind='all')
                    current_connections = set()
                    
                    for conn in connections:
                        if conn.status in ['ESTABLISHED', 'LISTEN']:
                            conn_key = (
                                conn.laddr.ip if conn.laddr else '',
                                conn.laddr.port if conn.laddr else 0,
                                conn.raddr.ip if conn.raddr else '',
                                conn.raddr.port if conn.raddr else 0,
                                conn.type.name if hasattr(conn.type, 'name') else str(conn.type)
                            )
                            current_connections.add(conn_key)
                            
                            if conn_key not in last_connections:
                                # New connection detected
                                packet_info = self.create_connection_packet(conn)
                                if packet_info:
                                    self.packet_count += 1
                                    packet_info['no'] = self.packet_count
                                    packet_info['timestamp'] = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                                    self.packet_received.emit(packet_info)
                    
                    last_connections = current_connections
                    time.sleep(0.5)  # Check every 500ms
                    
                except Exception as e:
                    print(f"Socket monitoring error: {e}")
                    time.sleep(1)
                    
        except Exception as e:
            self.error_occurred.emit(f"Socket monitoring failed: {str(e)}")
    
    def process_monitor(self):
        """Monitor process network activity"""
        try:
            self.status_changed.emit("Process monitoring active...")
            
            while self.running:
                try:
                    for proc in psutil.process_iter(['pid', 'name', 'connections']):
                        if not self.running:
                            break
                        
                        try:
                            connections = proc.info['connections']
                            if connections:
                                for conn in connections:
                                    packet_info = self.create_process_packet(proc.info, conn)
                                    if packet_info:
                                        self.packet_count += 1
                                        packet_info['no'] = self.packet_count
                                        packet_info['timestamp'] = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                                        self.packet_received.emit(packet_info)
                        except:
                            continue
                    
                    time.sleep(2)  # Check every 2 seconds
                    
                except Exception as e:
                    print(f"Process monitoring error: {e}")
                    time.sleep(1)
                    
        except Exception as e:
            self.error_occurred.emit(f"Process monitoring failed: {str(e)}")
    
    def parse_scapy_packet(self, packet):
        """Parse Scapy packet object"""
        try:
            packet_info = {
                'length': len(packet),
                'protocol': 'Unknown',
                'src': 'Unknown',
                'dst': 'Unknown',
                'sport': 0,
                'dport': 0,
                'qos_dscp': 0,
                'qos_name': 'BE',
                'info': '',
                'flags': '',
                'threat_score': 0
            }
            
            # IP Layer
            if packet.haslayer(IP):
                ip = packet[IP]
                packet_info['src'] = ip.src
                packet_info['dst'] = ip.dst
                packet_info['qos_dscp'] = (ip.tos >> 2) & 0x3F
                packet_info['qos_name'] = DSCP_CLASSES.get(packet_info['qos_dscp'], ('Unknown', 'UK', '#95a5a6'))[1]
            
            # Transport Layer
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                packet_info['protocol'] = 'TCP'
                packet_info['sport'] = tcp.sport
                packet_info['dport'] = tcp.dport
                
                # TCP Flags
                flags = []
                if tcp.flags.F: flags.append('FIN')
                if tcp.flags.S: flags.append('SYN')
                if tcp.flags.R: flags.append('RST')
                if tcp.flags.P: flags.append('PSH')
                if tcp.flags.A: flags.append('ACK')
                if tcp.flags.U: flags.append('URG')
                packet_info['flags'] = ','.join(flags)
                
                # Application Protocol Detection
                app_protocol = self.detect_application_protocol(tcp.sport, tcp.dport, packet)
                packet_info['protocol'] = app_protocol
                packet_info['info'] = f"TCP [{packet_info['flags']}] {tcp.sport} → {tcp.dport}"
                
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                packet_info['protocol'] = 'UDP'
                packet_info['sport'] = udp.sport
                packet_info['dport'] = udp.dport
                
                app_protocol = self.detect_application_protocol(udp.sport, udp.dport, packet)
                packet_info['protocol'] = app_protocol
                packet_info['info'] = f"UDP {udp.sport} → {udp.dport}"
                
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                packet_info['protocol'] = 'ICMP'
                packet_info['info'] = f"ICMP Type {icmp.type}"
            
            # Threat Analysis
            packet_info['threat_score'] = self.calculate_threat_score(packet_info)
            
            return packet_info
            
        except Exception as e:
            print(f"Scapy packet parse error: {e}")
            return None
    
    def detect_application_protocol(self, sport, dport, packet):
        """Enhanced application protocol detection"""
        # Well-known ports
        port_protocols = {
            80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH',
            21: 'FTP', 25: 'SMTP', 110: 'POP3', 143: 'IMAP',
            5060: 'SIP', 5061: 'SIP-TLS', 8080: 'HTTP-Alt',
            3389: 'RDP', 1723: 'PPTP', 1701: 'L2TP'
        }
        
        # Check both source and destination ports
        if sport in port_protocols:
            return port_protocols[sport]
        if dport in port_protocols:
            return port_protocols[dport]
        
        # Deep packet inspection for HTTP
        if packet.haslayer('Raw'):
            payload = packet['Raw'].load
            if payload:
                payload_str = payload.decode('utf-8', errors='ignore')
                if any(method in payload_str[:50] for method in ['GET ', 'POST ', 'HTTP/']):
                    return 'HTTP'
                elif 'SIP/2.0' in payload_str[:100]:
                    return 'SIP'
        
        # Default to transport protocol
        if packet.haslayer(TCP):
            return 'TCP'
        elif packet.haslayer(UDP):
            return 'UDP'
        
        return 'Unknown'
    
    def create_connection_packet(self, conn):
        """Create packet info from connection"""
        try:
            if not conn.laddr or not conn.raddr:
                return None
            
            packet_info = {
                'src': conn.laddr.ip,
                'dst': conn.raddr.ip,
                'sport': conn.laddr.port,
                'dport': conn.raddr.port,
                'protocol': conn.type.name if hasattr(conn.type, 'name') else 'TCP',
                'length': 0,  # Unknown for connection monitoring
                'qos_dscp': 0,
                'qos_name': 'BE',
                'info': f"Connection {conn.status}",
                'flags': conn.status,
                'threat_score': 0
            }
            
            return packet_info
            
        except Exception as e:
            print(f"Connection packet creation error: {e}")
            return None
    
    def create_process_packet(self, proc_info, conn):
        """Create packet info from process connection"""
        try:
            if not hasattr(conn, 'laddr') or not hasattr(conn, 'raddr'):
                return None
            if not conn.laddr or not conn.raddr:
                return None
            
            packet_info = {
                'src': conn.laddr.ip,
                'dst': conn.raddr.ip,
                'sport': conn.laddr.port,
                'dport': conn.raddr.port,
                'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                'length': 0,
                'qos_dscp': 0,
                'qos_name': 'BE',
                'info': f"Process: {proc_info['name']} (PID: {proc_info['pid']})",
                'flags': conn.status if hasattr(conn, 'status') else 'UNKNOWN',
                'threat_score': 0,
                'process_name': proc_info['name'],
                'process_pid': proc_info['pid']
            }
            
            return packet_info
            
        except Exception as e:
            print(f"Process packet creation error: {e}")
            return None
    
    def calculate_threat_score(self, packet_info):
        """Calculate threat score for packet"""
        score = 0
        
        # Check against threat feeds
        if packet_info['src'] in THREAT_FEEDS['suspicious_ips']:
            score += 50
        if packet_info['dst'] in THREAT_FEEDS['suspicious_ips']:
            score += 50
        
        # Suspicious ports
        suspicious_ports = [1337, 31337, 12345, 54321, 6667, 6668, 6669]
        if packet_info['sport'] in suspicious_ports or packet_info['dport'] in suspicious_ports:
            score += 30
        
        # High ports to low ports (potential backdoor)
        if packet_info['sport'] > 49152 and packet_info['dport'] < 1024:
            score += 10
        
        return min(score, 100)  # Cap at 100
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False

class RemoteAgent:
    """Remote capture agent for distributed monitoring"""
    
    def __init__(self, host, port=9999, auth_key=None):
        self.host = host
        self.port = port
        self.auth_key = auth_key
        self.connected = False
    
    def connect(self):
        """Connect to remote agent"""
        try:
            # This would implement actual remote connection
            # For demo purposes, simulate connection
            self.connected = True
            return True
        except:
            return False
    
    def start_remote_capture(self, filters=None):
        """Start capture on remote agent"""
        if not self.connected:
            return False
        
        # Send capture command to remote agent
        # Implementation would depend on protocol used
        return True
    
    def get_packets(self):
        """Retrieve packets from remote agent"""
        if not self.connected:
            return []
        
        # Retrieve and parse packets from remote agent
        return []
    
    def stop_capture(self):
        """Stop remote capture"""
        if self.connected:
            # Send stop command
            pass

class ThreatIntelligence(QThread):
    """Threat intelligence and anomaly detection"""
    
    threat_detected = pyqtSignal(dict)
    intel_updated = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.running = False
        self.ml_models = {}
        self.baseline_traffic = defaultdict(list)
    
    def start_monitoring(self):
        """Start threat monitoring"""
        self.running = True
        self.start()
    
    def run(self):
        """Main threat monitoring loop"""
        while self.running:
            try:
                # Update threat feeds
                self.update_threat_feeds()
                
                # Analyze traffic patterns
                self.analyze_traffic_patterns()
                
                # Check for anomalies
                self.detect_anomalies()
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.intel_updated.emit(f"Threat monitoring error: {e}")
    
    #!/usr/bin/env python3
"""
NetHawk Pro - Part 2: UI Components and Visualization (Fixed)
Advanced Network Packet Analyzer - UI Layer

This continues from Part 1 and contains:
- Completion of ThreatIntelligence class
- Modern packet table with filtering
- Real-time visualization components
- Geolocation services
- Context menus and user interactions

To run: Import this file after Part 1
"""

# Complete the ThreatIntelligence class methods from Part 1
def update_threat_feeds(self):
    """Update threat intelligence feeds"""
    try:
        # Simulate threat feed updates (in production, would fetch from real sources)
        sample_threats = [
            '192.168.1.100',  # Sample suspicious IPs
            '10.0.0.50',
            'malware.example.com'
        ]
        
        for threat in sample_threats:
            if '.' in threat and threat.count('.') == 3:
                THREAT_FEEDS['suspicious_ips'].add(threat)
            else:
                THREAT_FEEDS['malware_domains'].add(threat)
        
        self.intel_updated.emit("Threat feeds updated")
        
    except Exception as e:
        print(f"Threat feed update error: {e}")

def analyze_traffic_patterns(self):
    """Analyze traffic for patterns"""
    try:
        # Baseline traffic analysis
        current_time = time.time()
        
        # This would analyze actual packet data in production
        # For now, simulate pattern analysis
        
        # Check for unusual traffic spikes
        # Check for new communication patterns
        # Identify potential data exfiltration
        
    except Exception as e:
        print(f"Traffic pattern analysis error: {e}")

def detect_anomalies(self):
    """Detect traffic anomalies using ML"""
    try:
        # Simple anomaly detection based on traffic volume
        # In production, this would use proper ML models
        
        # Detect port scanning
        # Detect DDoS patterns
        # Detect unusual protocol usage
        # Detect geographic anomalies
        
        pass
        
    except Exception as e:
        print(f"Anomaly detection error: {e}")

def stop_monitoring(self):
    """Stop threat monitoring"""
    self.running = False

# Add these methods to ThreatIntelligence class from Part 1
ThreatIntelligence.update_threat_feeds = update_threat_feeds
ThreatIntelligence.analyze_traffic_patterns = analyze_traffic_patterns
ThreatIntelligence.detect_anomalies = detect_anomalies 
ThreatIntelligence.stop_monitoring = stop_monitoring

class GeoLocationService:
    """Geolocation service for IP addresses"""
    
    def __init__(self):
        self.cache = {}
        self.api_key = None  # Would be set from config
    
    def get_location(self, ip_address):
        """Get geographic location for IP address"""
        if ip_address in self.cache:
            return self.cache[ip_address]
        
        try:
            # Check if it's a private IP
            ip = ipaddress.ip_address(ip_address)
            if ip.is_private:
                location = {'country': 'Private', 'city': 'Local', 'lat': 0, 'lon': 0}
            else:
                # In production, use real geolocation API
                location = self.mock_geolocation(ip_address)
            
            self.cache[ip_address] = location
            return location
            
        except Exception as e:
            print(f"Geolocation error: {e}")
            return {'country': 'Unknown', 'city': 'Unknown', 'lat': 0, 'lon': 0}
    
    def mock_geolocation(self, ip_address):
        """Mock geolocation for demo"""
        # This would call actual geolocation service
        sample_locations = {
            'default': {'country': 'Unknown', 'city': 'Unknown', 'lat': 0, 'lon': 0},
            '8.8.8.8': {'country': 'USA', 'city': 'Mountain View', 'lat': 37.386, 'lon': -122.084},
            '1.1.1.1': {'country': 'USA', 'city': 'San Francisco', 'lat': 37.775, 'lon': -122.418}
        }
        
        return sample_locations.get(ip_address, sample_locations['default'])

class ModernPacketTable(QTableWidget):
    """Enhanced packet table with modern features"""
    
    packet_selected = pyqtSignal(dict)
    filter_changed = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.packets = []
        self.filtered_packets = []
        self.geo_service = GeoLocationService()
        self.setup_table()
        self.setup_context_menu()
        self.itemSelectionChanged.connect(self.on_selection)
    
    def setup_table(self):
        """Setup enhanced table with modern styling"""
        headers = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'QoS', 'Length', 'Geo', 'Threat', 'Info']
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        
        # Modern styling
        self.setStyleSheet("""
            QTableWidget {
                background-color: #2c3e50;
                color: white;
                gridline-color: #34495e;
                selection-background-color: #3498db;
            }
            QHeaderView::section {
                background-color: #34495e;
                color: white;
                border: 1px solid #2c3e50;
                padding: 8px;
                font-weight: bold;
            }
            QTableWidget::item:alternate {
                background-color: #354d65;
            }
        """)
        
        # Configure column sizing
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # No.
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Time
        header.setSectionResizeMode(2, QHeaderView.Stretch)           # Source
        header.setSectionResizeMode(3, QHeaderView.Stretch)           # Destination
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Protocol
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # QoS
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)  # Length
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)  # Geo
        header.setSectionResizeMode(8, QHeaderView.ResizeToContents)  # Threat
        header.setSectionResizeMode(9, QHeaderView.Stretch)           # Info
        
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSortingEnabled(True)
    
    def setup_context_menu(self):
        """Setup right-click context menu"""
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
    
    def show_context_menu(self, position):
        """Show context menu"""
        if self.itemAt(position):
            menu = QMenu(self)
            
            menu.addAction("Copy IP Address", self.copy_ip_address)
            menu.addAction("Whois Lookup", self.whois_lookup)
            menu.addAction("Trace Route", self.trace_route)
            menu.addSeparator()
            menu.addAction("Filter by Source", self.filter_by_source)
            menu.addAction("Filter by Destination", self.filter_by_dest)
            menu.addAction("Filter by Protocol", self.filter_by_protocol)
            menu.addSeparator()
            menu.addAction("Export Selected", self.export_selected)
            
            menu.exec_(self.mapToGlobal(position))
    
    def copy_ip_address(self):
        """Copy IP address to clipboard"""
        current_row = self.currentRow()
        if 0 <= current_row < len(self.filtered_packets):
            ip = self.filtered_packets[current_row]['src']
            QApplication.clipboard().setText(ip)
    
    def whois_lookup(self):
        """Perform whois lookup"""
        current_row = self.currentRow()
        if 0 <= current_row < len(self.filtered_packets):
            ip = self.filtered_packets[current_row]['src']
            # Would implement actual whois lookup
            QMessageBox.information(self, "Whois", f"Whois lookup for {ip}\n(Not implemented in demo)")
    
    def trace_route(self):
        """Perform trace route"""
        current_row = self.currentRow()
        if 0 <= current_row < len(self.filtered_packets):
            ip = self.filtered_packets[current_row]['dst']
            QMessageBox.information(self, "Trace Route", f"Trace route to {ip}\n(Not implemented in demo)")
    
    def filter_by_source(self):
        """Filter by source IP"""
        current_row = self.currentRow()
        if 0 <= current_row < len(self.filtered_packets):
            ip = self.filtered_packets[current_row]['src']
            self.filter_changed.emit(f"src:{ip}")
    
    def filter_by_dest(self):
        """Filter by destination IP"""
        current_row = self.currentRow()
        if 0 <= current_row < len(self.filtered_packets):
            ip = self.filtered_packets[current_row]['dst']
            self.filter_changed.emit(f"dst:{ip}")
    
    def filter_by_protocol(self):
        """Filter by protocol"""
        current_row = self.currentRow()
        if 0 <= current_row < len(self.filtered_packets):
            protocol = self.filtered_packets[current_row]['protocol']
            self.filter_changed.emit(f"protocol:{protocol}")
    
    def export_selected(self):
        """Export selected packets"""
        selected_rows = set(item.row() for item in self.selectedItems())
        if selected_rows:
            filename, _ = QFileDialog.getSaveFileName(self, 'Export Selected Packets', '', 'CSV Files (*.csv)')
            if filename:
                self.export_packets_to_csv(filename, selected_rows)
    
    def add_packet(self, packet_info):
        """Add new packet with enhanced info"""
        # Add geolocation
        src_geo = self.geo_service.get_location(packet_info['src'])
        dst_geo = self.geo_service.get_location(packet_info['dst'])
        packet_info['src_geo'] = src_geo
        packet_info['dst_geo'] = dst_geo
        packet_info['geo_display'] = f"{src_geo['country']} → {dst_geo['country']}"
        
        self.packets.append(packet_info)
        self.apply_current_filter()
        
    def apply_current_filter(self, filter_text=""):
        """Apply current filter and update display"""
        if not filter_text:
            self.filtered_packets = self.packets.copy()
        else:
            self.filtered_packets = self.filter_packets_advanced(filter_text)
        
        self.update_display()
    
    def filter_packets_advanced(self, filter_text):
        """Advanced packet filtering with multiple criteria"""
        if not filter_text:
            return self.packets.copy()
        
        filtered = []
        filter_lower = filter_text.lower()
        
        # Parse filter expression
        if ':' in filter_text:
            # Advanced filter format: src:192.168.1.1, protocol:HTTP, etc.
            filter_parts = filter_text.split(':', 1)
            filter_type = filter_parts[0].lower()
            filter_value = filter_parts[1].lower()
            
            for packet in self.packets:
                match = False
                
                if filter_type == 'src' and filter_value in packet['src'].lower():
                    match = True
                elif filter_type == 'dst' and filter_value in packet['dst'].lower():
                    match = True
                elif filter_type == 'protocol' and filter_value in packet['protocol'].lower():
                    match = True
                elif filter_type == 'port' and (str(packet.get('sport', '')) == filter_value or 
                                               str(packet.get('dport', '')) == filter_value):
                    match = True
                elif filter_type == 'threat':
                    try:
                        if '>' in filter_value:
                            threshold = float(filter_value.replace('>', ''))
                            if packet.get('threat_score', 0) > threshold:
                                match = True
                        else:
                            if packet.get('threat_score', 0) == float(filter_value):
                                match = True
                    except ValueError:
                        pass
                
                if match:
                    filtered.append(packet)
        else:
            # Simple text search
            for packet in self.packets:
                if (filter_lower in packet['src'].lower() or
                    filter_lower in packet['dst'].lower() or
                    filter_lower in packet['protocol'].lower() or
                    filter_lower in packet.get('info', '').lower()):
                    filtered.append(packet)
        
        return filtered
    
    def update_display(self):
        """Update table display with filtered packets"""
        self.setRowCount(len(self.filtered_packets))
        
        for row, packet_info in enumerate(self.filtered_packets):
            # No.
            self.setItem(row, 0, QTableWidgetItem(str(packet_info['no'])))
            
            # Time
            self.setItem(row, 1, QTableWidgetItem(packet_info['timestamp']))
            
            # Source
            self.setItem(row, 2, QTableWidgetItem(packet_info['src']))
            
            # Destination
            self.setItem(row, 3, QTableWidgetItem(packet_info['dst']))
            
            # Protocol with color
            protocol_item = QTableWidgetItem(packet_info['protocol'])
            color = QColor(PROTOCOL_COLORS.get(packet_info['protocol'], PROTOCOL_COLORS['Other']))
            protocol_item.setBackground(QBrush(color))
            self.setItem(row, 4, protocol_item)
            
            # QoS
            qos_item = QTableWidgetItem(packet_info.get('qos_name', 'BE'))
            qos_color = QColor(DSCP_CLASSES.get(packet_info.get('qos_dscp', 0), ('', '', '#95a5a6'))[2])
            qos_item.setBackground(QBrush(qos_color))
            self.setItem(row, 5, qos_item)
            
            # Length
            self.setItem(row, 6, QTableWidgetItem(str(packet_info['length'])))
            
            # Geo
            self.setItem(row, 7, QTableWidgetItem(packet_info.get('geo_display', 'Unknown')))
            
            # Threat Score
            threat_score = packet_info.get('threat_score', 0)
            threat_item = QTableWidgetItem(str(threat_score))
            if threat_score > 70:
                threat_item.setBackground(QBrush(QColor('#e74c3c')))  # Red
            elif threat_score > 40:
                threat_item.setBackground(QBrush(QColor('#f39c12')))  # Orange
            elif threat_score > 0:
                threat_item.setBackground(QBrush(QColor('#f1c40f')))  # Yellow
            self.setItem(row, 8, threat_item)
            
            # Info
            self.setItem(row, 9, QTableWidgetItem(packet_info.get('info', '')))
        
        # Auto-scroll to bottom
        self.scrollToBottom()
    
    def on_selection(self):
        """Handle packet selection"""
        current_row = self.currentRow()
        if 0 <= current_row < len(self.filtered_packets):
            self.packet_selected.emit(self.filtered_packets[current_row])
    
    def clear_all(self):
        """Clear all packets"""
        self.packets.clear()
        self.filtered_packets.clear()
        self.setRowCount(0)
    
    def export_packets_to_csv(self, filename, selected_rows=None):
        """Export packets to CSV"""
        try:
            packets_to_export = []
            
            if selected_rows:
                packets_to_export = [self.filtered_packets[row] for row in selected_rows 
                                   if row < len(self.filtered_packets)]
            else:
                packets_to_export = self.filtered_packets
            
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Header
                writer.writerow([
                    'No', 'Time', 'Source', 'Destination', 'Protocol', 
                    'QoS', 'Length', 'Geography', 'Threat_Score', 'Info'
                ])
                
                # Data
                for pkt in packets_to_export:
                    writer.writerow([
                        pkt['no'], pkt['timestamp'], pkt['src'], pkt['dst'],
                        pkt['protocol'], pkt.get('qos_name', 'BE'), 
                        pkt['length'], pkt.get('geo_display', ''), 
                        pkt.get('threat_score', 0), pkt.get('info', '')
                    ])
            
            return True
        except Exception as e:
            print(f"CSV export error: {e}")
            return False

# Import matplotlib for visualizations
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    import plotly.graph_objs as go
    import plotly.offline as pyo
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    print("Warning: Matplotlib/Plotly not available. Install with: pip install matplotlib seaborn plotly")
    MATPLOTLIB_AVAILABLE = False

class NetworkVisualization(QWidget):
    """Network visualization with graphs and charts"""
    
    def __init__(self):
        super().__init__()
        self.packet_data = []
        self.setup_ui()
        
        if MATPLOTLIB_AVAILABLE:
            self.update_timer = QTimer()
            self.update_timer.timeout.connect(self.update_charts)
            self.update_timer.start(2000)  # Update every 2 seconds
    
    def setup_ui(self):
        """Setup visualization UI"""
        layout = QVBoxLayout(self)
        
        if not MATPLOTLIB_AVAILABLE:
            # Show message if matplotlib is not available
            msg_label = QLabel("Real-time visualizations require matplotlib and plotly.\n"
                              "Install with: pip install matplotlib seaborn plotly")
            msg_label.setStyleSheet("color: #f39c12; font-size: 14px; padding: 20px;")
            msg_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(msg_label)
            return
        
        # Create matplotlib figure
        self.figure = Figure(figsize=(12, 8))
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)
        
        # Create subplots
        self.protocol_ax = self.figure.add_subplot(2, 2, 1)
        self.traffic_ax = self.figure.add_subplot(2, 2, 2)
        self.geo_ax = self.figure.add_subplot(2, 2, 3)
        self.threat_ax = self.figure.add_subplot(2, 2, 4)
        
        # Style the figure
        self.figure.patch.set_facecolor('#2c3e50')
        for ax in [self.protocol_ax, self.traffic_ax, self.geo_ax, self.threat_ax]:
            ax.set_facecolor('#34495e')
            ax.tick_params(colors='white')
            ax.xaxis.label.set_color('white')
            ax.yaxis.label.set_color('white')
            ax.title.set_color('white')
        
        self.canvas.draw()
    
    def add_packet_data(self, packet_info):
        """Add packet data for visualization"""
        if not MATPLOTLIB_AVAILABLE:
            return
            
        self.packet_data.append({
            'timestamp': datetime.now(),
            'protocol': packet_info['protocol'],
            'length': packet_info['length'],
            'src_country': packet_info.get('src_geo', {}).get('country', 'Unknown'),
            'dst_country': packet_info.get('dst_geo', {}).get('country', 'Unknown'),
            'threat_score': packet_info.get('threat_score', 0)
        })
        
        # Keep only last 1000 packets for performance
        if len(self.packet_data) > 1000:
            self.packet_data.pop(0)
    
    def update_charts(self):
        """Update all charts"""
        if not MATPLOTLIB_AVAILABLE or not self.packet_data:
            return
        
        try:
            self.update_protocol_chart()
            self.update_traffic_chart()
            self.update_geo_chart()
            self.update_threat_chart()
            self.canvas.draw()
        except Exception as e:
            print(f"Chart update error: {e}")
    
    def update_protocol_chart(self):
        """Update protocol distribution pie chart"""
        self.protocol_ax.clear()
        self.protocol_ax.set_facecolor('#34495e')
        
        # Count protocols
        protocol_counts = defaultdict(int)
        for packet in self.packet_data[-100:]:  # Last 100 packets
            protocol_counts[packet['protocol']] += 1
        
        if protocol_counts:
            protocols = list(protocol_counts.keys())
            counts = list(protocol_counts.values())
            colors = [PROTOCOL_COLORS.get(p, PROTOCOL_COLORS['Other']) for p in protocols]
            
            self.protocol_ax.pie(counts, labels=protocols, colors=colors, autopct='%1.1f%%')
            self.protocol_ax.set_title('Protocol Distribution', color='white')
    
    def update_traffic_chart(self):
        """Update traffic over time"""
        self.traffic_ax.clear()
        self.traffic_ax.set_facecolor('#34495e')
        
        if len(self.packet_data) < 2:
            return
        
        # Group by time intervals (every 10 seconds)
        time_buckets = defaultdict(int)
        time_bytes = defaultdict(int)
        
        now = datetime.now()
        for packet in self.packet_data[-200:]:  # Last 200 packets
            time_diff = (now - packet['timestamp']).total_seconds()
            bucket = int(time_diff / 10) * 10
            time_buckets[bucket] += 1
            time_bytes[bucket] += packet['length']
        
        if time_buckets:
            times = sorted(time_buckets.keys(), reverse=True)[:20]  # Last 20 intervals
            packet_counts = [time_buckets[t] for t in times]
            byte_counts = [time_bytes[t] / 1024 for t in times]  # Convert to KB
            
            times_display = [f"-{t}s" for t in times]
            
            self.traffic_ax.plot(times_display, packet_counts, 'b-', label='Packets', linewidth=2)
            self.traffic_ax.set_ylabel('Packets', color='#3498db')
            self.traffic_ax.tick_params(axis='y', labelcolor='#3498db')
            
            # Add bytes on secondary y-axis
            ax2 = self.traffic_ax.twinx()
            ax2.plot(times_display, byte_counts, 'r-', label='KB', linewidth=2)
            ax2.set_ylabel('KB', color='#e74c3c')
            ax2.tick_params(axis='y', labelcolor='#e74c3c')
            ax2.set_facecolor('#34495e')
            
            self.traffic_ax.set_title('Traffic Over Time', color='white')
            self.traffic_ax.tick_params(axis='x', rotation=45)
    
    def update_geo_chart(self):
        """Update geographic distribution"""
        self.geo_ax.clear()
        self.geo_ax.set_facecolor('#34495e')
        
        # Count countries
        country_counts = defaultdict(int)
        for packet in self.packet_data[-100:]:  # Last 100 packets
            src_country = packet['src_country']
            dst_country = packet['dst_country']
            if src_country != 'Unknown' and src_country != 'Private':
                country_counts[src_country] += 1
            if dst_country != 'Unknown' and dst_country != 'Private':
                country_counts[dst_country] += 1
        
        if country_counts:
            countries = list(country_counts.keys())[:10]  # Top 10
            counts = [country_counts[c] for c in countries]
            
            bars = self.geo_ax.bar(countries, counts, color='#2ecc71')
            self.geo_ax.set_title('Geographic Distribution', color='white')
            self.geo_ax.set_ylabel('Packets', color='white')
            
            # Rotate labels for better readability
            self.geo_ax.tick_params(axis='x', rotation=45)
    
    def update_threat_chart(self):
        """Update threat score distribution"""
        self.threat_ax.clear()
        self.threat_ax.set_facecolor('#34495e')
        
        # Get threat scores
        threat_scores = [packet['threat_score'] for packet in self.packet_data[-200:]]
        
        if threat_scores and max(threat_scores) > 0:
            # Create histogram
            bins = [0, 10, 25, 50, 75, 100]
            colors = ['#2ecc71', '#f1c40f', '#f39c12', '#e67e22', '#e74c3c']
            
            n, bins, patches = self.threat_ax.hist(threat_scores, bins=bins, color=colors, edgecolor='white')
            
            self.threat_ax.set_title('Threat Score Distribution', color='white')
            self.threat_ax.set_xlabel('Threat Score', color='white')
            self.threat_ax.set_ylabel('Count', color='white')
            
            # Color patches based on threat level
            for i, patch in enumerate(patches):
                if i < len(colors):
                    patch.set_facecolor(colors[i])

class PacketDetailsWidget(QTextBrowser):
    """Enhanced packet details viewer"""
    
    def __init__(self):
        super().__init__()
        self.setFont(QFont("Consolas", 10))
        self.setStyleSheet("""
            QTextBrowser {
                background-color: #2c3e50;
                color: white;
                border: 1px solid #34495e;
            }
        """)
        
    def show_packet_details(self, packet_info):
        """Display detailed packet information with enhanced formatting"""
        details_html = f"""
        <style>
        body {{ background-color: #2c3e50; color: white; font-family: Consolas, monospace; }}
        h3 {{ color: #3498db; border-bottom: 2px solid #3498db; padding-bottom: 5px; }}
        h4 {{ color: #2ecc71; margin-top: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        td {{ padding: 5px; border-bottom: 1px solid #34495e; }}
        .highlight {{ background-color: #34495e; }}
        .threat-high {{ color: #e74c3c; font-weight: bold; }}
        .threat-medium {{ color: #f39c12; font-weight: bold; }}
        .threat-low {{ color: #2ecc71; }}
        </style>
        
        <h3>Packet #{packet_info['no']} Analysis</h3>
        
        <h4>Network Information</h4>
        <table>
        <tr><td><b>Timestamp:</b></td><td>{packet_info['timestamp']}</td></tr>
        <tr class="highlight"><td><b>Source IP:</b></td><td>{packet_info['src']}</td></tr>
        <tr><td><b>Destination IP:</b></td><td>{packet_info['dst']}</td></tr>
        <tr class="highlight"><td><b>Protocol:</b></td><td>{packet_info['protocol']}</td></tr>
        <tr><td><b>Packet Length:</b></td><td>{packet_info['length']} bytes</td></tr>
        </table>
        
        <h4>Transport Layer Details</h4>
        <table>
        <tr><td><b>Source Port:</b></td><td>{packet_info.get('sport', 'N/A')}</td></tr>
        <tr class="highlight"><td><b>Destination Port:</b></td><td>{packet_info.get('dport', 'N/A')}</td></tr>
        <tr><td><b>TCP Flags:</b></td><td>{packet_info.get('flags', 'N/A')}</td></tr>
        </table>
        
        <h4>Quality of Service</h4>
        <table>
        <tr><td><b>DSCP Value:</b></td><td>{packet_info.get('qos_dscp', 0)}</td></tr>
        <tr class="highlight"><td><b>QoS Class:</b></td><td>{packet_info.get('qos_name', 'BE')}</td></tr>
        <tr><td><b>Priority:</b></td><td>{'High' if packet_info.get('qos_dscp', 0) > 0 else 'Normal'}</td></tr>
        </table>
        
        <h4>Geographic Analysis</h4>
        <table>
        <tr><td><b>Source Location:</b></td><td>{packet_info.get('src_geo', {}).get('country', 'Unknown')}, {packet_info.get('src_geo', {}).get('city', 'Unknown')}</td></tr>
        <tr class="highlight"><td><b>Destination Location:</b></td><td>{packet_info.get('dst_geo', {}).get('country', 'Unknown')}, {packet_info.get('dst_geo', {}).get('city', 'Unknown')}</td></tr>
        <tr><td><b>Geographic Path:</b></td><td>{packet_info.get('geo_display', 'Unknown')}</td></tr>
        </table>
        
        <h4>Security Assessment</h4>
        <table>
        <tr><td><b>Threat Score:</b></td><td class="{'threat-high' if packet_info.get('threat_score', 0) > 70 else 'threat-medium' if packet_info.get('threat_score', 0) > 30 else 'threat-low'}">{packet_info.get('threat_score', 0)}/100</td></tr>
        <tr class="highlight"><td><b>Risk Level:</b></td><td class="{'threat-high' if packet_info.get('threat_score', 0) > 70 else 'threat-medium' if packet_info.get('threat_score', 0) > 30 else 'threat-low'}">{'HIGH RISK' if packet_info.get('threat_score', 0) > 70 else 'MEDIUM RISK' if packet_info.get('threat_score', 0) > 30 else 'LOW RISK'}</td></tr>
        <tr><td><b>Suspicious Indicators:</b></td><td>{'Yes' if packet_info.get('threat_score', 0) > 50 else 'None detected'}</td></tr>
        </table>
        
        <h4>Additional Information</h4>
        <table>
        <tr><td><b>Process Name:</b></td><td>{packet_info.get('process_name', 'N/A')}</td></tr>
        <tr class="highlight"><td><b>Process ID:</b></td><td>{packet_info.get('process_pid', 'N/A')}</td></tr>
        <tr><td><b>Packet Info:</b></td><td>{packet_info.get('info', 'No additional info')}</td></tr>
        </table>
        
        <h4>Raw Data Summary</h4>
        <table>
        <tr><td><b>Capture Method:</b></td><td>NetHawk Pro Unprivileged Capture</td></tr>
        <tr class="highlight"><td><b>Analysis Time:</b></td><td>{datetime.now().strftime('%H:%M:%S')}</td></tr>
        <tr><td><b>Data Quality:</b></td><td>High</td></tr>
        </table>
        """
        
        self.setHtml(details_html)

class SIPCallFlow(QGraphicsView):
    """SIP call flow visualization widget"""
    
    def __init__(self):
        super().__init__()
        self.scene = QGraphicsScene()
        self.setScene(self.scene)
        self.setRenderHint(QPainter.Antialiasing)
        self.setStyleSheet("QGraphicsView { background-color: #2c3e50; }")
        
    def show_sip_flow(self, sip_packets):
        """Display SIP call flow diagram"""
        self.scene.clear()
        
        if not sip_packets:
            # Show placeholder text
            text_item = self.scene.addText("No SIP packets selected", QFont("Arial", 12))
            text_item.setDefaultTextColor(QColor("white"))
            text_item.setPos(50, 50)
            return
            
        # Find unique endpoints
        endpoints = set()
        for pkt in sip_packets:
            endpoints.add(pkt['src'])
            endpoints.add(pkt['dst'])
        
        endpoints = sorted(list(endpoints))
        if len(endpoints) < 2:
            text_item = self.scene.addText("Need at least 2 SIP endpoints", QFont("Arial", 12))
            text_item.setDefaultTextColor(QColor("white"))
            text_item.setPos(50, 50)
            return
        
        # Layout parameters
        spacing = 200
        start_y = 50
        msg_spacing = 40
        
        # Draw endpoints
        positions = {}
        for i, endpoint in enumerate(endpoints):
            x = i * spacing + 100
            positions[endpoint] = x
            
            # Endpoint header
            rect = QGraphicsRectItem(x-60, start_y, 120, 25)
            rect.setBrush(QBrush(QColor(52, 73, 94)))
            rect.setPen(QPen(QColor(52, 152, 219), 2))
            self.scene.addItem(rect)
            
            # Endpoint label
            text = self.scene.addText(endpoint, QFont("Arial", 9, QFont.Bold))
            text.setDefaultTextColor(QColor("white"))
            text.setPos(x - text.boundingRect().width()/2, start_y + 3)
            
            # Vertical timeline
            line_y = start_y + 25
            line = QGraphicsLineItem(x, line_y, x, line_y + len(sip_packets) * msg_spacing + 20)
            line.setPen(QPen(QColor(150, 150, 150), 1, Qt.DashLine))
            self.scene.addItem(line)
        
        # Draw SIP messages
        y = start_y + 50
        for pkt in sip_packets:
            if 'sip_info' not in pkt:
                continue
                
            src_x = positions.get(pkt['src'], positions[list(positions.keys())[0]])
            dst_x = positions.get(pkt['dst'], positions[list(positions.keys())[-1]])
            
            # Message arrow
            arrow = QGraphicsLineItem(src_x, y, dst_x, y)
            arrow.setPen(QPen(QColor(52, 152, 219), 2))
            self.scene.addItem(arrow)
            
            # Arrow head
            if src_x < dst_x:
                points = [QPointF(dst_x-8, y-4), QPointF(dst_x, y), QPointF(dst_x-8, y+4)]
            else:
                points = [QPointF(dst_x+8, y-4), QPointF(dst_x, y), QPointF(dst_x+8, y+4)]
                
            arrowhead = QGraphicsPolygonItem(QPolygonF(points))
            arrowhead.setBrush(QBrush(QColor(52, 152, 219)))
            self.scene.addItem(arrowhead)
            
            # Message label
            method = pkt['sip_info'].get('method', 'Unknown')
            label = self.scene.addText(method, QFont("Arial", 8))
            label.setDefaultTextColor(QColor("white"))
            label.setPos((src_x + dst_x)/2 - label.boundingRect().width()/2, y - 18)
            
            y += msg_spacing
        
        # Update scene bounds
        self.scene.setSceneRect(self.scene.itemsBoundingRect())

class StatisticsWidget(QWidget):
    """Statistics display widget"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.stats_data = defaultdict(int)
        
    def setup_ui(self):
        """Setup statistics UI"""
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Network Statistics")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #3498db; padding: 10px;")
        layout.addWidget(title)
        
        # Statistics table
        self.stats_table = QTableWidget()
        self.stats_table.setColumnCount(3)
        self.stats_table.setHorizontalHeaderLabels(['Metric', 'Value', 'Percentage'])
        self.stats_table.setStyleSheet("""
            QTableWidget {
                background-color: #34495e;
                color: white;
                gridline-color: #2c3e50;
            }
            QHeaderView::section {
                background-color: #2c3e50;
                color: white;
                font-weight: bold;
                padding: 5px;
            }
        """)
        layout.addWidget(self.stats_table)
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(5000)  # Update every 5 seconds
    
    def update_stats(self, stats_dict):
        """Update statistics data"""
        self.stats_data = stats_dict.copy()
        self.update_display()
    
    def update_display(self):
        """Update statistics display"""
        if not self.stats_data:
            return
        
        total = self.stats_data.get('total', 0)
        if total == 0:
            return
        
        # Prepare data for display
        display_data = []
        for key, value in self.stats_data.items():
            if key not in ['total', 'total_bytes']:
                percentage = (value / total) * 100 if total > 0 else 0
                display_data.append([key, str(value), f"{percentage:.1f}%"])
        
        # Add summary rows
        display_data.insert(0, ['Total Packets', str(total), '100.0%'])
        display_data.insert(1, ['Total Bytes', str(self.stats_data.get('total_bytes', 0)), '-'])
        
        # Update table
        self.stats_table.setRowCount(len(display_data))
        for row, (metric, value, percentage) in enumerate(display_data):
            self.stats_table.setItem(row, 0, QTableWidgetItem(metric))
            self.stats_table.setItem(row, 1, QTableWidgetItem(value))
            self.stats_table.setItem(row, 2, QTableWidgetItem(percentage))
        
        self.stats_table.resizeColumnsToContents()

class FilterWidget(QWidget):
    """Advanced filter widget with presets"""
    
    filter_applied = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        """Setup filter UI"""
        layout = QHBoxLayout(self)
        
        # Filter input
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Enter filter: src:IP, protocol:HTTP, threat:>50")
        self.filter_input.textChanged.connect(self.on_filter_changed)
        layout.addWidget(self.filter_input)
        
        # Preset buttons
        preset_layout = QHBoxLayout()
        
        presets = [
            ("SIP", "protocol:SIP"),
            ("HTTP", "protocol:HTTP"),
            ("Threats", "threat:>0"),
            ("Local", "src:192.168")
        ]
        
        for name, filter_text in presets:
            btn = QPushButton(name)
            btn.clicked.connect(lambda checked, f=filter_text: self.apply_preset(f))
            btn.setStyleSheet("QPushButton { min-width: 60px; }")
            preset_layout.addWidget(btn)
        
        # Clear button
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear_filter)
        preset_layout.addWidget(clear_btn)
        
        layout.addLayout(preset_layout)
    
    def apply_preset(self, filter_text):
        """Apply preset filter"""
        self.filter_input.setText(filter_text)
    
    def clear_filter(self):
        """Clear current filter"""
        self.filter_input.clear()
    
    def on_filter_changed(self, text):
        """Handle filter text change"""
        self.filter_applied.emit(text)

class ThreatIndicatorWidget(QWidget):
    """Threat level indicator widget"""
    
    def __init__(self):
        super().__init__()
        self.threat_level = "LOW"
        self.threat_count = 0
        self.setup_ui()
        
    def setup_ui(self):
        """Setup threat indicator UI"""
        layout = QVBoxLayout(self)
        
        # Threat level label
        self.level_label = QLabel("THREAT LEVEL: LOW")
        self.level_label.setAlignment(Qt.AlignCenter)
        self.level_label.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #2ecc71;
            padding: 15px;
            border: 2px solid #2ecc71;
            border-radius: 8px;
            background-color: rgba(46, 204, 113, 0.1);
        """)
        layout.addWidget(self.level_label)
        
        # Threat count
        self.count_label = QLabel("0 threats detected")
        self.count_label.setAlignment(Qt.AlignCenter)
        self.count_label.setStyleSheet("font-size: 12px; color: #7f8c8d; padding: 5px;")
        layout.addWidget(self.count_label)
    
    def update_threat_level(self, threat_count):
        """Update threat level based on count"""
        self.threat_count = threat_count
        
        if threat_count > 10:
            self.threat_level = "HIGH"
            color = "#e74c3c"
        elif threat_count > 5:
            self.threat_level = "MEDIUM"
            color = "#f39c12"
        else:
            self.threat_level = "LOW"
            color = "#2ecc71"
        
        self.level_label.setText(f"THREAT LEVEL: {self.threat_level}")
        self.level_label.setStyleSheet(f"""
            font-size: 18px;
            font-weight: bold;
            color: {color};
            padding: 15px;
            border: 2px solid {color};
            border-radius: 8px;
            background-color: rgba({self.hex_to_rgb(color)}, 0.1);
        """)
        
        self.count_label.setText(f"{threat_count} threats detected")
    
    #!/usr/bin/env python3
"""
NetHawk Pro - Part 3: Main Application and UI Integration (Corrected)
Advanced Network Packet Analyzer - Main Application

This file contains the main application starting from hex_to_rgb method:
- Main application window
- Menu and toolbar setup
- Event handlers
- Settings management
- Application entry point

To run: Import Parts 1 and 2 first, then run this file
"""

# Start from hex_to_rgb method as requested
def hex_to_rgb(self, hex_color):
    """Convert hex color to RGB string"""
    hex_color = hex_color.lstrip('#')
    return ', '.join(str(int(hex_color[i:i+2], 16)) for i in (0, 2, 4))

# Add this method to ThreatIndicatorWidget from Part 2
if 'ThreatIndicatorWidget' in globals():
    ThreatIndicatorWidget.hex_to_rgb = hex_to_rgb

class NetHawkPro(QMainWindow):
    """Main NetHawk Pro application window"""
    
    def __init__(self):
        super().__init__()
        self.config = load_config()
        self.capture_thread = None
        self.discovery_thread = None
        self.threat_thread = None
        self.capturing = False
        self.stats = defaultdict(int)
        self.packet_db = PacketDatabase()
        self.remote_agents = []
        
        self.setup_ui()
        self.setup_menu()
        self.setup_toolbar()
        self.setup_status_bar()
        
        # Apply theme
        if self.config.get('dark_mode', True):
            self.apply_dark_theme()
        
        # Start background services
        self.start_threat_monitoring()
        
        # Statistics timer
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_statistics)
        self.stats_timer.start(self.config.get('update_interval', 1000))
    
    def setup_ui(self):
        """Setup main user interface"""
        self.setWindowTitle('NetHawk Pro - Advanced Network Analyzer')
        self.setGeometry(100, 100, 1400, 900)
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        
        # Control panel
        control_panel = self.create_control_panel()
        main_layout.addWidget(control_panel)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Setup tabs
        self.setup_packet_tab()
        self.setup_discovery_tab()
        self.setup_visualization_tab()
        self.setup_remote_tab()
        self.setup_threat_tab()
    
    def create_control_panel(self):
        """Create the main control panel"""
        panel = QGroupBox("Capture Control")
        layout = QHBoxLayout(panel)
        
        # Interface selection
        layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        self.populate_interfaces()
        layout.addWidget(self.interface_combo)
        
        # Capture method
        layout.addWidget(QLabel("Method:"))
        self.method_combo = QComboBox()
        self.method_combo.addItems(["Scapy (Recommended)", "Socket Monitor", "Process Monitor"])
        layout.addWidget(self.method_combo)
        
        # Control buttons
        self.start_btn = QPushButton('▶ Start Capture')
        self.start_btn.clicked.connect(self.start_capture)
        self.start_btn.setStyleSheet("QPushButton { background-color: #27ae60; color: white; font-weight: bold; }")
        layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton('⏸ Stop Capture')
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("QPushButton { background-color: #e74c3c; color: white; font-weight: bold; }")
        layout.addWidget(self.stop_btn)
        
        self.clear_btn = QPushButton('🗑 Clear')
        self.clear_btn.clicked.connect(self.clear_packets)
        layout.addWidget(self.clear_btn)
        
        # Status
        self.status_label = QLabel('Ready - No Admin Rights Required!')
        self.status_label.setStyleSheet('color: #2ecc71; font-weight: bold; font-size: 12px;')
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        return panel
    
    def populate_interfaces(self):
        """Populate interface dropdown"""
        self.interface_combo.addItem("Auto-detect", None)
        
        try:
            capture = UnprivilegedCapture()
            interfaces = capture.get_available_interfaces()
            
            for iface in interfaces:
                self.interface_combo.addItem(iface['description'], iface['name'])
                
        except Exception as e:
            print(f"Interface enumeration error: {e}")
    
    def setup_packet_tab(self):
        """Setup packet analysis tab"""
        packet_widget = QWidget()
        packet_layout = QVBoxLayout(packet_widget)
        
        # Filter widget
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel('🔍 Filter:'))
        
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText('Advanced filter: src:192.168.1.1, protocol:HTTP, threat:>50')
        self.filter_edit.textChanged.connect(self.apply_packet_filter)
        filter_layout.addWidget(self.filter_edit)
        
        # Filter presets
        preset_btn = QPushButton('Presets')
        preset_menu = QMenu()
        preset_menu.addAction('SIP Traffic', lambda: self.filter_edit.setText('protocol:SIP'))
        preset_menu.addAction('HTTP Traffic', lambda: self.filter_edit.setText('protocol:HTTP'))
        preset_menu.addAction('High Threats', lambda: self.filter_edit.setText('threat:>50'))
        preset_menu.addAction('Local Traffic', lambda: self.filter_edit.setText('src:192.168'))
        preset_btn.setMenu(preset_menu)
        filter_layout.addWidget(preset_btn)
        
        packet_layout.addLayout(filter_layout)
        
        # Splitter for packets and details
        splitter = QSplitter(Qt.Vertical)
        
        # Packet table
        self.packet_table = ModernPacketTable()
        self.packet_table.packet_selected.connect(self.show_packet_details)
        self.packet_table.filter_changed.connect(lambda f: self.filter_edit.setText(f))
        splitter.addWidget(self.packet_table)
        
        # Bottom panel
        bottom_tabs = QTabWidget()
        
        # Packet details
        self.packet_details = PacketDetailsWidget()
        bottom_tabs.addTab(self.packet_details, "Details")
        
        # Hex dump
        self.hex_dump = QTextBrowser()
        self.hex_dump.setFont(QFont("Consolas", 9))
        self.hex_dump.setStyleSheet("QTextBrowser { background-color: #2c3e50; color: white; }")
        bottom_tabs.addTab(self.hex_dump, "Hex Dump")
        
        # Statistics
        self.stats_widget = StatisticsWidget()
        bottom_tabs.addTab(self.stats_widget, "Statistics")
        
        splitter.addWidget(bottom_tabs)
        splitter.setSizes([600, 300])
        
        packet_layout.addWidget(splitter)
        self.tab_widget.addTab(packet_widget, "📡 Packet Analysis")
    
    def setup_discovery_tab(self):
        """Setup network discovery tab"""
        discovery_widget = QWidget()
        discovery_layout = QVBoxLayout(discovery_widget)
        
        # Controls
        controls = QHBoxLayout()
        
        self.network_input = QLineEdit()
        self.network_input.setPlaceholderText("Network range (e.g., 192.168.1.0/24)")
        controls.addWidget(QLabel("Target:"))
        controls.addWidget(self.network_input)
        
        self.discovery_btn = QPushButton("🔍 Start Discovery")
        self.discovery_btn.clicked.connect(self.start_discovery)
        controls.addWidget(self.discovery_btn)
        
        self.stop_discovery_btn = QPushButton("⏹ Stop")
        self.stop_discovery_btn.clicked.connect(self.stop_discovery)
        self.stop_discovery_btn.setEnabled(False)
        controls.addWidget(self.stop_discovery_btn)
        
        discovery_layout.addLayout(controls)
        
        # Progress
        self.discovery_progress = QProgressBar()
        self.discovery_progress.setVisible(False)
        discovery_layout.addWidget(self.discovery_progress)
        
        # Host table
        self.host_table = QTableWidget()
        self.host_table.setColumnCount(6)
        self.host_table.setHorizontalHeaderLabels(['IP', 'Hostname', 'MAC', 'Status', 'Ports', 'OS'])
        
        header = self.host_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        
        discovery_layout.addWidget(self.host_table)
        self.tab_widget.addTab(discovery_widget, "🌐 Network Discovery")
    
    def setup_visualization_tab(self):
        """Setup visualization tab"""
        self.visualization = NetworkVisualization()
        self.tab_widget.addTab(self.visualization, "📊 Analytics")
    
    def setup_remote_tab(self):
        """Setup remote agents tab"""
        remote_widget = QWidget()
        remote_layout = QVBoxLayout(remote_widget)
        
        # Agent controls
        controls = QHBoxLayout()
        
        self.agent_host_input = QLineEdit()
        self.agent_host_input.setPlaceholderText("Remote host IP")
        controls.addWidget(QLabel("Host:"))
        controls.addWidget(self.agent_host_input)
        
        self.agent_port_input = QLineEdit("9999")
        controls.addWidget(QLabel("Port:"))
        controls.addWidget(self.agent_port_input)
        
        self.add_agent_btn = QPushButton("➕ Add Agent")
        self.add_agent_btn.clicked.connect(self.add_remote_agent)
        controls.addWidget(self.add_agent_btn)
        
        remote_layout.addLayout(controls)
        
        # Agent table
        self.agent_table = QTableWidget()
        self.agent_table.setColumnCount(5)
        self.agent_table.setHorizontalHeaderLabels(['Host', 'Port', 'Status', 'Packets', 'Actions'])
        remote_layout.addWidget(self.agent_table)
        
        self.tab_widget.addTab(remote_widget, "🔗 Remote Agents")
    
    def setup_threat_tab(self):
        """Setup threat intelligence tab"""
        threat_widget = QWidget()
        threat_layout = QVBoxLayout(threat_widget)
        
        # Threat summary
        summary = QHBoxLayout()
        
        self.threat_indicator = ThreatIndicatorWidget()
        summary.addWidget(self.threat_indicator)
        
        summary.addStretch()
        
        self.update_feeds_btn = QPushButton("🔄 Update Feeds")
        self.update_feeds_btn.clicked.connect(self.update_threat_feeds)
        summary.addWidget(self.update_feeds_btn)
        
        threat_layout.addLayout(summary)
        
        # Threat table
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(6)
        self.threat_table.setHorizontalHeaderLabels(['Time', 'Source', 'Dest', 'Type', 'Score', 'Details'])
        threat_layout.addWidget(self.threat_table)
        
        # Feeds list
        feeds_group = QGroupBox("Intelligence Feeds")
        feeds_layout = QVBoxLayout(feeds_group)
        
        self.feeds_list = QListWidget()
        feeds_layout.addWidget(self.feeds_list)
        
        threat_layout.addWidget(feeds_group)
        self.tab_widget.addTab(threat_widget, "🛡️ Threat Intel")
    
    def setup_menu(self):
        """Setup menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        file_menu.addAction('Open PCAP', self.open_pcap_file, 'Ctrl+O')
        file_menu.addAction('Save Session', self.save_session, 'Ctrl+S')
        file_menu.addAction('Load Session', self.load_session)
        file_menu.addSeparator()
        file_menu.addAction('Export Packets', self.export_packets, 'Ctrl+E')
        file_menu.addAction('Export Report', self.export_report)
        file_menu.addSeparator()
        file_menu.addAction('Settings', self.show_settings)
        file_menu.addAction('Exit', self.close, 'Ctrl+Q')
        
        # Capture menu
        capture_menu = menubar.addMenu('Capture')
        capture_menu.addAction('Start', self.start_capture, 'F5')
        capture_menu.addAction('Stop', self.stop_capture, 'F6')
        capture_menu.addAction('Clear', self.clear_packets, 'Ctrl+L')
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        tools_menu.addAction('Network Discovery', self.start_discovery)
        tools_menu.addAction('Port Scanner', self.port_scan)
        tools_menu.addAction('Security Audit', self.security_audit)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        help_menu.addAction('Help', self.show_help, 'F1')
        help_menu.addAction('About', self.show_about)
    
    def setup_toolbar(self):
        """Setup toolbar"""
        toolbar = self.addToolBar('Main')
        
        # Capture controls
        toolbar.addAction('▶ Start', self.start_capture)
        toolbar.addAction('⏸ Stop', self.stop_capture)
        toolbar.addSeparator()
        toolbar.addAction('📁 Open', self.open_pcap_file)
        toolbar.addAction('💾 Save', self.save_session)
        toolbar.addSeparator()
        toolbar.addAction('🔍 Discover', self.start_discovery)
        toolbar.addAction('⚙ Settings', self.show_settings)
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Status widgets
        self.packets_label = QLabel("Packets: 0")
        self.status_bar.addPermanentWidget(self.packets_label)
        
        self.bandwidth_label = QLabel("Data: 0 KB")
        self.status_bar.addPermanentWidget(self.bandwidth_label)
        
        self.threats_label = QLabel("Threats: 0")
        self.threats_label.setStyleSheet("color: #e74c3c;")
        self.status_bar.addPermanentWidget(self.threats_label)
        
        self.status_bar.showMessage("NetHawk Pro Ready - No Admin Rights Required!")
    
    def apply_dark_theme(self):
        """Apply dark theme"""
        self.setStyleSheet("""
        QMainWindow { background-color: #2c3e50; color: white; }
        QTabWidget::pane { border: 1px solid #34495e; background-color: #2c3e50; }
        QTabBar::tab { 
            background-color: #34495e; color: white; 
            padding: 8px 16px; margin: 2px; border-radius: 4px; 
        }
        QTabBar::tab:selected { background-color: #3498db; }
        QGroupBox { 
            font-weight: bold; border: 2px solid #34495e; 
            border-radius: 5px; margin: 10px 0px; padding-top: 10px; 
        }
        QGroupBox::title { color: #3498db; padding: 0 5px 0 5px; }
        QPushButton { 
            background-color: #34495e; color: white; border: 1px solid #2c3e50; 
            padding: 8px 16px; border-radius: 4px; font-weight: bold; 
        }
        QPushButton:hover { background-color: #3498db; }
        QPushButton:disabled { background-color: #7f8c8d; }
        QLineEdit, QComboBox { 
            background-color: #34495e; color: white; 
            border: 1px solid #2c3e50; padding: 5px; border-radius: 3px; 
        }
        QTextBrowser { background-color: #2c3e50; color: white; }
        QMenuBar { background-color: #34495e; color: white; }
        QMenu { background-color: #34495e; color: white; }
        QLabel { color: white; }
        """)
    
    # Core methods
    def start_capture(self):
        """Start packet capture"""
        if self.capturing:
            return
        
        interface_data = self.interface_combo.currentData()
        method_text = self.method_combo.currentText().lower()
        
        methods = ['scapy'] if 'scapy' in method_text else ['socket_monitor'] if 'socket' in method_text else ['process_monitor']
        
        self.capture_thread = UnprivilegedCapture()
        self.capture_thread.packet_received.connect(self.on_packet_received)
        self.capture_thread.status_changed.connect(self.on_status_changed)
        self.capture_thread.error_occurred.connect(self.on_capture_error)
        
        self.capture_thread.start_capture(interface_data, methods)
        self.capturing = True
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText('Starting...')
        self.status_label.setStyleSheet('color: #f39c12; font-weight: bold;')
    
    def stop_capture(self):
        """Stop packet capture"""
        if not self.capturing:
            return
        
        if self.capture_thread:
            self.capture_thread.stop_capture()
            self.capture_thread.wait(3000)
        
        self.capturing = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText('Stopped')
        self.status_label.setStyleSheet('color: #e74c3c; font-weight: bold;')
    
    def clear_packets(self):
        """Clear all packets"""
        reply = QMessageBox.question(self, 'Clear', 'Clear all packets?', 
                                   QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.packet_table.clear_all()
            self.packet_details.clear()
            self.stats.clear()
            self.status_bar.showMessage('Packets cleared')
    
    def on_packet_received(self, packet_info):
        """Handle new packet"""
        self.packet_table.add_packet(packet_info)
        self.visualization.add_packet_data(packet_info)
        
        protocol = packet_info['protocol']
        self.stats[protocol] += 1
        self.stats['total'] += 1
        self.stats['total_bytes'] += packet_info['length']
        
        if hasattr(self, 'stats_widget'):
            self.stats_widget.update_stats(dict(self.stats))
        
        threat_score = packet_info.get('threat_score', 0)
        if threat_score > 50:
            self.add_threat_alert(packet_info)
    
    def on_status_changed(self, status):
        """Handle status updates"""
        self.status_label.setText(status)
        self.status_bar.showMessage(status)
        
        if 'active' in status.lower():
            self.status_label.setStyleSheet('color: #2ecc71; font-weight: bold;')
    
    def on_capture_error(self, error):
        """Handle capture errors"""
        self.capturing = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText('Error')
        self.status_label.setStyleSheet('color: #e74c3c; font-weight: bold;')
        
        QMessageBox.critical(self, 'Capture Error', f"Error: {error}")
    
    def apply_packet_filter(self, filter_text):
        """Apply packet filter"""
        self.packet_table.apply_current_filter(filter_text)
    
    def show_packet_details(self, packet_info):
        """Show packet details"""
        self.packet_details.show_packet_details(packet_info)
        
        hex_data = f"Hex dump for packet #{packet_info['no']}:\n"
        hex_data += f"Length: {packet_info['length']} bytes\n"
        hex_data += f"Protocol: {packet_info['protocol']}\n\n"
        hex_data += "Raw data not available with current capture method."
        
        self.hex_dump.setPlainText(hex_data)
    
    # Network discovery
    def start_discovery(self):
        """Start network discovery"""
        if self.discovery_thread and self.discovery_thread.isRunning():
            return
        
        networks = [self.network_input.text().strip()] if self.network_input.text().strip() else []
        
        self.discovery_thread = NetworkDiscovery()
        self.discovery_thread.host_discovered.connect(self.on_host_discovered)
        self.discovery_thread.scan_progress.connect(self.on_scan_progress)
        self.discovery_thread.scan_complete.connect(self.on_scan_complete)
        
        self.discovery_thread.discover_networks(networks)
        
        self.discovery_btn.setEnabled(False)
        self.stop_discovery_btn.setEnabled(True)
        self.discovery_progress.setVisible(True)
        self.host_table.setRowCount(0)
    
    def stop_discovery(self):
        """Stop discovery"""
        if self.discovery_thread:
            self.discovery_thread.stop_discovery()
        
        self.discovery_btn.setEnabled(True)
        self.stop_discovery_btn.setEnabled(False)
        self.discovery_progress.setVisible(False)
    
    def on_host_discovered(self, host_info):
        """Handle discovered host"""
        row = self.host_table.rowCount()
        self.host_table.insertRow(row)
        
        self.host_table.setItem(row, 0, QTableWidgetItem(host_info['ip']))
        self.host_table.setItem(row, 1, QTableWidgetItem(host_info.get('hostname', 'Unknown')))
        self.host_table.setItem(row, 2, QTableWidgetItem(host_info.get('mac_address', 'Unknown')))
        self.host_table.setItem(row, 3, QTableWidgetItem(host_info['status']))
        
        ports = ', '.join([f"{p['port']}" for p in host_info.get('open_ports', [])[:5]])
        self.host_table.setItem(row, 4, QTableWidgetItem(ports))
        self.host_table.setItem(row, 5, QTableWidgetItem(host_info.get('os_guess', 'Unknown')))
    
    def on_scan_progress(self, message, progress):
        """Handle scan progress"""
        self.status_bar.showMessage(message)
        self.discovery_progress.setValue(progress)
    
    def on_scan_complete(self):
        """Handle scan completion"""
        self.discovery_btn.setEnabled(True)
        self.stop_discovery_btn.setEnabled(False)
        self.discovery_progress.setVisible(False)
        self.status_bar.showMessage(f"Discovery complete - found {self.host_table.rowCount()} hosts")
    
    # Remote agents
    def add_remote_agent(self):
        """Add remote agent"""
        host = self.agent_host_input.text().strip()
        port = int(self.agent_port_input.text() or 9999)
        
        if not host:
            QMessageBox.warning(self, "Input Error", "Please enter host address")
            return
        
        agent = RemoteAgent(host, port)
        if agent.connect():
            self.remote_agents.append(agent)
            
            row = self.agent_table.rowCount()
            self.agent_table.insertRow(row)
            
            self.agent_table.setItem(row, 0, QTableWidgetItem(host))
            self.agent_table.setItem(row, 1, QTableWidgetItem(str(port)))
            self.agent_table.setItem(row, 2, QTableWidgetItem("Connected"))
            self.agent_table.setItem(row, 3, QTableWidgetItem("0"))
            
            self.agent_host_input.clear()
        else:
            QMessageBox.critical(self, "Connection Failed", f"Failed to connect to {host}:{port}")
    
    # Threat intelligence
    def start_threat_monitoring(self):
        """Start threat monitoring"""
        self.threat_thread = ThreatIntelligence()
        self.threat_thread.threat_detected.connect(self.on_threat_detected)
        self.threat_thread.intel_updated.connect(self.on_intel_updated)
        self.threat_thread.start_monitoring()
    
    def on_threat_detected(self, threat_info):
        """Handle threat detection"""
        self.add_threat_alert(threat_info)
    
    def on_intel_updated(self, message):
        """Handle intelligence updates"""
        self.feeds_list.addItem(f"{datetime.now().strftime('%H:%M:%S')} - {message}")
    
    def add_threat_alert(self, packet_info):
        """Add threat alert"""
        row = self.threat_table.rowCount()
        self.threat_table.insertRow(row)
        
        self.threat_table.setItem(row, 0, QTableWidgetItem(datetime.now().strftime('%H:%M:%S')))
        self.threat_table.setItem(row, 1, QTableWidgetItem(packet_info['src']))
        self.threat_table.setItem(row, 2, QTableWidgetItem(packet_info['dst']))
        self.threat_table.setItem(row, 3, QTableWidgetItem("Suspicious"))
        self.threat_table.setItem(row, 4, QTableWidgetItem(str(packet_info.get('threat_score', 0))))
        self.threat_table.setItem(row, 5, QTableWidgetItem(packet_info.get('info', '')))
        
        threat_count = self.threat_table.rowCount()
        self.threat_indicator.update_threat_level(threat_count)
    
    def update_statistics(self):
        """Update statistics"""
        if self.stats:
            total = self.stats.get('total', 0)
            total_bytes = self.stats.get('total_bytes', 0)
            threat_count = self.threat_table.rowCount()
            
            self.packets_label.setText(f"Packets: {total:,}")
            self.bandwidth_label.setText(f"Data: {total_bytes // 1024:,} KB")
            self.threats_label.setText(f"Threats: {threat_count}")
    
    def update_threat_feeds(self):
        """Update threat feeds"""
        self.on_intel_updated("Threat feeds updated")
        QMessageBox.information(self, "Feeds", "Threat feeds updated!")
    
    # File operations
    def open_pcap_file(self):
        """Open PCAP file"""
        filename, _ = QFileDialog.getOpenFileName(self, 'Open PCAP', '', 'PCAP Files (*.pcap *.cap)')
        if filename:
            QMessageBox.information(self, "PCAP", f"PCAP loading: {os.path.basename(filename)}\n(Feature in development)")
    
    def save_session(self):
        """Save session"""
        if not self.packet_table.packets:
            QMessageBox.information(self, 'No Data', 'No packets to save.')
            return
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Save Session', '', 'NetHawk Sessions (*.nhs)')
        if filename:
            try:
                session_data = {
                    'packets': self.packet_table.packets,
                    'config': self.config,
                    'stats': dict(self.stats),
                    'timestamp': datetime.now().isoformat()
                }
                
                with open(filename, 'wb') as f:
                    pickle.dump(session_data, f)
                
                QMessageBox.information(self, "Saved", f"Session saved: {os.path.basename(filename)}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Save failed: {e}")
    
    def load_session(self):
        """Load session"""
        filename, _ = QFileDialog.getOpenFileName(self, 'Load Session', '', 'NetHawk Sessions (*.nhs)')
        if filename:
            try:
                with open(filename, 'rb') as f:
                    session_data = pickle.load(f)
                
                self.clear_packets()
                for packet in session_data.get('packets', []):
                    self.packet_table.add_packet(packet)
                
                self.stats.update(session_data.get('stats', {}))
                QMessageBox.information(self, "Loaded", f"Session loaded: {os.path.basename(filename)}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Load failed: {e}")
    
    def export_packets(self):
        """Export packets"""
        if not self.packet_table.packets:
            QMessageBox.information(self, 'No Data', 'No packets to export.')
            return
        
        filename, selected_filter = QFileDialog.getSaveFileName(
            self, 'Export Packets', '', 
            'CSV Files (*.csv);;JSON Files (*.json);;XML Files (*.xml)'
        )
        
        if filename:
            try:
                if selected_filter.startswith('CSV'):
                    self.export_csv(filename)
                elif selected_filter.startswith('JSON'):
                    self.export_json(filename)
                elif selected_filter.startswith('XML'):
                    self.export_xml(filename)
            except Exception as e:
                QMessageBox.critical(self, 'Export Error', f'Failed to export: {str(e)}')
    
    def export_csv(self, filename):
        """Export to CSV"""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['No', 'Time', 'Source', 'Dest', 'Protocol', 'QoS', 'Length', 'Geo', 'Threat', 'Info'])
            
            for pkt in self.packet_table.packets:
                writer.writerow([
                    pkt['no'], pkt['timestamp'], pkt['src'], pkt['dst'],
                    pkt['protocol'], pkt.get('qos_name', 'BE'), 
                    pkt['length'], pkt.get('geo_display', ''),
                    pkt.get('threat_score', 0), pkt.get('info', '')
                ])
        
        QMessageBox.information(self, 'Export Complete', f'Exported {len(self.packet_table.packets)} packets to CSV')
    
    def export_json(self, filename):
        """Export to JSON"""
        with open(filename, 'w') as f:
            json.dump({
                'export_info': {
                    'version': '1.0.0',
                    'timestamp': datetime.now().isoformat(),
                    'packet_count': len(self.packet_table.packets)
                },
                'packets': self.packet_table.packets
            }, f, indent=2, default=str)
        
        QMessageBox.information(self, 'Export Complete', f'Exported {len(self.packet_table.packets)} packets to JSON')
    
    def export_xml(self, filename):
        """Export to XML"""
        with open(filename, 'w') as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n<nethawk_export>\n')
            f.write(f'  <info timestamp="{datetime.now().isoformat()}" count="{len(self.packet_table.packets)}"/>\n')
            f.write('  <packets>\n')
            
            for packet in self.packet_table.packets:
                f.write('    <packet>\n')
                for key, value in packet.items():
                    f.write(f'      <{key}>{str(value)}</{key}>\n')
                f.write('    </packet>\n')
            
            f.write('  </packets>\n</nethawk_export>')
        
        QMessageBox.information(self, 'Export Complete', f'Exported {len(self.packet_table.packets)} packets to XML')
    
    def export_report(self):
        """Export HTML report"""
        if not self.packet_table.packets:
            QMessageBox.information(self, 'No Data', 'No packets to include in report.')
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 'Export Report', f'nethawk_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html',
            'HTML Reports (*.html)'
        )
        
        if filename:
            try:
                self.generate_html_report(filename)
                QMessageBox.information(self, 'Report Generated', f'Report saved to {os.path.basename(filename)}')
            except Exception as e:
                QMessageBox.critical(self, 'Report Error', f'Failed to generate report: {str(e)}')
    
    def generate_html_report(self, filename):
        """Generate HTML report"""
        total_packets = self.stats.get('total', 0)
        total_bytes = self.stats.get('total_bytes', 0)
        threat_count = self.threat_table.rowCount()
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>NetHawk Pro Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f7fa; }}
                .header {{ background: linear-gradient(135deg, #667eea, #764ba2); 
                          color: white; padding: 30px; border-radius: 10px; text-align: center; }}
                .section {{ background: white; margin: 20px 0; padding: 25px; 
                           border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; }}
                .stat-box {{ text-align: center; padding: 20px; background: #e8f4fd; 
                            border-radius: 8px; border-left: 4px solid #3498db; }}
                .stat-number {{ font-size: 2em; font-weight: bold; color: #2c3e50; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #34495e; color: white; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>NetHawk Pro Network Analysis Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="stats">
                    <div class="stat-box">
                        <div class="stat-number">{total_packets:,}</div>
                        <div>Total Packets</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{len(set([p['protocol'] for p in self.packet_table.packets]))}</div>
                        <div>Protocols</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{threat_count}</div>
                        <div>Security Alerts</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{total_bytes // 1024:,}</div>
                        <div>KB Processed</div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Security Assessment</h2>
                <p style="font-size: 1.2em; color: {'#e74c3c' if threat_count > 10 else '#f39c12' if threat_count > 5 else '#27ae60'};">
                    Threat Level: {'HIGH' if threat_count > 10 else 'MEDIUM' if threat_count > 5 else 'LOW'}
                </p>
                <p>{threat_count} security alerts were detected during analysis.</p>
            </div>
            
            <div class="section">
                <h2>Protocol Distribution</h2>
                <table>
                    <tr><th>Protocol</th><th>Packets</th><th>Percentage</th></tr>
        """
        
        # Add protocol stats
        for protocol, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
            if protocol not in ['total', 'total_bytes'] and count > 0:
                percentage = (count / total_packets * 100) if total_packets > 0 else 0
                html_content += f"<tr><td>{protocol}</td><td>{count:,}</td><td>{percentage:.1f}%</td></tr>"
        
        html_content += """
                </table>
            </div>
            
            <div class="section">
                <h2>Technical Details</h2>
                <p><b>Capture Method:</b> """ + self.method_combo.currentText() + """</p>
                <p><b>Interface:</b> """ + self.interface_combo.currentText() + """</p>
                <p><b>Analysis Engine:</b> NetHawk Pro v1.0</p>
                <p><b>Admin Rights:</b> Not Required</p>
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
                <ul>
                    <li>Continue regular monitoring with NetHawk Pro</li>
                    <li>Investigate high-threat packets immediately</li>
                    <li>Consider network segmentation for security</li>
                    <li>Update security policies based on findings</li>
                </ul>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
    
    # Tools
    def port_scan(self):
        """Port scanner tool"""
        dialog = QDialog(self)
        dialog.setWindowTitle('Port Scanner')
        dialog.resize(500, 400)
        layout = QVBoxLayout(dialog)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel('Target:'))
        target_input = QLineEdit()
        target_input.setPlaceholderText('IP address or hostname')
        target_layout.addWidget(target_input)
        layout.addLayout(target_layout)
        
        # Port input
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel('Ports:'))
        port_input = QLineEdit()
        port_input.setText('21,22,23,25,53,80,110,443,993,995,5060,8080')
        port_layout.addWidget(port_input)
        layout.addLayout(port_layout)
        
        # Results
        results = QTextBrowser()
        layout.addWidget(results)
        
        # Buttons
        button_layout = QHBoxLayout()
        scan_btn = QPushButton('Scan')
        close_btn = QPushButton('Close')
        close_btn.clicked.connect(dialog.accept)
        button_layout.addWidget(scan_btn)
        button_layout.addWidget(close_btn)
        layout.addLayout(button_layout)
        
        def perform_scan():
            target = target_input.text().strip()
            ports = [int(p.strip()) for p in port_input.text().split(',') if p.strip().isdigit()]
            
            if not target:
                results.setText('Please enter a target')
                return
            
            results.setText(f'Scanning {target}...\n')
            QApplication.processEvents()
            
            open_ports = []
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        open_ports.append(port)
                        results.append(f'Port {port}: OPEN')
                    else:
                        results.append(f'Port {port}: CLOSED')
                except:
                    results.append(f'Port {port}: ERROR')
            
            results.append(f'\nScan complete. {len(open_ports)} ports open.')
        
        scan_btn.clicked.connect(perform_scan)
        dialog.exec_()
    
    def security_audit(self):
        """Security audit tool"""
        dialog = QDialog(self)
        dialog.setWindowTitle('Security Audit')
        dialog.resize(600, 400)
        layout = QVBoxLayout(dialog)
        
        results = QTextBrowser()
        layout.addWidget(results)
        
        # Perform audit
        audit_results = []
        
        # Check threats
        threat_count = self.threat_table.rowCount()
        if threat_count > 10:
            audit_results.append("HIGH: Excessive security threats detected")
        elif threat_count > 5:
            audit_results.append("MEDIUM: Moderate security activity")
        
        # Check protocols
        protocols = set([p['protocol'] for p in self.packet_table.packets])
        if 'HTTP' in protocols:
            audit_results.append("WARNING: Unencrypted HTTP traffic detected")
        
        if not audit_results:
            audit_results.append("PASS: No obvious security issues")
        
        results.setHtml('<br>'.join([f"• {result}" for result in audit_results]))
        
        close_btn = QPushButton('Close')
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)
        
        dialog.exec_()
    
    def show_settings(self):
        """Show settings dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle('Settings')
        dialog.resize(400, 300)
        layout = QVBoxLayout(dialog)
        
        # Max packets
        max_packets_layout = QHBoxLayout()
        max_packets_layout.addWidget(QLabel('Max Packets:'))
        max_packets_spin = QSpinBox()
        max_packets_spin.setRange(1000, 100000)
        max_packets_spin.setValue(self.config.get('max_packets', MAX_PACKETS))
        max_packets_layout.addWidget(max_packets_spin)
        layout.addLayout(max_packets_layout)
        
        # Dark mode
        dark_mode_check = QCheckBox('Dark Mode')
        dark_mode_check.setChecked(self.config.get('dark_mode', True))
        layout.addWidget(dark_mode_check)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        if dialog.exec_() == QDialog.Accepted:
            self.config['max_packets'] = max_packets_spin.value()
            self.config['dark_mode'] = dark_mode_check.isChecked()
            save_config(self.config)
            
            if self.config['dark_mode']:
                self.apply_dark_theme()
            else:
                self.setStyleSheet("")
            
            QMessageBox.information(self, 'Settings', 'Settings saved!')
    
    def show_help(self):
        """Show help"""
        help_text = """
        <h2>NetHawk Pro Help</h2>
        
        <h3>Getting Started</h3>
        <p>NetHawk Pro provides advanced network analysis without requiring administrator privileges.</p>
        
        <h3>Capture Methods</h3>
        <ul>
        <li><b>Scapy:</b> Recommended method, most reliable</li>
        <li><b>Socket Monitor:</b> Monitors network connections</li>
        <li><b>Process Monitor:</b> Tracks process network activity</li>
        </ul>
        
        <h3>Advanced Filtering</h3>
        <ul>
        <li><code>src:192.168.1.1</code> - Filter by source IP</li>
        <li><code>protocol:HTTP</code> - Filter by protocol</li>
        <li><code>threat:>50</code> - Filter by threat score</li>
        </ul>
        
        <h3>Features</h3>
        <ul>
        <li>Real-time packet capture</li>
        <li>Network discovery</li>
        <li>Threat detection</li>
        <li>Geographic analysis</li>
        <li>Professional reporting</li>
        </ul>
        """
        
        QMessageBox.about(self, 'Help', help_text)
    
    def show_about(self):
        """Show about dialog"""
        about_text = f"""
        <h1>NetHawk Pro</h1>
        <h2>Advanced Network Analyzer</h2>
        <p><b>Version 1.0.0</b></p>
        
        <h3>Revolutionary Features:</h3>
        <ul>
        <li>No Administrator Rights Required</li>
        <li>Real-time Packet Analysis</li>
        <li>Network Discovery & Scanning</li>
        <li>Advanced Threat Detection</li>
        <li>Geographic IP Mapping</li>
        <li>Professional Reporting</li>
        <li>Modern UI Design</li>
        </ul>
        
        <p><i>"The ultimate network analysis tool"</i></p>
        <p>© 2024 NetHawk Pro Team</p>
        """
        
        QMessageBox.about(self, 'About NetHawk Pro', about_text)
    
    def closeEvent(self, event):
        """Handle application close"""
        if self.capturing:
            reply = QMessageBox.question(self, 'Exit', 
                'Capture is active. Stop and exit?',
                QMessageBox.Yes | QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                self.stop_capture()
            else:
                event.ignore()
                return
        
        # Cleanup
        if self.discovery_thread:
            self.discovery_thread.stop_discovery()
        
        if self.threat_thread:
            self.threat_thread.stop_monitoring()
        
        save_config(self.config)
        event.accept()


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("NetHawk Pro")
    app.setApplicationVersion("1.0.0")
    
    # Check dependencies
    missing = []
    required = ['psutil', 'scapy']
    
    for dep in required:
        try:
            __import__(dep)
        except ImportError:
            missing.append(dep)
    
    if missing:
        QMessageBox.critical(None, "Missing Dependencies", 
            f"Required: {', '.join(missing)}\nInstall: pip install {' '.join(missing)}")
        return 1
    
    # Welcome message
    welcome = QMessageBox()
    welcome.setIcon(QMessageBox.Information)
    welcome.setWindowTitle('NetHawk Pro')
    welcome.setText('NetHawk Pro v1.0 - Advanced Network Analyzer')
    welcome.setInformativeText(
        'Revolutionary network analysis without admin privileges!\n\n'
        'Features:\n'
        '• Real-time packet capture\n'
        '• Network discovery\n' 
        '• Threat detection\n'
        '• Geographic analysis\n'
        '• Professional reporting\n\n'
        'Ready to start?'
    )
    welcome.exec_()
    
    # Create main window
    try:
        window = NetHawkPro()
        window.show()
        return app.exec_()
    except Exception as e:
        QMessageBox.critical(None, "Error", f"Failed to start: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())