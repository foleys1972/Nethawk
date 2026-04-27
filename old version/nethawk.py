#!/usr/bin/env python3
"""
NetHawk Pro - Part 1: Core Infrastructure
Advanced PCAP and SIP Analysis Tool - Core Components

This file contains:
- Configuration management
- Database operations
- Basic packet structures
- Core utilities and constants
- Base classes for packet analysis
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
    from scapy.all import *
    from scapy.layers.inet import *
    from scapy.layers.l2 import *
    from scapy.utils import rdpcap, wrpcap
except ImportError as e:
    print(f"Error: Missing required packages. Run: pip install psutil requests scapy")
    print(f"Missing: {e}")
    sys.exit(1)

# Configuration
CONFIG_FILE = 'nethawk_config.json'
DB_FILE = 'nethawk_packets.db'
MAX_PACKETS = 50000

# Enhanced protocol colors with modern theme
PROTOCOL_COLORS = {
    'TCP': '#3498db',     # Blue
    'UDP': '#2ecc71',     # Green  
    'ICMP': '#f39c12',    # Orange
    'SIP': '#e74c3c',     # Red
    'RTP': '#8e44ad',     # Purple
    'RTCP': '#9b59b6',    # Light Purple
    'HTTP': '#16a085',    # Teal
    'HTTPS': '#27ae60',   # Dark Green
    'DNS': '#d35400',     # Dark Orange
    'SSH': '#34495e',     # Dark Blue-Gray
    'FTP': '#c0392b',     # Dark Red
    'SMTP': '#7f8c8d',    # Gray
    'Other': '#95a5a6'    # Light Gray
}

# SIP Methods and Response Codes
SIP_METHODS = [
    'INVITE', 'ACK', 'BYE', 'CANCEL', 'OPTIONS', 'REGISTER',
    'PRACK', 'SUBSCRIBE', 'NOTIFY', 'PUBLISH', 'INFO', 'REFER', 'MESSAGE', 'UPDATE'
]

SIP_RESPONSE_CODES = {
    # 1xx Provisional
    100: 'Trying', 180: 'Ringing', 183: 'Session Progress',
    # 2xx Success  
    200: 'OK', 202: 'Accepted',
    # 3xx Redirection
    300: 'Multiple Choices', 301: 'Moved Permanently', 302: 'Moved Temporarily',
    # 4xx Client Error
    400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
    407: 'Proxy Authentication Required', 408: 'Request Timeout', 410: 'Gone',
    413: 'Request Entity Too Large', 414: 'Request-URI Too Long', 415: 'Unsupported Media Type',
    416: 'Unsupported URI Scheme', 420: 'Bad Extension', 421: 'Extension Required',
    423: 'Interval Too Brief', 480: 'Temporarily Unavailable', 481: 'Call/Transaction Does Not Exist',
    482: 'Loop Detected', 483: 'Too Many Hops', 484: 'Address Incomplete',
    485: 'Ambiguous', 486: 'Busy Here', 487: 'Request Terminated', 488: 'Not Acceptable Here',
    491: 'Request Pending', 493: 'Undecipherable',
    # 5xx Server Error
    500: 'Server Internal Error', 501: 'Not Implemented', 502: 'Bad Gateway',
    503: 'Service Unavailable', 504: 'Server Time-out', 505: 'Version Not Supported',
    513: 'Message Too Large',
    # 6xx Global Failure
    600: 'Busy Everywhere', 603: 'Decline', 604: 'Does Not Exist Anywhere', 606: 'Not Acceptable'
}

# RTP Payload Types
RTP_PAYLOAD_TYPES = {
    0: 'PCMU', 1: 'Reserved', 2: 'Reserved', 3: 'GSM', 4: 'G723', 5: 'DVI4-8000',
    6: 'DVI4-16000', 7: 'LPC', 8: 'PCMA', 9: 'G722', 10: 'L16-2', 11: 'L16-1',
    12: 'QCELP', 13: 'CN', 14: 'MPA', 15: 'G728', 16: 'DVI4-11025', 17: 'DVI4-22050',
    18: 'G729', 25: 'CelB', 26: 'JPEG', 28: 'nv', 31: 'H261', 32: 'MPV', 33: 'MP2T',
    34: 'H263', 96: 'Dynamic', 97: 'Dynamic', 98: 'Dynamic'
}

def load_config():
    """Load configuration with enhanced defaults for PCAP analysis"""
    default = {
        'max_packets': MAX_PACKETS,
        'auto_scroll': True,
        'pcap_directory': './pcaps',
        'export_directory': './exports',
        'dark_mode': True,
        'update_interval': 1000,
        'export_format': 'csv',
        'sip_call_tracking': True,
        'rtp_analysis': True,
        'show_hex_dump': True,
        'auto_save_session': False
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
    """SQLite database for packet storage and analysis with SIP support"""
    
    def __init__(self, db_file=DB_FILE):
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with SIP tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Main packets table
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
                flags TEXT,
                payload_hash TEXT,
                raw_data BLOB,
                is_sip BOOLEAN DEFAULT 0,
                is_rtp BOOLEAN DEFAULT 0,
                call_id TEXT,
                sip_method TEXT,
                sip_response_code INTEGER,
                rtp_payload_type INTEGER,
                rtp_ssrc INTEGER
            )
        ''')
        
        # SIP calls table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sip_calls (
                call_id TEXT PRIMARY KEY,
                caller TEXT,
                callee TEXT,
                start_time REAL,
                end_time REAL,
                duration REAL,
                status TEXT,
                packets_count INTEGER DEFAULT 0
            )
        ''')
        
        # RTP streams table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rtp_streams (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                call_id TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                ssrc INTEGER,
                payload_type INTEGER,
                packet_count INTEGER DEFAULT 0,
                bytes_transferred INTEGER DEFAULT 0,
                FOREIGN KEY (call_id) REFERENCES sip_calls (call_id)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON packets(src_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol ON packets(protocol)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_call_id ON packets(call_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sip ON packets(is_sip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rtp ON packets(is_rtp)')
        
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
                    protocol, length, flags, payload_hash, raw_data,
                    is_sip, is_rtp, call_id, sip_method, sip_response_code,
                    rtp_payload_type, rtp_ssrc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', packet_data)
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database insert error: {e}")
    
    def insert_sip_call(self, call_data):
        """Insert SIP call record"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO sip_calls (
                    call_id, caller, callee, start_time, end_time, 
                    duration, status, packets_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', call_data)
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"SIP call insert error: {e}")
    
    def get_sip_calls(self):
        """Get all SIP calls"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM sip_calls ORDER BY start_time DESC')
            results = cursor.fetchall()
            conn.close()
            return results
        except Exception as e:
            print(f"SIP calls query error: {e}")
            return []
    
    def get_packets_by_call_id(self, call_id):
        """Get all packets for a specific call"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM packets WHERE call_id = ? ORDER BY timestamp', (call_id,))
            results = cursor.fetchall()
            conn.close()
            return results
        except Exception as e:
            print(f"Call packets query error: {e}")
            return []
    
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
            if 'call_id' in filters:
                conditions.append("call_id = ?")
                params.append(filters['call_id'])
            if 'sip_only' in filters and filters['sip_only']:
                conditions.append("is_sip = 1")
            if 'rtp_only' in filters and filters['rtp_only']:
                conditions.append("is_rtp = 1")
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        query += f" ORDER BY timestamp DESC LIMIT {limit}"
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        
        return results

class SIPCallTracker:
    """Track SIP calls and their associated packets"""
    
    def __init__(self):
        self.active_calls = {}  # call_id -> call_info
        self.call_packets = defaultdict(list)  # call_id -> [packets]
        self.rtp_streams = defaultdict(list)  # call_id -> [rtp_streams]
    
    def process_sip_packet(self, packet_info):
        """Process SIP packet and update call tracking"""
        if not packet_info.get('is_sip'):
            return
        
        call_id = packet_info.get('call_id')
        if not call_id:
            return
        
        # Add packet to call
        self.call_packets[call_id].append(packet_info)
        
        # Update call state based on SIP method/response
        method = packet_info.get('sip_method')
        response_code = packet_info.get('sip_response_code')
        
        if call_id not in self.active_calls:
            self.active_calls[call_id] = {
                'call_id': call_id,
                'caller': packet_info.get('src'),
                'callee': packet_info.get('dst'),
                'start_time': packet_info.get('timestamp'),
                'status': 'INITIATED',
                'packets': []
            }
        
        call_info = self.active_calls[call_id]
        
        # Update call status based on SIP messages
        if method == 'INVITE':
            call_info['status'] = 'INVITE_SENT'
        elif method == 'ACK':
            call_info['status'] = 'ESTABLISHED'
        elif method == 'BYE':
            call_info['status'] = 'TERMINATING'
        elif response_code:
            if 100 <= response_code < 200:
                call_info['status'] = 'PROCEEDING'
            elif response_code == 200:
                call_info['status'] = 'ANSWERED'
            elif response_code >= 400:
                call_info['status'] = 'FAILED'
        
        call_info['packets'].append(packet_info)
        call_info['end_time'] = packet_info.get('timestamp')
    
    def get_call_info(self, call_id):
        """Get call information"""
        return self.active_calls.get(call_id)
    
    def get_all_calls(self):
        """Get all tracked calls"""
        return list(self.active_calls.values())
    
    def get_call_packets(self, call_id):
        """Get packets for specific call"""
        return self.call_packets.get(call_id, [])

class RTPAnalyzer:
    """Analyze RTP streams"""
    
    def __init__(self):
        self.streams = {}  # (src_ip, src_port, dst_ip, dst_port) -> stream_info
        self.call_streams = defaultdict(list)  # call_id -> [streams]
    
    def process_rtp_packet(self, packet_info):
        """Process RTP packet"""
        if not packet_info.get('is_rtp'):
            return
        
        stream_key = (
            packet_info['src'], packet_info['sport'],
            packet_info['dst'], packet_info['dport']
        )
        
        if stream_key not in self.streams:
            self.streams[stream_key] = {
                'src_ip': packet_info['src'],
                'src_port': packet_info['sport'],
                'dst_ip': packet_info['dst'],
                'dst_port': packet_info['dport'],
                'ssrc': packet_info.get('rtp_ssrc', 0),
                'payload_type': packet_info.get('rtp_payload_type', 0),
                'packet_count': 0,
                'bytes_count': 0,
                'start_time': packet_info['timestamp'],
                'last_time': packet_info['timestamp'],
                'call_id': packet_info.get('call_id')
            }
        
        stream_info = self.streams[stream_key]
        stream_info['packet_count'] += 1
        stream_info['bytes_count'] += packet_info['length']
        stream_info['last_time'] = packet_info['timestamp']
        
        # Associate with call
        call_id = packet_info.get('call_id')
        if call_id and stream_key not in self.call_streams[call_id]:
            self.call_streams[call_id].append(stream_key)
    
    def get_stream_info(self, stream_key):
        """Get RTP stream information"""
        return self.streams.get(stream_key)
    
    def get_call_streams(self, call_id):
        """Get RTP streams for a call"""
        stream_keys = self.call_streams.get(call_id, [])
        return [self.streams[key] for key in stream_keys if key in self.streams]
    
    def get_all_streams(self):
        """Get all RTP streams"""
        return list(self.streams.values())

class PacketParser:
    """Enhanced packet parser with SIP and RTP support"""
    
    def __init__(self):
        self.sip_tracker = SIPCallTracker()
        self.rtp_analyzer = RTPAnalyzer()
    
    def parse_packet(self, scapy_packet):
        """Parse Scapy packet with enhanced SIP/RTP analysis"""
        try:
            packet_info = {
                'timestamp': time.time(),
                'length': len(scapy_packet),
                'protocol': 'Unknown',
                'src': 'Unknown',
                'dst': 'Unknown',
                'sport': 0,
                'dport': 0,
                'info': '',
                'flags': '',
                'is_sip': False,
                'is_rtp': False,
                'call_id': None,
                'sip_method': None,
                'sip_response_code': None,
                'rtp_payload_type': None,
                'rtp_ssrc': None
            }
            
            # Extract timestamp from packet if available
            if hasattr(scapy_packet, 'time'):
                packet_info['timestamp'] = float(scapy_packet.time)
            
            # IP Layer
            if scapy_packet.haslayer(IP):
                ip = scapy_packet[IP]
                packet_info['src'] = ip.src
                packet_info['dst'] = ip.dst
            
            # Transport Layer
            if scapy_packet.haslayer(TCP):
                tcp = scapy_packet[TCP]
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
                
                # Check for SIP over TCP
                if scapy_packet.haslayer(Raw):
                    self._analyze_sip_payload(scapy_packet[Raw].load, packet_info)
                
            elif scapy_packet.haslayer(UDP):
                udp = scapy_packet[UDP]
                packet_info['protocol'] = 'UDP'
                packet_info['sport'] = udp.sport
                packet_info['dport'] = udp.dport
                
                # Check for SIP (typical ports 5060, 5061)
                if (udp.sport in [5060, 5061] or udp.dport in [5060, 5061]) and scapy_packet.haslayer(Raw):
                    self._analyze_sip_payload(scapy_packet[Raw].load, packet_info)
                # Check for RTP (even ports > 1024)
                elif (udp.sport > 1024 and udp.dport > 1024 and 
                      udp.sport % 2 == 0 and udp.dport % 2 == 0 and scapy_packet.haslayer(Raw)):
                    self._analyze_rtp_payload(scapy_packet[Raw].load, packet_info)
                
            elif scapy_packet.haslayer(ICMP):
                icmp = scapy_packet[ICMP]
                packet_info['protocol'] = 'ICMP'
                packet_info['info'] = f"ICMP Type {icmp.type}"
            
            # Update protocol based on application layer analysis
            if packet_info['is_sip']:
                packet_info['protocol'] = 'SIP'
                self.sip_tracker.process_sip_packet(packet_info)
            elif packet_info['is_rtp']:
                packet_info['protocol'] = 'RTP'
                self.rtp_analyzer.process_rtp_packet(packet_info)
            
            # Generate info string
            if not packet_info['info']:
                packet_info['info'] = f"{packet_info['protocol']} {packet_info['sport']} -> {packet_info['dport']}"
            
            return packet_info
            
        except Exception as e:
            print(f"Packet parse error: {e}")
            return None
    
    def _analyze_sip_payload(self, payload, packet_info):
        """Analyze SIP payload"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            
            # Check if it's SIP
            if not any(method in payload_str[:50] for method in SIP_METHODS) and 'SIP/2.0' not in payload_str[:50]:
                return
            
            packet_info['is_sip'] = True
            lines = payload_str.split('\r\n')
            first_line = lines[0] if lines else ''
            
            # Parse SIP method or response
            if any(method in first_line for method in SIP_METHODS):
                # SIP Request
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    packet_info['sip_method'] = parts[0]
                    packet_info['info'] = f"SIP {parts[0]} {parts[1]}"
            elif first_line.startswith('SIP/2.0'):
                # SIP Response
                parts = first_line.split(' ', 2)
                if len(parts) >= 2:
                    try:
                        code = int(parts[1])
                        packet_info['sip_response_code'] = code
                        status = SIP_RESPONSE_CODES.get(code, 'Unknown')
                        packet_info['info'] = f"SIP {code} {status}"
                    except ValueError:
                        packet_info['info'] = f"SIP Response {first_line}"
            
            # Extract Call-ID
            for line in lines:
                if line.lower().startswith('call-id:'):
                    packet_info['call_id'] = line.split(':', 1)[1].strip()
                    break
                elif line.lower().startswith('i:'):
                    packet_info['call_id'] = line.split(':', 1)[1].strip()
                    break
                    
        except Exception as e:
            print(f"SIP analysis error: {e}")
    
    def _analyze_rtp_payload(self, payload, packet_info):
        """Analyze RTP payload"""
        try:
            if len(payload) < 12:  # RTP header minimum size
                return
            
            # RTP Header format (RFC 3550)
            # 0                   1                   2                   3
            # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |V=2|P|X|  CC   |M|     PT      |       sequence number         |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            
            first_byte = payload[0]
            version = (first_byte >> 6) & 0x03
            
            # Check RTP version
            if version != 2:
                return
            
            packet_info['is_rtp'] = True
            
            # Extract payload type
            payload_type = payload[1] & 0x7F
            packet_info['rtp_payload_type'] = payload_type
            
            # Extract SSRC
            ssrc = struct.unpack('>I', payload[8:12])[0]
            packet_info['rtp_ssrc'] = ssrc
            
            # Generate info
            codec = RTP_PAYLOAD_TYPES.get(payload_type, f'Unknown({payload_type})')
            packet_info['info'] = f"RTP {codec} SSRC=0x{ssrc:08x}"
            
        except Exception as e:
            print(f"RTP analysis error: {e}")

class GeoLocationService:
    """Geolocation service for IP addresses (simplified for PCAP analysis)"""
    
    def __init__(self):
        self.cache = {}
    
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
                # Mock geolocation for demo (in production, use real API)
                location = self.mock_geolocation(ip_address)
            
            self.cache[ip_address] = location
            return location
            
        except Exception as e:
            print(f"Geolocation error: {e}")
            return {'country': 'Unknown', 'city': 'Unknown', 'lat': 0, 'lon': 0}
    
    def mock_geolocation(self, ip_address):
        """Mock geolocation for demo"""
        sample_locations = {
            'default': {'country': 'Unknown', 'city': 'Unknown', 'lat': 0, 'lon': 0},
            '8.8.8.8': {'country': 'USA', 'city': 'Mountain View', 'lat': 37.386, 'lon': -122.084},
            '1.1.1.1': {'country': 'USA', 'city': 'San Francisco', 'lat': 37.775, 'lon': -122.418}
        }
        return sample_locations.get(ip_address, sample_locations['default'])

# Utility functions for packet analysis
def extract_call_id_from_sip(sip_payload):
    """Extract Call-ID from SIP payload"""
    try:
        lines = sip_payload.decode('utf-8', errors='ignore').split('\r\n')
        for line in lines:
            if line.lower().startswith('call-id:'):
                return line.split(':', 1)[1].strip()
            elif line.lower().startswith('i:'):
                return line.split(':', 1)[1].strip()
    except:
        pass
    return None

def is_rtp_packet(udp_payload):
    """Check if UDP payload is RTP"""
    if len(udp_payload) < 12:
        return False
    
    # Check RTP version (should be 2)
    version = (udp_payload[0] >> 6) & 0x03
    return version == 2

def format_duration(seconds):
    """Format duration in human readable format"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{int(seconds//60)}m {int(seconds%60)}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours}h {minutes}m {secs}s"

def get_sip_method_color(method):
    """Get color for SIP method"""
    colors = {
        'INVITE': '#e74c3c',    # Red
        'ACK': '#27ae60',       # Green
        'BYE': '#f39c12',       # Orange
        'CANCEL': '#e67e22',    # Dark Orange
        'REGISTER': '#3498db',  # Blue
        'OPTIONS': '#9b59b6',   # Purple
        'PRACK': '#16a085',     # Teal
        'SUBSCRIBE': '#8e44ad', # Dark Purple
        'NOTIFY': '#2ecc71',    # Light Green
        'INFO': '#34495e',      # Dark Gray
        'REFER': '#d35400',     # Dark Orange
        'MESSAGE': '#7f8c8d',   # Gray
        'UPDATE': '#95a5a6'     # Light Gray
    }
    return colors.get(method, '#95a5a6')

def get_sip_response_color(code):
    """Get color for SIP response code"""
    if 100 <= code < 200:
        return '#3498db'  # Blue for provisional
    elif 200 <= code < 300:
        return '#27ae60'  # Green for success
        
#!/usr/bin/env python3
"""
NetHawk Pro - Part 2: PCAP Processing & Analysis
Advanced PCAP and SIP Analysis Tool - PCAP Processing Layer

This file contains:
- PCAP file reading and processing
- Packet capture functionality
- Protocol analysis engines
- Data filtering and search
- Export capabilities
"""

# Continue from Part 1 - add these color functions to complete Part 1
def get_sip_response_color(code):
    """Get color for SIP response code"""
    if 100 <= code < 200:
        return '#3498db'  # Blue for provisional
    elif 200 <= code < 300:
        return '#27ae60'  # Green for success
    elif 300 <= code < 400:
        return '#f39c12'  # Orange for redirection
    elif 400 <= code < 500:
        return '#e74c3c'  # Red for client error
    elif 500 <= code < 600:
        return '#8e44ad'  # Purple for server error
    elif 600 <= code < 700:
        return '#34495e'  # Dark gray for global failure
    else:
        return '#95a5a6'  # Light gray for unknown

class PCAPProcessor:
    """Enhanced PCAP file processor with SIP analysis"""
    
    def __init__(self):
        self.packet_parser = PacketParser()
        self.packets = []
        self.sip_calls = {}
        self.rtp_streams = {}
        self.processing_progress = 0
        self.total_packets = 0
    
    def load_pcap_file(self, filename, progress_callback=None):
        """Load and process PCAP file"""
        try:
            self.packets.clear()
            self.sip_calls.clear()
            self.rtp_streams.clear()
            
            # Read PCAP file using Scapy
            scapy_packets = rdpcap(filename)
            self.total_packets = len(scapy_packets)
            
            processed_packets = []
            
            for i, scapy_packet in enumerate(scapy_packets):
                # Update progress
                self.processing_progress = int((i / self.total_packets) * 100)
                if progress_callback:
                    progress_callback(self.processing_progress, f"Processing packet {i+1}/{self.total_packets}")
                
                # Parse packet
                packet_info = self.packet_parser.parse_packet(scapy_packet)
                if packet_info:
                    packet_info['no'] = i + 1
                    packet_info['timestamp_str'] = datetime.fromtimestamp(packet_info['timestamp']).strftime('%H:%M:%S.%f')[:-3]
                    processed_packets.append(packet_info)
                    
                    # Store raw packet data for hex dump
                    packet_info['raw_packet'] = bytes(scapy_packet)
            
            self.packets = processed_packets
            
            # Extract SIP calls and RTP streams
            self.sip_calls = self.packet_parser.sip_tracker.active_calls.copy()
            self.rtp_streams = self.packet_parser.rtp_analyzer.streams.copy()
            
            return True, f"Loaded {len(self.packets)} packets from {filename}"
            
        except Exception as e:
            return False, f"Failed to load PCAP: {str(e)}"
    
    def save_pcap_file(self, filename, packets_to_save=None):
        """Save packets to PCAP file"""
        try:
            if packets_to_save is None:
                packets_to_save = self.packets
            
            # Convert packet info back to Scapy packets for saving
            scapy_packets = []
            for packet_info in packets_to_save:
                if 'raw_packet' in packet_info:
                    # Reconstruct from raw data
                    scapy_packet = Ether(packet_info['raw_packet'])
                    scapy_packets.append(scapy_packet)
            
            if scapy_packets:
                wrpcap(filename, scapy_packets)
                return True, f"Saved {len(scapy_packets)} packets to {filename}"
            else:
                return False, "No packets to save"
                
        except Exception as e:
            return False, f"Failed to save PCAP: {str(e)}"
    
    def get_packets(self):
        """Get all processed packets"""
        return self.packets
    
    def get_sip_calls(self):
        """Get SIP call information"""
        return list(self.sip_calls.values())
    
    def get_rtp_streams(self):
        """Get RTP stream information"""
        return list(self.rtp_streams.values())
    
    def filter_packets(self, filter_criteria):
        """Filter packets based on criteria"""
        filtered = []
        
        for packet in self.packets:
            match = True
            
            # Source IP filter
            if 'src_ip' in filter_criteria:
                if filter_criteria['src_ip'].lower() not in packet['src'].lower():
                    match = False
            
            # Destination IP filter
            if 'dst_ip' in filter_criteria:
                if filter_criteria['dst_ip'].lower() not in packet['dst'].lower():
                    match = False
            
            # Protocol filter
            if 'protocol' in filter_criteria:
                if filter_criteria['protocol'].upper() != packet['protocol'].upper():
                    match = False
            
            # Port filter
            if 'port' in filter_criteria:
                port = filter_criteria['port']
                if port != packet['sport'] and port != packet['dport']:
                    match = False
            
            # SIP filter
            if 'sip_only' in filter_criteria and filter_criteria['sip_only']:
                if not packet.get('is_sip', False):
                    match = False
            
            # RTP filter
            if 'rtp_only' in filter_criteria and filter_criteria['rtp_only']:
                if not packet.get('is_rtp', False):
                    match = False
            
            # Call ID filter
            if 'call_id' in filter_criteria:
                if filter_criteria['call_id'] != packet.get('call_id'):
                    match = False
            
            # Time range filter
            if 'start_time' in filter_criteria:
                if packet['timestamp'] < filter_criteria['start_time']:
                    match = False
            
            if 'end_time' in filter_criteria:
                if packet['timestamp'] > filter_criteria['end_time']:
                    match = False
            
            if match:
                filtered.append(packet)
        
        return filtered

class LiveCapture(QThread):
    """Live packet capture thread"""
    
    packet_received = pyqtSignal(dict)
    status_changed = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.running = False
        self.packet_count = 0
        self.packet_parser = PacketParser()
        self.interface = None
        self.capture_filter = None
    
    def start_capture(self, interface=None, capture_filter=None):
        """Start live packet capture"""
        self.interface = interface
        self.capture_filter = capture_filter
        self.running = True
        self.packet_count = 0
        self.start()
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
    
    def run(self):
        """Main capture loop"""
        try:
            self.status_changed.emit("Starting capture...")
            
            def packet_handler(packet):
                if not self.running:
                    return
                
                try:
                    packet_info = self.packet_parser.parse_packet(packet)
                    if packet_info:
                        self.packet_count += 1
                        packet_info['no'] = self.packet_count
                        packet_info['timestamp_str'] = datetime.fromtimestamp(packet_info['timestamp']).strftime('%H:%M:%S.%f')[:-3]
                        packet_info['raw_packet'] = bytes(packet)
                        self.packet_received.emit(packet_info)
                except Exception as e:
                    print(f"Packet processing error: {e}")
            
            self.status_changed.emit("Capture active...")
            
            # Start sniffing with Scapy
            sniff(
                iface=self.interface,
                filter=self.capture_filter,
                prn=packet_handler,
                stop_filter=lambda x: not self.running
            )
            
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            self.status_changed.emit("Capture stopped")

class ProtocolAnalyzer:
    """Enhanced protocol analysis for various network protocols"""
    
    def __init__(self):
        self.http_sessions = {}
        self.dns_queries = {}
        self.tcp_conversations = defaultdict(list)
        self.udp_conversations = defaultdict(list)
    
    def analyze_http_packet(self, packet_info, raw_payload):
        """Analyze HTTP packet"""
        try:
            payload_str = raw_payload.decode('utf-8', errors='ignore')
            
            # HTTP Request
            if any(method in payload_str[:50] for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ']):
                lines = payload_str.split('\r\n')
                request_line = lines[0]
                
                packet_info['protocol'] = 'HTTP'
                packet_info['info'] = f"HTTP Request: {request_line}"
                packet_info['http_method'] = request_line.split(' ')[0]
                packet_info['http_uri'] = request_line.split(' ')[1] if len(request_line.split(' ')) > 1 else ''
                
                # Extract Host header
                for line in lines[1:]:
                    if line.lower().startswith('host:'):
                        packet_info['http_host'] = line.split(':', 1)[1].strip()
                        break
            
            # HTTP Response
            elif payload_str.startswith('HTTP/'):
                lines = payload_str.split('\r\n')
                status_line = lines[0]
                
                packet_info['protocol'] = 'HTTP'
                packet_info['info'] = f"HTTP Response: {status_line}"
                
                parts = status_line.split(' ')
                if len(parts) >= 2:
                    packet_info['http_status_code'] = int(parts[1])
                    packet_info['http_status_text'] = ' '.join(parts[2:]) if len(parts) > 2 else ''
            
        except Exception as e:
            print(f"HTTP analysis error: {e}")
    
    def analyze_dns_packet(self, packet_info, dns_layer):
        """Analyze DNS packet"""
        try:
            if hasattr(dns_layer, 'qr'):
                if dns_layer.qr == 0:  # Query
                    packet_info['protocol'] = 'DNS'
                    if hasattr(dns_layer, 'qd') and dns_layer.qd:
                        query_name = str(dns_layer.qd.qname, 'utf-8').rstrip('.')
                        packet_info['info'] = f"DNS Query: {query_name}"
                        packet_info['dns_query'] = query_name
                        packet_info['dns_type'] = dns_layer.qd.qtype
                else:  # Response
                    packet_info['protocol'] = 'DNS'
                    if hasattr(dns_layer, 'an') and dns_layer.an:
                        answers = []
                        for i in range(dns_layer.ancount):
                            if hasattr(dns_layer.an[i], 'rdata'):
                                answers.append(str(dns_layer.an[i].rdata))
                        packet_info['info'] = f"DNS Response: {', '.join(answers)}"
                        packet_info['dns_answers'] = answers
                        
        except Exception as e:
            print(f"DNS analysis error: {e}")
    
    def analyze_tcp_conversation(self, packet_info):
        """Track TCP conversations"""
        try:
            conv_key = tuple(sorted([
                (packet_info['src'], packet_info['sport']),
                (packet_info['dst'], packet_info['dport'])
            ]))
            
            self.tcp_conversations[conv_key].append(packet_info)
            
            # Analyze conversation state
            packets = self.tcp_conversations[conv_key]
            syn_count = sum(1 for p in packets if 'SYN' in p.get('flags', ''))
            fin_count = sum(1 for p in packets if 'FIN' in p.get('flags', ''))
            rst_count = sum(1 for p in packets if 'RST' in p.get('flags', ''))
            
            if syn_count > 0 and fin_count == 0 and rst_count == 0:
                packet_info['tcp_state'] = 'ESTABLISHED'
            elif fin_count > 0:
                packet_info['tcp_state'] = 'CLOSING'
            elif rst_count > 0:
                packet_info['tcp_state'] = 'RESET'
            else:
                packet_info['tcp_state'] = 'UNKNOWN'
                
        except Exception as e:
            print(f"TCP conversation analysis error: {e}")

class PacketSearchEngine:
    """Advanced packet search and filtering engine"""
    
    def __init__(self):
        self.search_history = []
        self.saved_filters = {}
    
    def search_packets(self, packets, search_query):
        """Search packets with advanced query syntax"""
        results = []
        
        try:
            # Parse search query
            filters = self._parse_search_query(search_query)
            
            for packet in packets:
                if self._matches_filters(packet, filters):
                    results.append(packet)
        
        except Exception as e:
            print(f"Search error: {e}")
            return packets  # Return all packets if search fails
        
        # Add to search history
        if search_query and search_query not in self.search_history:
            self.search_history.append(search_query)
            if len(self.search_history) > 20:
                self.search_history.pop(0)
        
        return results
    
    def _parse_search_query(self, query):
        """Parse search query into filters"""
        filters = {
            'text_search': [],
            'ip_src': [],
            'ip_dst': [],
            'port': [],
            'protocol': [],
            'sip_method': [],
            'call_id': [],
            'contains': []
        }
        
        # Split query by spaces, but respect quoted strings
        parts = []
        current_part = ""
        in_quotes = False
        
        for char in query:
            if char == '"':
                in_quotes = not in_quotes
            elif char == ' ' and not in_quotes:
                if current_part:
                    parts.append(current_part)
                    current_part = ""
            else:
                current_part += char
        
        if current_part:
            parts.append(current_part)
        
        # Process each part
        for part in parts:
            part = part.strip('"')
            
            if ':' in part:
                key, value = part.split(':', 1)
                key = key.lower()
                
                if key in ['src', 'source', 'ip.src']:
                    filters['ip_src'].append(value)
                elif key in ['dst', 'dest', 'destination', 'ip.dst']:
                    filters['ip_dst'].append(value)
                elif key in ['port', 'p']:
                    try:
                        filters['port'].append(int(value))
                    except ValueError:
                        filters['text_search'].append(part)
                elif key in ['proto', 'protocol']:
                    filters['protocol'].append(value.upper())
                elif key in ['sip', 'sip.method']:
                    filters['sip_method'].append(value.upper())
                elif key in ['call', 'callid', 'call-id']:
                    filters['call_id'].append(value)
                elif key in ['contains', 'payload']:
                    filters['contains'].append(value)
                else:
                    filters['text_search'].append(part)
            else:
                filters['text_search'].append(part)
        
        return filters
    
    def _matches_filters(self, packet, filters):
        """Check if packet matches all filters"""
        # IP source filters
        if filters['ip_src']:
            if not any(src in packet['src'] for src in filters['ip_src']):
                return False
        
        # IP destination filters
        if filters['ip_dst']:
            if not any(dst in packet['dst'] for dst in filters['ip_dst']):
                return False
        
        # Port filters
        if filters['port']:
            if not any(port in [packet['sport'], packet['dport']] for port in filters['port']):
                return False
        
        # Protocol filters
        if filters['protocol']:
            if packet['protocol'] not in filters['protocol']:
                return False
        
        # SIP method filters
        if filters['sip_method']:
            if packet.get('sip_method') not in filters['sip_method']:
                return False
        
        # Call ID filters
        if filters['call_id']:
            if not any(call_id in str(packet.get('call_id', '')) for call_id in filters['call_id']):
                return False
        
        # Contains filters (search in payload/info)
        if filters['contains']:
            info_str = packet.get('info', '').lower()
            if not any(contains.lower() in info_str for contains in filters['contains']):
                return False
        
        # General text search
        if filters['text_search']:
            search_text = ' '.join([
                packet['src'], packet['dst'], packet['protocol'],
                str(packet['sport']), str(packet['dport']),
                packet.get('info', ''), str(packet.get('call_id', ''))
            ]).lower()
            
            if not all(term.lower() in search_text for term in filters['text_search']):
                return False
        
        return True
    
    def save_filter(self, name, query):
        """Save a filter for later use"""
        self.saved_filters[name] = query
    
    def get_saved_filters(self):
        """Get saved filters"""
        return self.saved_filters
    
    def get_search_history(self):
        """Get search history"""
        return self.search_history

class ExportManager:
    """Manage various export formats for packet data"""
    
    def __init__(self):
        self.supported_formats = ['csv', 'json', 'xml', 'txt', 'html', 'pcap']
    
    def export_packets(self, packets, filename, format_type='csv', options=None):
        """Export packets in specified format"""
        if options is None:
            options = {}
        
        try:
            if format_type.lower() == 'csv':
                return self._export_csv(packets, filename, options)
            elif format_type.lower() == 'json':
                return self._export_json(packets, filename, options)
            elif format_type.lower() == 'xml':
                return self._export_xml(packets, filename, options)
            elif format_type.lower() == 'txt':
                return self._export_txt(packets, filename, options)
            elif format_type.lower() == 'html':
                return self._export_html(packets, filename, options)
            elif format_type.lower() == 'pcap':
                return self._export_pcap(packets, filename, options)
            else:
                return False, f"Unsupported format: {format_type}"
                
        except Exception as e:
            return False, f"Export failed: {str(e)}"
    
    def _export_csv(self, packets, filename, options):
        """Export to CSV format"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Headers
            headers = ['No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
            if options.get('include_sip', True):
                headers.extend(['SIP Method', 'SIP Response', 'Call ID'])
            if options.get('include_rtp', True):
                headers.extend(['RTP Payload Type', 'RTP SSRC'])
            if options.get('include_ports', True):
                headers.extend(['Source Port', 'Dest Port'])
            
            writer.writerow(headers)
            
            # Data
            for packet in packets:
                row = [
                    packet.get('no', ''),
                    packet.get('timestamp_str', ''),
                    packet.get('src', ''),
                    packet.get('dst', ''),
                    packet.get('protocol', ''),
                    packet.get('length', ''),
                    packet.get('info', '')
                ]
                
                if options.get('include_sip', True):
                    row.extend([
                        packet.get('sip_method', ''),
                        packet.get('sip_response_code', ''),
                        packet.get('call_id', '')
                    ])
                
                if options.get('include_rtp', True):
                    row.extend([
                        packet.get('rtp_payload_type', ''),
                        packet.get('rtp_ssrc', '')
                    ])
                
                if options.get('include_ports', True):
                    row.extend([
                        packet.get('sport', ''),
                        packet.get('dport', '')
                    ])
                
                writer.writerow(row)
        
        return True, f"Exported {len(packets)} packets to CSV"
    
    def _export_json(self, packets, filename, options):
        """Export to JSON format"""
        export_data = {
            'export_info': {
                'version': '1.0.0',
                'timestamp': datetime.now().isoformat(),
                'packet_count': len(packets),
                'tool': 'NetHawk Pro'
            },
            'packets': []
        }
        
        for packet in packets:
            packet_data = packet.copy()
            # Remove binary data
            if 'raw_packet' in packet_data:
                del packet_data['raw_packet']
            export_data['packets'].append(packet_data)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        return True, f"Exported {len(packets)} packets to JSON"
    
    def _export_xml(self, packets, filename, options):
        """Export to XML format"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            f.write('<nethawk_export>\n')
            f.write(f'  <info timestamp="{datetime.now().isoformat()}" count="{len(packets)}"/>\n')
            f.write('  <packets>\n')
            
            for packet in packets:
                f.write('    <packet>\n')
                for key, value in packet.items():
                    if key != 'raw_packet':  # Skip binary data
                        f.write(f'      <{key}><![CDATA[{str(value)}]]></{key}>\n')
                f.write('    </packet>\n')
            
            f.write('  </packets>\n')
            f.write('</nethawk_export>')
        
        return True, f"Exported {len(packets)} packets to XML"
    
    def _export_txt(self, packets, filename, options):
        """Export to plain text format"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"NetHawk Pro Packet Export\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Packets: {len(packets)}\n")
            f.write("=" * 80 + "\n\n")
            
            for packet in packets:
                f.write(f"Packet #{packet.get('no', 'Unknown')}\n")
                f.write(f"Time: {packet.get('timestamp_str', 'Unknown')}\n")
                f.write(f"Source: {packet.get('src', 'Unknown')}:{packet.get('sport', 0)}\n")
                f.write(f"Destination: {packet.get('dst', 'Unknown')}:{packet.get('dport', 0)}\n")
                f.write(f"Protocol: {packet.get('protocol', 'Unknown')}\n")
                f.write(f"Length: {packet.get('length', 0)} bytes\n")
                f.write(f"Info: {packet.get('info', 'No info')}\n")
                
                if packet.get('is_sip'):
                    f.write(f"SIP Method: {packet.get('sip_method', 'N/A')}\n")
                    f.write(f"SIP Response: {packet.get('sip_response_code', 'N/A')}\n")
                    f.write(f"Call ID: {packet.get('call_id', 'N/A')}\n")
                
                if packet.get('is_rtp'):
                    f.write(f"RTP Payload Type: {packet.get('rtp_payload_type', 'N/A')}\n")
                    f.write(f"RTP SSRC: {packet.get('rtp_ssrc', 'N/A')}\n")
                
                f.write("-" * 40 + "\n")
        
        return True, f"Exported {len(packets)} packets to text file"
    
    def _export_html(self, packets, filename, options):
        """Export to HTML report format"""
        # Count protocols
        protocol_stats = defaultdict(int)
        sip_calls = set()
        rtp_streams = set()
        
        for packet in packets:
            protocol_stats[packet.get('protocol', 'Unknown')] += 1
            if packet.get('call_id'):
                sip_calls.add(packet.get('call_id'))
            if packet.get('is_rtp'):
                rtp_streams.add((packet.get('src'), packet.get('sport')))
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>NetHawk Pro Packet Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f7fa; }}
                .header {{ background: linear-gradient(135deg, #667eea, #764ba2); 
                          color: white; padding: 20px; border-radius: 10px; text-align: center; }}
                .section {{ background: white; margin: 15px 0; padding: 20px; 
                           border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; }}
                .stat-box {{ text-align: center; padding: 15px; background: #e8f4fd; 
                            border-radius: 6px; border-left: 4px solid #3498db; }}
                .stat-number {{ font-size: 1.8em; font-weight: bold; color: #2c3e50; }}
                table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #34495e; color: white; }}
                .sip {{ background-color: #fdf2f2; }}
                .rtp {{ background-color: #f2f8fd; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>NetHawk Pro Packet Analysis Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Summary Statistics</h2>
                <div class="stats">
                    <div class="stat-box">
                        <div class="stat-number">{len(packets):,}</div>
                        <div>Total Packets</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{len(protocol_stats)}</div>
                        <div>Protocols</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{len(sip_calls)}</div>
                        <div>SIP Calls</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{len(rtp_streams)}</div>
                        <div>RTP Streams</div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Protocol Distribution</h2>
                <table>
                    <tr><th>Protocol</th><th>Packets</th><th>Percentage</th></tr>
        """
        
        # Add protocol statistics
        total_packets = len(packets)
        for protocol, count in sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            html_content += f"<tr><td>{protocol}</td><td>{count:,}</td><td>{percentage:.1f}%</td></tr>"
        
        html_content += """
                </table>
            </div>
            
            <div class="section">
                <h2>Packet Details</h2>
                <table>
                    <tr>
                        <th>No</th><th>Time</th><th>Source</th><th>Destination</th>
                        <th>Protocol</th><th>Length</th><th>Info</th>
                    </tr>
        """
        
        # Add packet details (limit to first 1000 for performance)
        display_packets = packets[:1000]
        for packet in display_packets:
            row_class = ""
            if packet.get('is_sip'):
                row_class = ' class="sip"'
            elif packet.get('is_rtp'):
                row_class = ' class="rtp"'
            
            html_content += f"""
                    <tr{row_class}>
                        <td>{packet.get('no', '')}</td>
                        <td>{packet.get('timestamp_str', '')}</td>
                        <td>{packet.get('src', '')}:{packet.get('sport', '')}</td>
                        <td>{packet.get('dst', '')}:{packet.get('dport', '')}</td>
                        <td>{packet.get('protocol', '')}</td>
                        <td>{packet.get('length', 0)}</td>
                        <td>{packet.get('info', '')}</td>
                    </tr>"""
        
        if len(packets) > 1000:
            html_content += f"<tr><td colspan='7'><i>... and {len(packets) - 1000} more packets</i></td></tr>"
        
        html_content += """
                </table>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return True, f"Exported {len(packets)} packets to HTML report"
    
    def _export_pcap(self, packets, filename, options):
        """Export to PCAP format"""
        try:
            # Create Scapy packets from packet info
            scapy_packets = []
            
            for packet_info in packets:
                if 'raw_packet' in packet_info:
                    # Use original raw packet data
                    scapy_packet = Ether(packet_info['raw_packet'])
                else:
                    # Reconstruct basic packet structure
                    scapy_packet = self._reconstruct_packet(packet_info)
                
                if scapy_packet:
                    scapy_packets.append(scapy_packet)
            
            if scapy_packets:
                wrpcap(filename, scapy_packets)
                return True, f"Exported {len(scapy_packets)} packets to PCAP"
            else:
                return False, "No packets could be reconstructed for PCAP export"
                
        except Exception as e:
            return False, f"PCAP export failed: {str(e)}"
    
    def _reconstruct_packet(self, packet_info):
        """Reconstruct a basic Scapy packet from packet info"""
        try:
            # Create basic IP packet
            packet = IP(src=packet_info.get('src', '0.0.0.0'), 
                       dst=packet_info.get('dst', '0.0.0.0'))
            
            if packet_info.get('protocol') == 'TCP':
                tcp_layer = TCP(sport=packet_info.get('sport', 0),
                              dport=packet_info.get('dport', 0))
                packet = packet / tcp_layer
            elif packet_info.get('protocol') == 'UDP':
                udp_layer = UDP(sport=packet_info.get('sport', 0),
                              dport=packet_info.get('dport', 0))
                packet = packet / udp_layer
            
            return packet
            
        except Exception as e:
            print(f"Packet reconstruction error: {e}")
            return None

class StatisticsEngine:
    """Generate detailed statistics for packet analysis"""
    
    def __init__(self):
        self.stats_cache = {}
        self.last_update = 0
    
    def generate_statistics(self, packets, force_refresh=False):
        """Generate comprehensive statistics"""
        # Use cache if recent and not forced
        current_time = time.time()
        if not force_refresh and (current_time - self.last_update) < 5:
            return self.stats_cache
        
        stats = {
            'total_packets': len(packets),
            'protocols': defaultdict(int),
            'conversations': defaultdict(int),
            'sip_calls': defaultdict(int),
            'rtp_streams': defaultdict(int),
            'time_analysis': {},
            'size_analysis': {},
            'traffic_analysis': {}
        }
        
        if not packets:
            return stats
        
        # Basic protocol stats
        total_bytes = 0
        min_time = float('inf')
        max_time = 0
        packet_sizes = []
        
        for packet in packets:
            protocol = packet.get('protocol', 'Unknown')
            stats['protocols'][protocol] += 1
            
            # Size stats
            size = packet.get('length', 0)
            packet_sizes.append(size)
            total_bytes += size
            
            # Time stats
            timestamp = packet.get('timestamp', 0)
            if timestamp > 0:
                min_time = min(min_time, timestamp)
                max_time = max(max_time, timestamp)
            
            # Conversation stats
            conv_key = f"{packet.get('src', '')}:{packet.get('sport', 0)} <-> {packet.get('dst', '')}:{packet.get('dport', 0)}"
            stats['conversations'][conv_key] += 1
            
            # SIP call stats
            if packet.get('is_sip') and packet.get('call_id'):
                stats['sip_calls'][packet.get('call_id')] += 1
            
            # RTP stream stats
            if packet.get('is_rtp'):
                rtp_key = f"{packet.get('src', '')}:{packet.get('sport', 0)} -> {packet.get('dst', '')}:{packet.get('dport', 0)}"
                stats['rtp_streams'][rtp_key] += 1
        
        # Time analysis
        if min_time != float('inf') and max_time > min_time:
            duration = max_time - min_time
            stats['time_analysis'] = {
                'start_time': datetime.fromtimestamp(min_time).strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': datetime.fromtimestamp(max_time).strftime('%Y-%m-%d %H:%M:%S'),
                'duration': format_duration(duration),
                'duration_seconds': duration,
                'packets_per_second': len(packets) / duration if duration > 0 else 0
            }
        
        # Size analysis
        if packet_sizes:
            stats['size_analysis'] = {
                'total_bytes': total_bytes,
                'average_size': sum(packet_sizes) / len(packet_sizes),
                'min_size': min(packet_sizes),
                'max_size': max(packet_sizes),
                'median_size': statistics.median(packet_sizes)
            }
        
        # Traffic analysis
        ip_traffic = defaultdict(lambda: {'sent': 0, 'received': 0, 'bytes_sent': 0, 'bytes_received': 0})
        
        for packet in packets:
            src = packet.get('src', '')
            dst = packet.get('dst', '')
            size = packet.get('length', 0)
            
            if src:
                ip_traffic[src]['sent'] += 1
                ip_traffic[src]['bytes_sent'] += size
            if dst:
                ip_traffic[dst]['received'] += 1
                ip_traffic[dst]['bytes_received'] += size
        
        # Top talkers
        top_senders = sorted(ip_traffic.items(), 
                           key=lambda x: x[1]['bytes_sent'], 
                           reverse=True)[:10]
        top_receivers = sorted(ip_traffic.items(), 
                             key=lambda x: x[1]['bytes_received'], 
                             reverse=True)[:10]
        
        stats['traffic_analysis'] = {
            'unique_ips': len(ip_traffic),
            'top_senders': [(ip, data['bytes_sent']) for ip, data in top_senders],
            'top_receivers': [(ip, data['bytes_received']) for ip, data in top_receivers]
        }
        
        # Update cache
        self.stats_cache = stats
        self.last_update = current_time
        
        return stats
    
    def generate_sip_statistics(self, packets):
        """Generate SIP-specific statistics"""
        sip_stats = {
            'total_sip_packets': 0,
            'methods': defaultdict(int),
            'responses': defaultdict(int),
            'calls': defaultdict(lambda: {'packets': 0, 'methods': set(), 'responses': set()}),
            'endpoints': defaultdict(int)
        }
        
        for packet in packets:
            if not packet.get('is_sip'):
                continue
            
            sip_stats['total_sip_packets'] += 1
            
            # Method stats
            if packet.get('sip_method'):
                method = packet.get('sip_method')
                sip_stats['methods'][method] += 1
            
            # Response stats
            if packet.get('sip_response_code'):
                code = packet.get('sip_response_code')
                sip_stats['responses'][code] += 1
            
            # Call stats
            call_id = packet.get('call_id')
            if call_id:
                call_info = sip_stats['calls'][call_id]
                call_info['packets'] += 1
                if packet.get('sip_method'):
                    call_info['methods'].add(packet.get('sip_method'))
                if packet.get('sip_response_code'):
                    call_info['responses'].add(packet.get('sip_response_code'))
            
            # Endpoint stats
            src = packet.get('src')
            dst = packet.get('dst')
            if src:
                sip_stats['endpoints'][src] += 1
            if dst:
                sip_stats['endpoints'][dst] += 1
        
        return sip_stats
    
    def generate_rtp_statistics(self, packets):
        """Generate RTP-specific statistics"""
        rtp_stats = {
            'total_rtp_packets': 0,
            'payload_types': defaultdict(int),
            'streams': defaultdict(lambda: {'packets': 0, 'bytes': 0, 'payload_types': set()}),
            'ssrc_stats': defaultdict(int)
        }
        
        for packet in packets:
            if not packet.get('is_rtp'):
                continue
            
            rtp_stats['total_rtp_packets'] += 1
            
            # Payload type stats
            payload_type = packet.get('rtp_payload_type')
            if payload_type is not None:
                rtp_stats['payload_types'][payload_type] += 1
            
            # Stream stats
            stream_key = f"{packet.get('src')}:{packet.get('sport')} -> {packet.get('dst')}:{packet.get('dport')}"
            stream_info = rtp_stats['streams'][stream_key]
            stream_info['packets'] += 1
            stream_info['bytes'] += packet.get('length', 0)
            if payload_type is not None:
                stream_info['payload_types'].add(payload_type)
            
            # SSRC stats
            ssrc = packet.get('rtp_ssrc')
            if ssrc is not None:
                rtp_stats['ssrc_stats'][ssrc] += 1
        
        return rtp_stats
#!/usr/bin/env python3
"""
NetHawk Pro - Part 3: SIP/Voice Analysis & Visualization
Advanced PCAP and SIP Analysis Tool - SIP/Voice Components

This file contains:
- SIP call flow visualization
- Voice packet analysis widgets
- Call sequence diagrams
- RTP stream analysis
- SIP ladder diagrams
- Voice quality metrics
"""

# Import matplotlib for visualizations
try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as patches
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    import numpy as np
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    print("Warning: Matplotlib not available. Install with: pip install matplotlib")
    MATPLOTLIB_AVAILABLE = False

class SIPCallFlowWidget(QWidget):
    """Enhanced SIP call flow visualization widget"""
    
    call_selected = pyqtSignal(str)  # Emit call ID when selected
    packet_selected = pyqtSignal(dict)  # Emit packet info when clicked
    
    def __init__(self):
        super().__init__()
        self.sip_packets = []
        self.call_flows = {}
        self.selected_call = None
        self.setup_ui()
        
    def setup_ui(self):
        """Setup call flow UI"""
        layout = QVBoxLayout(self)
        
        # Controls
        controls = QHBoxLayout()
        
        # Call selection
        controls.addWidget(QLabel("Call:"))
        self.call_combo = QComboBox()
        self.call_combo.currentTextChanged.connect(self.on_call_selected)
        controls.addWidget(self.call_combo)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_calls)
        controls.addWidget(refresh_btn)
        
        # Export button
        export_btn = QPushButton("Export Diagram")
        export_btn.clicked.connect(self.export_diagram)
        controls.addWidget(export_btn)
        
        controls.addStretch()
        layout.addLayout(controls)
        
        # Call flow display
        if MATPLOTLIB_AVAILABLE:
            self.setup_matplotlib_display(layout)
        else:
            self.setup_text_display(layout)
    
    def setup_matplotlib_display(self, layout):
        """Setup matplotlib-based call flow display"""
        self.figure = Figure(figsize=(12, 8), facecolor='white')
        self.canvas = FigureCanvas(self.figure)
        self.canvas.mpl_connect('button_press_event', self.on_canvas_click)
        layout.addWidget(self.canvas)
        
        # Navigation toolbar
        from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT
        toolbar = NavigationToolbar2QT(self.canvas, self)
        layout.addWidget(toolbar)
    
    def setup_text_display(self, layout):
        """Setup text-based call flow display"""
        self.text_display = QTextBrowser()
        self.text_display.setFont(QFont("Courier", 10))
        self.text_display.setStyleSheet("""
            QTextBrowser {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                font-family: 'Courier New', monospace;
            }
        """)
        layout.addWidget(self.text_display)
    
    def update_sip_packets(self, packets):
        """Update with new SIP packets"""
        self.sip_packets = [p for p in packets if p.get('is_sip', False)]
        self.analyze_call_flows()
        self.update_call_combo()
    
    def analyze_call_flows(self):
        """Analyze SIP packets to create call flows"""
        self.call_flows = {}
        
        # Group packets by Call-ID
        call_packets = defaultdict(list)
        for packet in self.sip_packets:
            call_id = packet.get('call_id')
            if call_id:
                call_packets[call_id].append(packet)
        
        # Analyze each call
        for call_id, packets in call_packets.items():
            # Sort packets by timestamp
            packets.sort(key=lambda p: p.get('timestamp', 0))
            
            # Find unique endpoints
            endpoints = set()
            for packet in packets:
                endpoints.add(packet.get('src'))
                endpoints.add(packet.get('dst'))
            endpoints = sorted(list(endpoints))
            
            # Create call flow info
            self.call_flows[call_id] = {
                'packets': packets,
                'endpoints': endpoints,
                'start_time': packets[0].get('timestamp', 0) if packets else 0,
                'end_time': packets[-1].get('timestamp', 0) if packets else 0,
                'duration': 0,
                'status': self.determine_call_status(packets)
            }
            
            if packets:
                start_time = packets[0].get('timestamp', 0)
                end_time = packets[-1].get('timestamp', 0)
                self.call_flows[call_id]['duration'] = end_time - start_time
    
    def determine_call_status(self, packets):
        """Determine call status from packets"""
        methods = [p.get('sip_method') for p in packets if p.get('sip_method')]
        responses = [p.get('sip_response_code') for p in packets if p.get('sip_response_code')]
        
        if 'INVITE' in methods:
            if 200 in responses:
                if 'BYE' in methods:
                    return 'Completed'
                else:
                    return 'Established'
            elif any(code >= 400 for code in responses if code):
                return 'Failed'
            else:
                return 'In Progress'
        elif 'REGISTER' in methods:
            return 'Registration'
        elif 'OPTIONS' in methods:
            return 'Options'
        else:
            return 'Unknown'
    
    def update_call_combo(self):
        """Update call selection combo box"""
        current_call = self.call_combo.currentText()
        self.call_combo.clear()
        
        if not self.call_flows:
            self.call_combo.addItem("No calls found")
            return
        
        for call_id, call_info in self.call_flows.items():
            # Create display text with call info
            start_time = datetime.fromtimestamp(call_info['start_time']).strftime('%H:%M:%S')
            duration = format_duration(call_info['duration'])
            status = call_info['status']
            display_text = f"{call_id[:16]}... - {start_time} ({duration}) [{status}]"
            self.call_combo.addItem(display_text, call_id)
        
        # Restore selection if possible
        if current_call:
            index = self.call_combo.findText(current_call)
            if index >= 0:
                self.call_combo.setCurrentIndex(index)
    
    def on_call_selected(self, display_text):
        """Handle call selection"""
        if display_text == "No calls found":
            return
            
        # Get call ID from combo box data
        current_index = self.call_combo.currentIndex()
        if current_index >= 0:
            call_id = self.call_combo.itemData(current_index)
            if call_id and call_id in self.call_flows:
                self.selected_call = call_id
                self.display_call_flow(call_id)
                self.call_selected.emit(call_id)
    
    def display_call_flow(self, call_id):
        """Display call flow for selected call"""
        if call_id not in self.call_flows:
            return
        
        call_info = self.call_flows[call_id]
        
        if MATPLOTLIB_AVAILABLE:
            self.draw_matplotlib_flow(call_info)
        else:
            self.draw_text_flow(call_info)
    
    def draw_matplotlib_flow(self, call_info):
        """Draw call flow using matplotlib"""
        self.figure.clear()
        
        packets = call_info['packets']
        endpoints = call_info['endpoints']
        
        if len(endpoints) < 2:
            ax = self.figure.add_subplot(111)
            ax.text(0.5, 0.5, 'Need at least 2 endpoints for call flow', 
                   ha='center', va='center', transform=ax.transAxes)
            self.canvas.draw()
            return
        
        ax = self.figure.add_subplot(111)
        
        # Layout parameters
        endpoint_spacing = 1.0 / (len(endpoints) - 1) if len(endpoints) > 1 else 0
        y_start = 0.9
        y_spacing = 0.8 / max(len(packets), 1)
        
        # Draw endpoint columns
        endpoint_positions = {}
        for i, endpoint in enumerate(endpoints):
            x_pos = i * endpoint_spacing
            endpoint_positions[endpoint] = x_pos
            
            # Endpoint header
            ax.text(x_pos, y_start + 0.05, endpoint, ha='center', va='bottom', 
                   fontsize=10, fontweight='bold', 
                   bbox=dict(boxstyle="round,pad=0.3", facecolor='lightblue'))
            
            # Vertical timeline
            ax.plot([x_pos, x_pos], [y_start, y_start - len(packets) * y_spacing], 
                   'k--', alpha=0.3, linewidth=1)
        
        # Draw messages
        for i, packet in enumerate(packets):
            y_pos = y_start - (i + 1) * y_spacing
            src = packet.get('src')
            dst = packet.get('dst')
            
            if src in endpoint_positions and dst in endpoint_positions:
                src_x = endpoint_positions[src]
                dst_x = endpoint_positions[dst]
                
                # Message arrow
                arrow_props = dict(arrowstyle='->', lw=1.5)
                method = packet.get('sip_method')
                response_code = packet.get('sip_response_code')
                
                if method:
                    color = get_sip_method_color(method)
                    label = method
                elif response_code:
                    color = get_sip_response_color(response_code)
                    status_text = SIP_RESPONSE_CODES.get(response_code, 'Unknown')
                    label = f"{response_code} {status_text}"
                else:
                    color = '#666666'
                    label = 'SIP Message'
                
                arrow_props['color'] = color
                
                # Draw arrow
                ax.annotate('', xy=(dst_x, y_pos), xytext=(src_x, y_pos),
                           arrowprops=arrow_props)
                
                # Message label
                mid_x = (src_x + dst_x) / 2
                ax.text(mid_x, y_pos + 0.01, label, ha='center', va='bottom',
                       fontsize=8, color=color, fontweight='bold')
                
                # Timestamp
                timestamp_str = packet.get('timestamp_str', '')
                ax.text(-0.1, y_pos, timestamp_str, ha='right', va='center',
                       fontsize=7, color='gray')
        
        # Formatting
        ax.set_xlim(-0.15, 1.1)
        ax.set_ylim(y_start - len(packets) * y_spacing - 0.1, y_start + 0.1)
        ax.set_aspect('equal')
        ax.axis('off')
        
        # Title
        call_id = call_info.get('packets', [{}])[0].get('call_id', 'Unknown')
        duration = format_duration(call_info.get('duration', 0))
        status = call_info.get('status', 'Unknown')
        
        title = f"SIP Call Flow - {call_id[:32]}{'...' if len(call_id) > 32 else ''}\n"
        title += f"Duration: {duration} | Status: {status} | Packets: {len(packets)}"
        ax.set_title(title, fontsize=12, fontweight='bold', pad=20)
        
        self.figure.tight_layout()
        self.canvas.draw()
    
    def draw_text_flow(self, call_info):
        """Draw call flow using text display"""
        packets = call_info['packets']
        endpoints = call_info['endpoints']
        call_id = call_info.get('packets', [{}])[0].get('call_id', 'Unknown')
        
        # Generate text-based call flow
        text = f"SIP Call Flow Analysis\n"
        text += f"{'=' * 60}\n\n"
        text += f"Call ID: {call_id}\n"
        text += f"Status: {call_info.get('status', 'Unknown')}\n"
        text += f"Duration: {format_duration(call_info.get('duration', 0))}\n"
        text += f"Endpoints: {', '.join(endpoints)}\n"
        text += f"Total Packets: {len(packets)}\n\n"
        
        # Create endpoint layout
        if len(endpoints) >= 2:
            ep1, ep2 = endpoints[0], endpoints[1]
            text += f"{ep1:<25} {'':>15} {ep2:>25}\n"
            text += f"{'-' * 25} {'':>15} {'-' * 25}\n"
            
            for i, packet in enumerate(packets):
                timestamp = packet.get('timestamp_str', '')
                src = packet.get('src')
                dst = packet.get('dst')
                
                method = packet.get('sip_method')
                response_code = packet.get('sip_response_code')
                
                if method:
                    msg = method
                elif response_code:
                    status_text = SIP_RESPONSE_CODES.get(response_code, 'Unknown')
                    msg = f"{response_code} {status_text}"
                else:
                    msg = 'SIP'
                
                # Format message flow
                if src == ep1:
                    # Left to right
                    text += f"{timestamp:<8} {msg:<15} {'--->':<15} {'':<25}\n"
                else:
                    # Right to left
                    text += f"{timestamp:<8} {'':<15} {'<---':<15} {msg:<25}\n"
        
        text += "\n" + "=" * 60 + "\n"
        text += "Packet Details:\n"
        text += "-" * 60 + "\n"
        
        for i, packet in enumerate(packets, 1):
            text += f"{i:2d}. {packet.get('timestamp_str', ''):<10} "
            text += f"{packet.get('src', ''):<15} -> {packet.get('dst', ''):<15} "
            
            if packet.get('sip_method'):
                text += f"{packet.get('sip_method'):<10}"
            elif packet.get('sip_response_code'):
                code = packet.get('sip_response_code')
                status_text = SIP_RESPONSE_CODES.get(code, 'Unknown')
                text += f"{code} {status_text}"
            
            text += f" [{packet.get('length', 0)} bytes]\n"
        
        self.text_display.setPlainText(text)
    
    def on_canvas_click(self, event):
        """Handle canvas click events"""
        if not self.selected_call or not event.inaxes:
            return
        
        call_info = self.call_flows[self.selected_call]
        packets = call_info['packets']
        
        # Find clicked packet based on y-coordinate
        y_start = 0.9
        y_spacing = 0.8 / max(len(packets), 1)
        
        for i, packet in enumerate(packets):
            y_pos = y_start - (i + 1) * y_spacing
            if abs(event.ydata - y_pos) < y_spacing / 2:
                self.packet_selected.emit(packet)
                break
    
    def refresh_calls(self):
        """Refresh call flow analysis"""
        self.analyze_call_flows()
        self.update_call_combo()
        if self.selected_call and self.selected_call in self.call_flows:
            self.display_call_flow(self.selected_call)
    
    def export_diagram(self):
        """Export call flow diagram"""
        if not self.selected_call:
            QMessageBox.information(self, "Export", "Please select a call first")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 'Export Call Flow', 
            f'call_flow_{self.selected_call[:8]}.png',
            'PNG Files (*.png);;PDF Files (*.pdf);;SVG Files (*.svg)'
        )
        
        if filename:
            try:
                if MATPLOTLIB_AVAILABLE:
                    self.figure.savefig(filename, dpi=300, bbox_inches='tight')
                    QMessageBox.information(self, "Export", f"Call flow exported to {filename}")
                else:
                    # Export text version
                    with open(filename.replace('.png', '.txt'), 'w') as f:
                        f.write(self.text_display.toPlainText())
                    QMessageBox.information(self, "Export", f"Call flow exported to text file")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export: {e}")

class RTPStreamAnalyzer(QWidget):
    """RTP stream analysis widget"""
    
    def __init__(self):
        super().__init__()
        self.rtp_packets = []
        self.stream_stats = {}
        self.setup_ui()
    
    def setup_ui(self):
        """Setup RTP analyzer UI"""
        layout = QVBoxLayout(self)
        
        # Controls
        controls = QHBoxLayout()
        
        self.analyze_btn = QPushButton("Analyze RTP Streams")
        self.analyze_btn.clicked.connect(self.analyze_streams)
        controls.addWidget(self.analyze_btn)
        
        self.export_btn = QPushButton("Export Analysis")
        self.export_btn.clicked.connect(self.export_analysis)
        controls.addWidget(self.export_btn)
        
        controls.addStretch()
        layout.addLayout(controls)
        
        # Stream table
        self.stream_table = QTableWidget()
        self.stream_table.setColumnCount(8)
        self.stream_table.setHorizontalHeaderLabels([
            'Source', 'Destination', 'SSRC', 'Codec', 
            'Packets', 'Bytes', 'Duration', 'Packet Loss %'
        ])
        
        header = self.stream_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(self.stream_table)
        
        # Statistics display
        self.stats_text = QTextBrowser()
        self.stats_text.setMaximumHeight(200)
        layout.addWidget(self.stats_text)
    
    def update_rtp_packets(self, packets):
        """Update with new RTP packets"""
        self.rtp_packets = [p for p in packets if p.get('is_rtp', False)]
        if self.rtp_packets:
            self.analyze_streams()
    
    def analyze_streams(self):
        """Analyze RTP streams"""
        if not self.rtp_packets:
            self.stats_text.setPlainText("No RTP packets found")
            return
        
        # Group packets by stream
        streams = defaultdict(list)
        
        for packet in self.rtp_packets:
            stream_key = (
                packet.get('src'), packet.get('sport'),
                packet.get('dst'), packet.get('dport'),
                packet.get('rtp_ssrc')
            )
            streams[stream_key].append(packet)
        
        # Analyze each stream
        self.stream_stats = {}
        for stream_key, packets in streams.items():
            self.stream_stats[stream_key] = self.analyze_single_stream(packets)
        
        self.update_stream_table()
        self.update_stats_display()
    
    def analyze_single_stream(self, packets):
        """Analyze a single RTP stream"""
        if not packets:
            return {}
        
        # Sort packets by timestamp
        packets.sort(key=lambda p: p.get('timestamp', 0))
        
        # Basic stats
        total_packets = len(packets)
        total_bytes = sum(p.get('length', 0) for p in packets)
        
        # Time analysis
        start_time = packets[0].get('timestamp', 0)
        end_time = packets[-1].get('timestamp', 0)
        duration = end_time - start_time
        
        # Payload type analysis
        payload_types = set(p.get('rtp_payload_type') for p in packets if p.get('rtp_payload_type') is not None)
        most_common_pt = max(payload_types) if payload_types else 0
        codec_name = RTP_PAYLOAD_TYPES.get(most_common_pt, f'Unknown({most_common_pt})')
        
        # Packet loss estimation (simplified)
        # In real implementation, would analyze sequence numbers
        expected_packets = int(duration * 50) if duration > 0 else total_packets  # Assume 50 pps
        packet_loss = max(0, (expected_packets - total_packets) / expected_packets * 100) if expected_packets > 0 else 0
        
        # Jitter estimation (simplified)
        if len(packets) > 1:
            intervals = []
            for i in range(1, len(packets)):
                interval = packets[i].get('timestamp', 0) - packets[i-1].get('timestamp', 0)
                intervals.append(interval)
            
            avg_interval = sum(intervals) / len(intervals)
            jitter = sum(abs(interval - avg_interval) for interval in intervals) / len(intervals)
        else:
            jitter = 0
        
        return {
            'packets': packets,
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'duration': duration,
            'start_time': start_time,
            'end_time': end_time,
            'codec': codec_name,
            'payload_type': most_common_pt,
            'packet_loss_percent': packet_loss,
            'jitter': jitter,
            'bitrate': (total_bytes * 8 / duration) if duration > 0 else 0
        }
    
    def update_stream_table(self):
        """Update the stream table with analysis results"""
        self.stream_table.setRowCount(len(self.stream_stats))
        
        for row, (stream_key, stats) in enumerate(self.stream_stats.items()):
            src_ip, src_port, dst_ip, dst_port, ssrc = stream_key
            
            # Source
            self.stream_table.setItem(row, 0, QTableWidgetItem(f"{src_ip}:{src_port}"))
            
            # Destination
            self.stream_table.setItem(row, 1, QTableWidgetItem(f"{dst_ip}:{dst_port}"))
            
            # SSRC
            ssrc_text = f"0x{ssrc:08x}" if ssrc else "Unknown"
            self.stream_table.setItem(row, 2, QTableWidgetItem(ssrc_text))
            
            # Codec
            self.stream_table.setItem(row, 3, QTableWidgetItem(stats.get('codec', 'Unknown')))
            
            # Packets
            self.stream_table.setItem(row, 4, QTableWidgetItem(str(stats.get('total_packets', 0))))
            
            # Bytes
            bytes_text = f"{stats.get('total_bytes', 0):,}"
            self.stream_table.setItem(row, 5, QTableWidgetItem(bytes_text))
            
            # Duration
            duration_text = format_duration(stats.get('duration', 0))
            self.stream_table.setItem(row, 6, QTableWidgetItem(duration_text))
            
            # Packet Loss
            loss_text = f"{stats.get('packet_loss_percent', 0):.1f}%"
            item = QTableWidgetItem(loss_text)
            # Color code packet loss
            loss_percent = stats.get('packet_loss_percent', 0)
            if loss_percent > 5:
                item.setBackground(QBrush(QColor('#e74c3c')))  # Red
            elif loss_percent > 2:
                item.setBackground(QBrush(QColor('#f39c12')))  # Orange
            else:
                item.setBackground(QBrush(QColor('#2ecc71')))  # Green
            self.stream_table.setItem(row, 7, item)
    
    def update_stats_display(self):
        """Update statistics display"""
        if not self.stream_stats:
            return
        
        total_streams = len(self.stream_stats)
        total_packets = sum(stats.get('total_packets', 0) for stats in self.stream_stats.values())
        total_bytes = sum(stats.get('total_bytes', 0) for stats in self.stream_stats.values())
        avg_loss = sum(stats.get('packet_loss_percent', 0) for stats in self.stream_stats.values()) / total_streams
        
        # Codec distribution
        codecs = defaultdict(int)
        for stats in self.stream_stats.values():
            codecs[stats.get('codec', 'Unknown')] += 1
        
        # Quality assessment
        quality_issues = []
        high_loss_streams = sum(1 for stats in self.stream_stats.values() if stats.get('packet_loss_percent', 0) > 2)
        if high_loss_streams > 0:
            quality_issues.append(f"{high_loss_streams} streams with >2% packet loss")
        
        low_bitrate_streams = sum(1 for stats in self.stream_stats.values() if stats.get('bitrate', 0) < 64000)
        if low_bitrate_streams > 0:
            quality_issues.append(f"{low_bitrate_streams} streams with low bitrate")
        
        stats_text = f"""RTP Stream Analysis Summary
{'=' * 50}

Total Streams: {total_streams}
Total RTP Packets: {total_packets:,}
Total Bytes: {total_bytes:,} ({total_bytes/1024/1024:.1f} MB)
Average Packet Loss: {avg_loss:.1f}%

Codec Distribution:
{'-' * 20}
"""
        
        for codec, count in sorted(codecs.items()):
            percentage = (count / total_streams * 100) if total_streams > 0 else 0
            stats_text += f"{codec:<15}: {count:>3} ({percentage:>5.1f}%)\n"
        
        if quality_issues:
            stats_text += f"\nQuality Issues:\n{'-' * 20}\n"
            for issue in quality_issues:
                stats_text += f"• {issue}\n"
        else:
            stats_text += f"\nQuality Assessment: Good (No major issues detected)\n"
        
        self.stats_text.setPlainText(stats_text)
    
    def export_analysis(self):
        """Export RTP analysis results"""
        if not self.stream_stats:
            QMessageBox.information(self, "Export", "No analysis data to export")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 'Export RTP Analysis', 
            f'rtp_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
            'CSV Files (*.csv);;Text Files (*.txt)'
        )
        
        if not filename:
            return
        
        try:
            if filename.endswith('.csv'):
                self.export_csv(filename)
            else:
                self.export_text(filename)
            
            QMessageBox.information(self, "Export", f"Analysis exported to {filename}")
            
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export: {e}")
    
    def export_csv(self, filename):
        """Export analysis to CSV"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'SSRC',
                'Codec', 'Packets', 'Bytes', 'Duration (s)', 'Packet Loss %', 
                'Jitter (ms)', 'Bitrate (bps)'
            ])
            
            # Data
            for stream_key, stats in self.stream_stats.items():
                src_ip, src_port, dst_ip, dst_port, ssrc = stream_key
                writer.writerow([
                    src_ip, src_port, dst_ip, dst_port, 
                    f"0x{ssrc:08x}" if ssrc else "Unknown",
                    stats.get('codec', 'Unknown'),
                    stats.get('total_packets', 0),
                    stats.get('total_bytes', 0),
                    f"{stats.get('duration', 0):.3f}",
                    f"{stats.get('packet_loss_percent', 0):.1f}",
                    f"{stats.get('jitter', 0) * 1000:.2f}",
                    f"{stats.get('bitrate', 0):.0f}"
                ])
    
    def export_text(self, filename):
        """Export analysis to text file"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(self.stats_text.toPlainText())
            f.write("\n\nDetailed Stream Information:\n")
            f.write("=" * 60 + "\n")
            
            for i, (stream_key, stats) in enumerate(self.stream_stats.items(), 1):
                src_ip, src_port, dst_ip, dst_port, ssrc = stream_key
                f.write(f"\nStream {i}:\n")
                f.write(f"  Source: {src_ip}:{src_port}\n")
                f.write(f"  Destination: {dst_ip}:{dst_port}\n")
                f.write(f"  SSRC: 0x{ssrc:08x}" if ssrc else "Unknown")
                f.write(f"\n  Codec: {stats.get('codec', 'Unknown')}\n")
                f.write(f"  Packets: {stats.get('total_packets', 0):,}\n")
                f.write(f"  Bytes: {stats.get('total_bytes', 0):,}\n")
                f.write(f"  Duration: {format_duration(stats.get('duration', 0))}\n")
                f.write(f"  Packet Loss: {stats.get('packet_loss_percent', 0):.1f}%\n")
                f.write(f"  Jitter: {stats.get('jitter', 0) * 1000:.2f} ms\n")
                f.write(f"  Bitrate: {stats.get('bitrate', 0):,.0f} bps\n")

class VoiceQualityAnalyzer(QWidget):
    """Voice quality analysis and MOS scoring"""
    
    def __init__(self):
        super().__init__()
        self.call_data = {}
        self.quality_scores = {}
        self.setup_ui()
    
    def setup_ui(self):
        """Setup voice quality analyzer UI"""
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Voice Quality Analysis (MOS Estimation)")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; padding: 10px;")
        layout.addWidget(title)
        
        # Controls
        controls = QHBoxLayout()
        
        self.analyze_btn = QPushButton("Analyze Voice Quality")
        self.analyze_btn.clicked.connect(self.analyze_quality)
        controls.addWidget(self.analyze_btn)
        
        controls.addStretch()
        layout.addLayout(controls)
        
        # Results table
        self.quality_table = QTableWidget()
        self.quality_table.setColumnCount(6)
        self.quality_table.setHorizontalHeaderLabels([
            'Call ID', 'Duration', 'Codec', 'Avg Loss %', 'Avg Jitter (ms)', 'MOS Score'
        ])
        
        header = self.quality_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(self.quality_table)
        
        # MOS explanation
        mos_info = QTextBrowser()
        mos_info.setMaximumHeight(120)
        mos_info.setHtml("""
        <h4>MOS (Mean Opinion Score) Scale:</h4>
        <table border="1" style="border-collapse: collapse;">
        <tr><td><b>Score</b></td><td><b>Quality</b></td><td><b>Description</b></td></tr>
        <tr><td>4.3-5.0</td><td>Excellent</td><td>Imperceptible impairments</td></tr>
        <tr><td>4.0-4.3</td><td>Good</td><td>Perceptible but not annoying</td></tr>
        <tr><td>3.6-4.0</td><td>Fair</td><td>Slightly annoying impairments</td></tr>
        <tr><td>3.1-3.6</td><td>Poor</td><td>Annoying impairments</td></tr>
        <tr><td>2.6-3.1</td><td>Bad</td><td>Very annoying impairments</td></tr>
        </table>
        """)
        layout.addWidget(mos_info)
    
    def update_call_data(self, sip_packets, rtp_packets):
        """Update with SIP and RTP data for analysis"""
        # Group SIP packets by Call-ID
        sip_calls = defaultdict(list)
        for packet in sip_packets:
            call_id = packet.get('call_id')
            if call_id:
                sip_calls[call_id].append(packet)
        
        # Group RTP packets by potential call association
        # This is simplified - in reality would need SDP analysis
        rtp_streams = defaultdict(list)
        for packet in rtp_packets:
            # Use source/dest IP to associate with calls
            stream_key = f"{packet.get('src')}-{packet.get('dst')}"
            rtp_streams[stream_key].append(packet)
        
        self.call_data = {
            'sip_calls': sip_calls,
            'rtp_streams': rtp_streams
        }
    
    def analyze_quality(self):
        """Analyze voice quality for all calls"""
        if not self.call_data.get('sip_calls'):
            QMessageBox.information(self, "Analysis", "No SIP calls found for analysis")
            return
        
        self.quality_scores = {}
        
        for call_id, sip_packets in self.call_data['sip_calls'].items():
            # Find associated RTP streams (simplified association)
            call_endpoints = set()
            for packet in sip_packets:
                call_endpoints.add(packet.get('src'))
                call_endpoints.add(packet.get('dst'))
            
            # Find RTP streams between these endpoints
            associated_rtp = []
            for stream_key, rtp_packets in self.call_data['rtp_streams'].items():
                if any(endpoint in stream_key for endpoint in call_endpoints):
                    associated_rtp.extend(rtp_packets)
            
            # Calculate quality metrics
            quality_metrics = self.calculate_mos_score(sip_packets, associated_rtp)
            self.quality_scores[call_id] = quality_metrics
        
        self.update_quality_table()
    
    def calculate_mos_score(self, sip_packets, rtp_packets):
        """Calculate MOS score based on various quality factors"""
        if not sip_packets:
            return {'mos': 0, 'quality': 'Unknown', 'factors': {}}
        
        # Basic call information
        sip_packets.sort(key=lambda p: p.get('timestamp', 0))
        start_time = sip_packets[0].get('timestamp', 0)
        end_time = sip_packets[-1].get('timestamp', 0)
        duration = end_time - start_time
        
        # Default quality factors
        factors = {
            'duration': duration,
            'codec': 'Unknown',
            'packet_loss': 0,
            'jitter': 0,
            'call_setup_time': 0,
            'call_success': False
        }
        
        # Analyze SIP call setup
        invite_time = None
        answer_time = None
        
        for packet in sip_packets:
            if packet.get('sip_method') == 'INVITE' and invite_time is None:
                invite_time = packet.get('timestamp', 0)
            elif packet.get('sip_response_code') == 200 and answer_time is None:
                answer_time = packet.get('timestamp', 0)
        
        if invite_time and answer_time:
            factors['call_setup_time'] = answer_time - invite_time
            factors['call_success'] = True
        
        # Analyze RTP quality if available
        if rtp_packets:
            # Group by stream
            streams = defaultdict(list)
            for packet in rtp_packets:
                stream_key = (packet.get('src'), packet.get('dst'), packet.get('rtp_ssrc'))
                streams[stream_key].append(packet)
            
            # Calculate average metrics across streams
            if streams:
                total_loss = 0
                total_jitter = 0
                codecs = set()
                
                for stream_packets in streams.values():
                    stream_packets.sort(key=lambda p: p.get('timestamp', 0))
                    
                    # Codec
                    for packet in stream_packets:
                        pt = packet.get('rtp_payload_type')
                        if pt is not None:
                            codecs.add(RTP_PAYLOAD_TYPES.get(pt, f'Unknown({pt})'))
                    
                    # Simplified packet loss calculation
                    expected_duration = stream_packets[-1].get('timestamp', 0) - stream_packets[0].get('timestamp', 0)
                    expected_packets = int(expected_duration * 50)  # Assume 50 pps
                    actual_packets = len(stream_packets)
                    loss = max(0, (expected_packets - actual_packets) / expected_packets * 100) if expected_packets > 0 else 0
                    total_loss += loss
                    
                    # Simplified jitter calculation
                    if len(stream_packets) > 1:
                        intervals = []
                        for i in range(1, len(stream_packets)):
                            interval = stream_packets[i].get('timestamp', 0) - stream_packets[i-1].get('timestamp', 0)
                            intervals.append(interval)
                        
                        avg_interval = sum(intervals) / len(intervals)
                        jitter = sum(abs(interval - avg_interval) for interval in intervals) / len(intervals)
                        total_jitter += jitter
                
                factors['packet_loss'] = total_loss / len(streams)
                factors['jitter'] = (total_jitter / len(streams)) * 1000  # Convert to ms
                factors['codec'] = ', '.join(codecs) if codecs else 'Unknown'
        
        # Calculate MOS score using E-Model simplified approach
        mos_score = self.calculate_e_model_mos(factors)
        
        # Determine quality rating
        if mos_score >= 4.3:
            quality = 'Excellent'
        elif mos_score >= 4.0:
            quality = 'Good'
        elif mos_score >= 3.6:
            quality = 'Fair'
        elif mos_score >= 3.1:
            quality = 'Poor'
        else:
            quality = 'Bad'
        
        return {
            'mos': mos_score,
            'quality': quality,
            'factors': factors
        }
    
    def calculate_e_model_mos(self, factors):
        """Simplified E-Model MOS calculation"""
        # Start with perfect score
        r_factor = 93.0  # R-factor starts at 93 for G.711
        
        # Codec impairment (Ie)
        codec = factors.get('codec', 'Unknown')
        if 'PCMU' in codec or 'PCMA' in codec:
            ie = 0  # G.711 has minimal codec impairment
        elif 'G729' in codec:
            ie = 10
        elif 'G723' in codec:
            ie = 15
        else:
            ie = 5  # Default assumption
        
        # Packet loss impairment (Ie-eff)
        packet_loss = factors.get('packet_loss', 0)
        if packet_loss == 0:
            ie_eff = 0
        elif packet_loss <= 1:
            ie_eff = 2.5 * packet_loss
        elif packet_loss <= 5:
            ie_eff = 2.5 + 4 * (packet_loss - 1)
        else:
            ie_eff = 18.5 + 2 * (packet_loss - 5)
        
        # Delay impairment (Id)
        # Simplified - assume reasonable delay for now
        delay_ms = 50  # Assume 50ms one-way delay
        if delay_ms <= 150:
            id_factor = 0
        else:
            id_factor = 0.2 * (delay_ms - 150)
        
        # Equipment impairment factor (simplified)
        equipment_impairment = 0
        
        # Calculate R-factor
        r_factor = r_factor - ie - ie_eff - id_factor - equipment_impairment
        
        # Convert R-factor to MOS
        if r_factor < 0:
            mos = 1.0
        elif r_factor > 100:
            mos = 4.5
        else:
            # ITU-T G.107 conversion
            mos = 1 + 0.035 * r_factor + 7e-6 * r_factor * (r_factor - 60) * (100 - r_factor)
        
        return max(1.0, min(5.0, mos))  # Clamp between 1 and 5
    
    def update_quality_table(self):
        """Update quality results table"""
        self.quality_table.setRowCount(len(self.quality_scores))
        
        for row, (call_id, metrics) in enumerate(self.quality_scores.items()):
            factors = metrics['factors']
            
            # Call ID (truncated)
            call_id_short = call_id[:16] + '...' if len(call_id) > 16 else call_id
            self.quality_table.setItem(row, 0, QTableWidgetItem(call_id_short))
            
            # Duration
            duration_text = format_duration(factors.get('duration', 0))
            self.quality_table.setItem(row, 1, QTableWidgetItem(duration_text))
            
            # Codec
            self.quality_table.setItem(row, 2, QTableWidgetItem(factors.get('codec', 'Unknown')))
            
            # Average packet loss
            loss_text = f"{factors.get('packet_loss', 0):.1f}%"
            self.quality_table.setItem(row, 3, QTableWidgetItem(loss_text))
            
            # Average jitter
            jitter_text = f"{factors.get('jitter', 0):.1f}"
            self.quality_table.setItem(row, 4, QTableWidgetItem(jitter_text))
            
            # MOS Score with color coding
            mos_score = metrics['mos']
            mos_text = f"{mos_score:.2f} ({metrics['quality']})"
            item = QTableWidgetItem(mos_text)
            
            # Color code MOS score
            if mos_score >= 4.3:
                item.setBackground(QBrush(QColor('#27ae60')))  # Excellent - Green
            elif mos_score >= 4.0:
                item.setBackground(QBrush(QColor('#2ecc71')))  # Good - Light Green
            elif mos_score >= 3.6:
                item.setBackground(QBrush(QColor('#f1c40f')))  # Fair - Yellow
            elif mos_score >= 3.1:
                item.setBackground(QBrush(QColor('#f39c12')))  # Poor - Orange
            else:
                item.setBackground(QBrush(QColor('#e74c3c')))  # Bad - Red
            
            self.quality_table.setItem(row, 5, item)

class SIPPacketDetailsWidget(QWidget):
    """Detailed SIP packet analysis widget"""
    
    def __init__(self):
        super().__init__()
        self.current_packet = None
        self.setup_ui()
    
    def setup_ui(self):
        """Setup SIP packet details UI"""
        layout = QVBoxLayout(self)
        
        # Packet selector
        controls = QHBoxLayout()
        controls.addWidget(QLabel("SIP Packet Details:"))
        controls.addStretch()
        
        self.export_btn = QPushButton("Export Details")
        self.export_btn.clicked.connect(self.export_details)
        self.export_btn.setEnabled(False)
        controls.addWidget(self.export_btn)
        
        layout.addLayout(controls)
        
        # Details display
        self.details_text = QTextBrowser()
        self.details_text.setFont(QFont("Courier New", 9))
        self.details_text.setStyleSheet("""
            QTextBrowser {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                font-family: 'Courier New', monospace;
            }
        """)
        layout.addWidget(self.details_text)
    
    def show_packet_details(self, packet_info):
        """Show detailed SIP packet information"""
        if not packet_info.get('is_sip'):
            self.details_text.setPlainText("Selected packet is not a SIP packet")
            self.export_btn.setEnabled(False)
            return
        
        self.current_packet = packet_info
        self.export_btn.setEnabled(True)
        
        # Generate detailed analysis
        details = self.generate_sip_analysis(packet_info)
        self.details_text.setPlainText(details)
    
    def generate_sip_analysis(self, packet_info):
        """Generate detailed SIP packet analysis"""
        analysis = f"""SIP PACKET DETAILED ANALYSIS
{'=' * 80}

BASIC INFORMATION:
{'-' * 40}
Packet Number    : {packet_info.get('no', 'Unknown')}
Timestamp        : {packet_info.get('timestamp_str', 'Unknown')}
Source IP        : {packet_info.get('src', 'Unknown')}
Source Port      : {packet_info.get('sport', 'Unknown')}
Destination IP   : {packet_info.get('dst', 'Unknown')}
Destination Port : {packet_info.get('dport', 'Unknown')}
Packet Length    : {packet_info.get('length', 0)} bytes
Protocol         : {packet_info.get('protocol', 'Unknown')}

SIP INFORMATION:
{'-' * 40}
"""
        
        if packet_info.get('sip_method'):
            analysis += f"SIP Method       : {packet_info.get('sip_method')}\n"
            analysis += f"Method Type      : Request\n"
        elif packet_info.get('sip_response_code'):
            code = packet_info.get('sip_response_code')
            status_text = SIP_RESPONSE_CODES.get(code, 'Unknown')
            analysis += f"Response Code    : {code}\n"
            analysis += f"Response Text    : {status_text}\n"
            analysis += f"Method Type      : Response\n"
            
            # Response category
            if 100 <= code < 200:
                category = "Provisional Response"
            elif 200 <= code < 300:
                category = "Success Response"
            elif 300 <= code < 400:
                category = "Redirection Response"
            elif 400 <= code < 500:
                category = "Client Error Response"
            elif 500 <= code < 600:
                category = "Server Error Response"
            elif 600 <= code < 700:
                category = "Global Failure Response"
            else:
                category = "Unknown Category"
            
            analysis += f"Category         : {category}\n"
        
        call_id = packet_info.get('call_id')
        if call_id:
            analysis += f"Call-ID          : {call_id}\n"
            analysis += f"Call-ID (Short)  : {call_id[:32]}{'...' if len(call_id) > 32 else ''}\n"
        
        analysis += f"""
TRANSPORT INFORMATION:
{'-' * 40}
Transport        : {packet_info.get('protocol', 'Unknown')}
TCP Flags        : {packet_info.get('flags', 'N/A')}
Source Port Type : {'Well-known' if packet_info.get('sport', 0) < 1024 else 'Dynamic'}
Dest Port Type   : {'Well-known' if packet_info.get('dport', 0) < 1024 else 'Dynamic'}

TIMING ANALYSIS:
{'-' * 40}
"""
        
        timestamp = packet_info.get('timestamp', 0)
        if timestamp > 0:
            dt = datetime.fromtimestamp(timestamp)
            analysis += f"Full Timestamp   : {dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}\n"
            analysis += f"Time of Day      : {dt.strftime('%H:%M:%S')}\n"
            analysis += f"Date             : {dt.strftime('%Y-%m-%d')}\n"
        
        analysis += f"""
PACKET SIZE ANALYSIS:
{'-' * 40}
Total Length     : {packet_info.get('length', 0)} bytes
Size Category    : """
        
        length = packet_info.get('length', 0)
        if length < 100:
            analysis += "Very Small (< 100 bytes)\n"
        elif length < 500:
            analysis += "Small (100-499 bytes)\n"
        elif length < 1500:
            analysis += "Medium (500-1499 bytes)\n"
        else:
            analysis += "Large (>= 1500 bytes)\n"
        
        analysis += f"""
PROTOCOL ANALYSIS:
{'-' * 40}
Is SIP           : Yes
Is RTP           : {packet_info.get('is_rtp', False)}
Info String      : {packet_info.get('info', 'No info available')}

SIP MESSAGE CLASSIFICATION:
{'-' * 40}
"""
        
        # Classify SIP message
        if packet_info.get('sip_method'):
            method = packet_info.get('sip_method')
            if method in ['INVITE', 'ACK', 'BYE']:
                analysis += f"Message Class    : Call Control ({method})\n"
            elif method in ['REGISTER']:
                analysis += f"Message Class    : Registration ({method})\n"
            elif method in ['OPTIONS', 'INFO']:
                analysis += f"Message Class    : Information ({method})\n"
            elif method in ['SUBSCRIBE', 'NOTIFY']:
                analysis += f"Message Class    : Event ({method})\n"
            else:
                analysis += f"Message Class    : Other ({method})\n"
        elif packet_info.get('sip_response_code'):
            code = packet_info.get('sip_response_code')
            analysis += f"Message Class    : Response ({code})\n"
        
        # Add call flow context if available
        analysis += f"""
CALL FLOW CONTEXT:
{'-' * 40}
Call ID Present  : {'Yes' if call_id else 'No'}
"""
        
        if call_id:
            analysis += f"Call Association : Can be correlated with other packets\n"
            analysis += f"Flow Analysis    : Available via Call Flow tab\n"
        else:
            analysis += f"Call Association : Cannot correlate (no Call-ID)\n"
            analysis += f"Flow Analysis    : Not available\n"
        
        # Add recommendations
        analysis += f"""
ANALYSIS RECOMMENDATIONS:
{'-' * 40}
"""
        
        recommendations = []
        
        if packet_info.get('sip_method') == 'INVITE':
            recommendations.append("• Look for corresponding 100 Trying, 180 Ringing, and 200 OK responses")
            recommendations.append("• Check for SDP content in packet payload")
        elif packet_info.get('sip_response_code') == 200:
            recommendations.append("• Verify this is response to correct request")
            recommendations.append("• Look for ACK message to complete transaction")
        elif packet_info.get('sip_response_code', 0) >= 400:
            recommendations.append("• Investigate error cause in response text")
            recommendations.append("• Check if retry attempts were made")
        
        if not call_id:
            recommendations.append("• Missing Call-ID may indicate malformed SIP message")
        
        if recommendations:
            analysis += '\n'.join(recommendations) + '\n'
        else:
            analysis += "• No specific recommendations for this packet type\n"
        
        analysis += f"""
{'-' * 80}
End of Analysis
"""
        
        return analysis
    
    def export_details(self):
        """Export packet details to file"""
        if not self.current_packet:
            return
        
        packet_no = self.current_packet.get('no', 'unknown')
        filename, _ = QFileDialog.getSaveFileName(
            self, 'Export SIP Packet Details',
            f'sip_packet_{packet_no}_details.txt',
            'Text Files (*.txt);;All Files (*)'
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.details_text.toPlainText())
                QMessageBox.information(self, "Export", f"Details exported to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export: {e}")

class CallComparisonWidget(QWidget):
    """Compare multiple SIP calls side by side"""
    
    def __init__(self):
        super().__init__()
        self.call_data = {}
        self.selected_calls = []
        self.setup_ui()
    
    def setup_ui(self):
        """Setup call comparison UI"""
        layout = QVBoxLayout(self)
        
        # Controls
        controls = QHBoxLayout()
        
        controls.addWidget(QLabel("Compare Calls:"))
        
        self.call1_combo = QComboBox()
        controls.addWidget(QLabel("Call 1:"))
        controls.addWidget(self.call1_combo)
        
        self.call2_combo = QComboBox()
        controls.addWidget(QLabel("Call 2:"))
        controls.addWidget(self.call2_combo)
        
        self.compare_btn = QPushButton("Compare")
        self.compare_btn.clicked.connect(self.compare_calls)
        controls.addWidget(self.compare_btn)
        
        controls.addStretch()
        layout.addLayout(controls)
        
        # Comparison display
        self.comparison_text = QTextBrowser()
        self.comparison_text.setFont(QFont("Courier New", 9))
        layout.addWidget(self.comparison_text)
    
    def update_calls(self, call_flows):
        """Update available calls for comparison"""
        self.call_data = call_flows
        
        # Update combo boxes
        for combo in [self.call1_combo, self.call2_combo]:
            combo.clear()
            for call_id, call_info in call_flows.items():
                display_text = f"{call_id[:16]}... ({call_info.get('status', 'Unknown')})"
                combo.addItem(display_text, call_id)
    
    def compare_calls(self):
        """Compare selected calls"""
        call1_id = self.call1_combo.currentData()
        call2_id = self.call2_combo.currentData()
        
        if not call1_id or not call2_id:
            self.comparison_text.setPlainText("Please select two calls to compare")
            return
        
        if call1_id == call2_id:
            self.comparison_text.setPlainText("Please select two different calls")
            return
        
        call1_info = self.call_data.get(call1_id, {})
        call2_info = self.call_data.get(call2_id, {})
        
        comparison = self.generate_comparison(call1_id, call1_info, call2_id, call2_info)
        self.comparison_text.setPlainText(comparison)
    
    def generate_comparison(self, call1_id, call1_info, call2_id, call2_info):
        """Generate detailed call comparison"""
        comparison = f"""SIP CALL COMPARISON
{'=' * 80}

CALL IDENTIFIERS:
{'-' * 40}
Call 1 ID: {call1_id}
Call 2 ID: {call2_id}

BASIC COMPARISON:
{'-' * 40}
                        Call 1              Call 2              Difference
                        ------              ------              ----------
Status:                 {call1_info.get('status', 'Unknown'):<18} {call2_info.get('status', 'Unknown'):<18} {'Same' if call1_info.get('status') == call2_info.get('status') else 'Different'}
Duration:               {format_duration(call1_info.get('duration', 0)):<18} {format_duration(call2_info.get('duration', 0)):<18} {format_duration(abs(call1_info.get('duration', 0) - call2_info.get('duration', 0)))}
Packet Count:           {len(call1_info.get('packets', [])):<18} {len(call2_info.get('packets', [])):<18} {abs(len(call1_info.get('packets', [])) - len(call2_info.get('packets', [])))}
Endpoints:              {len(call1_info.get('endpoints', [])):<18} {len(call2_info.get('endpoints', [])):<18} {'Same' if len(call1_info.get('endpoints', [])) == len(call2_info.get('endpoints', [])) else 'Different'}

ENDPOINT ANALYSIS:
{'-' * 40}
Call 1 Endpoints: {', '.join(call1_info.get('endpoints', []))}
Call 2 Endpoints: {', '.join(call2_info.get('endpoints', []))}

Common Endpoints: {', '.join(set(call1_info.get('endpoints', [])) & set(call2_info.get('endpoints', [])))}

TIMING ANALYSIS:
{'-' * 40}
"""
        
        # Timing comparison
        call1_start = call1_info.get('start_time', 0)
        call2_start = call2_info.get('start_time', 0)
        
        if call1_start and call2_start:
            time_diff = abs(call1_start - call2_start)
            comparison += f"Start Time Diff:    {format_duration(time_diff)}\n"
            
            if call1_start < call2_start:
                comparison += f"Call Order:         Call 1 started first\n"
            elif call2_start < call1_start:
                comparison += f"Call Order:         Call 2 started first\n"
            else:
                comparison += f"Call Order:         Started simultaneously\n"
        
        # Message flow comparison
        call1_packets = call1_info.get('packets', [])
        call2_packets = call2_info.get('packets', [])
        
        comparison += f"""
MESSAGE FLOW COMPARISON:
{'-' * 40}
Call 1 Message Sequence:
"""
        
        for i, packet in enumerate(call1_packets[:10], 1):  # Show first 10
            method = packet.get('sip_method') or f"Response {packet.get('sip_response_code', 'Unknown')}"
            comparison += f"  {i:2d}. {packet.get('src', '')} -> {packet.get('dst', '')}: {method}\n"
        
        if len(call1_packets) > 10:
            comparison += f"  ... and {len(call1_packets) - 10} more messages\n"
        
        comparison += f"\nCall 2 Message Sequence:\n"
        
        for i, packet in enumerate(call2_packets[:10], 1):  # Show first 10
            method = packet.get('sip_method') or f"Response {packet.get('sip_response_code', 'Unknown')}"
            comparison += f"  {i:2d}. {packet.get('src', '')} -> {packet.get('dst', '')}: {method}\n"
        
        if len(call2_packets) > 10:
            comparison += f"  ... and {len(call2_packets) - 10} more messages\n"
        
        # Pattern analysis
        call1_methods = [p.get('sip_method') for p in call1_packets if p.get('sip_method')]
        call2_methods = [p.get('sip_method') for p in call2_packets if p.get('sip_method')]
        
        comparison += f"""
PATTERN ANALYSIS:
{'-' * 40}
Call 1 Methods:     {', '.join(call1_methods)}
Call 2 Methods:     {', '.join(call2_methods)}
Common Methods:     {', '.join(set(call1_methods) & set(call2_methods))}
Call 1 Only:        {', '.join(set(call1_methods) - set(call2_methods))}
Call 2 Only:        {', '.join(set(call2_methods) - set(call1_methods))}

SUMMARY:
{'-' * 40}
"""
        
        # Generate summary
        similarities = []
        differences = []
        
        if call1_info.get('status') == call2_info.get('status'):
            similarities.append("Same call status")
        else:
            differences.append("Different call status")
        
        if set(call1_info.get('endpoints', [])) == set(call2_info.get('endpoints', [])):
            similarities.append("Same endpoints")
        else:
            differences.append("Different endpoints")
        
        if set(call1_methods) == set(call2_methods):
            similarities.append("Same SIP methods used")
        else:
            differences.append("Different SIP methods used")
        
        duration_diff = abs(call1_info.get('duration', 0) - call2_info.get('duration', 0))
        if duration_diff < 5:  # Within 5 seconds
            similarities.append("Similar duration")
        else:
            differences.append("Significantly different duration")
        
        if similarities:
            comparison += "Similarities:\n"
            for sim in similarities:
                comparison += f"  • {sim}\n"
        
        if differences:
            comparison += "\nDifferences:\n"
            for diff in differences:
                comparison += f"  • {diff}\n"
        
        return comparison
 
#Part 4 
#!/usr/bin/env python3
"""
NetHawk Pro - Part 4: Main Application & UI Integration
Advanced PCAP and SIP Analysis Tool - Main Application

This file contains:
- Main application window
- UI integration and event handling  
- Menu and toolbar setup
- Settings management
- Application entry point
"""

class ModernPacketTable(QTableWidget):
    """Enhanced packet table for PCAP analysis"""
    
    packet_selected = pyqtSignal(dict)
    filter_changed = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.packets = []
        self.filtered_packets = []
        self.setup_table()
        self.setup_context_menu()
        self.itemSelectionChanged.connect(self.on_selection)
    
    def setup_table(self):
        """Setup enhanced table with modern styling"""
        headers = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        
        # Configure column sizing
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # No.
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Time
        header.setSectionResizeMode(2, QHeaderView.Stretch)           # Source
        header.setSectionResizeMode(3, QHeaderView.Stretch)           # Destination
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Protocol
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Length
        header.setSectionResizeMode(6, QHeaderView.Stretch)           # Info
        
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
            menu.addAction("Copy Source IP", self.copy_source_ip)
            menu.addAction("Copy Destination IP", self.copy_dest_ip)
            menu.addAction("Filter by Source", self.filter_by_source)
            menu.addAction("Filter by Destination", self.filter_by_dest)
            menu.addAction("Filter by Protocol", self.filter_by_protocol)
            menu.exec_(self.mapToGlobal(position))
    
    def copy_source_ip(self):
        """Copy source IP to clipboard"""
        current_row = self.currentRow()
        if 0 <= current_row < len(self.filtered_packets):
            ip = self.filtered_packets[current_row]['src']
            QApplication.clipboard().setText(ip)
    
    def copy_dest_ip(self):
        """Copy destination IP to clipboard"""
        current_row = self.currentRow()
        if 0 <= current_row < len(self.filtered_packets):
            ip = self.filtered_packets[current_row]['dst']
            QApplication.clipboard().setText(ip)
    
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
    
    def add_packet(self, packet_info):
        """Add new packet"""
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
        """Advanced packet filtering"""
        if not filter_text:
            return self.packets.copy()
        
        search_engine = PacketSearchEngine()
        return search_engine.search_packets(self.packets, filter_text)
    
    def update_display(self):
        """Update table display with filtered packets"""
        self.setRowCount(len(self.filtered_packets))
        
        for row, packet_info in enumerate(self.filtered_packets):
            # No.
            self.setItem(row, 0, QTableWidgetItem(str(packet_info.get('no', row + 1))))
            
            # Time
            self.setItem(row, 1, QTableWidgetItem(packet_info.get('timestamp_str', '')))
            
            # Source
            src_text = f"{packet_info.get('src', '')}:{packet_info.get('sport', '')}"
            self.setItem(row, 2, QTableWidgetItem(src_text))
            
            # Destination
            dst_text = f"{packet_info.get('dst', '')}:{packet_info.get('dport', '')}"
            self.setItem(row, 3, QTableWidgetItem(dst_text))
            
            # Protocol with color
            protocol_item = QTableWidgetItem(packet_info.get('protocol', 'Unknown'))
            protocol = packet_info.get('protocol', 'Unknown')
            if protocol in PROTOCOL_COLORS:
                color = QColor(PROTOCOL_COLORS[protocol])
                protocol_item.setForeground(QBrush(color))
            self.setItem(row, 4, protocol_item)
            
            # Length
            self.setItem(row, 5, QTableWidgetItem(str(packet_info.get('length', 0))))
            
            # Info
            info_text = packet_info.get('info', '')
            if len(info_text) > 80:
                info_text = info_text[:77] + '...'
            self.setItem(row, 6, QTableWidgetItem(info_text))
            
            # Highlight SIP and RTP packets
            if packet_info.get('is_sip'):
                for col in range(self.columnCount()):
                    item = self.item(row, col)
                    if item:
                        item.setBackground(QBrush(QColor('#ffeaa7')))  # Light yellow for SIP
            elif packet_info.get('is_rtp'):
                for col in range(self.columnCount()):
                    item = self.item(row, col)
                    if item:
                        item.setBackground(QBrush(QColor('#dda0dd')))  # Light purple for RTP
        
        if len(self.filtered_packets) > 0:
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

class PacketDetailsWidget(QTextBrowser):
    """Enhanced packet details viewer"""
    
    def __init__(self):
        super().__init__()
        self.setFont(QFont("Consolas", 10))
        
    def show_packet_details(self, packet_info):
        """Display detailed packet information"""
        if packet_info.get('is_sip'):
            details_text = self.generate_sip_details(packet_info)
        else:
            details_text = self.generate_standard_details(packet_info)
        self.setPlainText(details_text)
    
    def generate_sip_details(self, packet_info):
        """Generate SIP packet details"""
        details = f"""SIP PACKET ANALYSIS
{'=' * 50}

Packet Number: {packet_info.get('no', 'Unknown')}
Timestamp: {packet_info.get('timestamp_str', 'Unknown')}
Source: {packet_info.get('src', 'Unknown')}:{packet_info.get('sport', 0)}
Destination: {packet_info.get('dst', 'Unknown')}:{packet_info.get('dport', 0)}
Length: {packet_info.get('length', 0)} bytes

SIP Information:
"""
        if packet_info.get('sip_method'):
            details += f"Method: {packet_info.get('sip_method')}\n"
        elif packet_info.get('sip_response_code'):
            code = packet_info.get('sip_response_code')
            status_text = SIP_RESPONSE_CODES.get(code, 'Unknown')
            details += f"Response: {code} {status_text}\n"
        
        if packet_info.get('call_id'):
            details += f"Call-ID: {packet_info.get('call_id')}\n"
        
        details += f"\nInfo: {packet_info.get('info', 'No additional info')}"
        return details
    
    def generate_standard_details(self, packet_info):
        """Generate standard packet details"""
        details = f"""PACKET ANALYSIS
{'=' * 50}

Packet Number: {packet_info.get('no', 'Unknown')}
Timestamp: {packet_info.get('timestamp_str', 'Unknown')}
Source: {packet_info.get('src', 'Unknown')}:{packet_info.get('sport', 0)}
Destination: {packet_info.get('dst', 'Unknown')}:{packet_info.get('dport', 0)}
Protocol: {packet_info.get('protocol', 'Unknown')}
Length: {packet_info.get('length', 0)} bytes
"""
        
        if packet_info.get('protocol') == 'TCP':
            details += f"TCP Flags: {packet_info.get('flags', 'None')}\n"
        
        if packet_info.get('is_rtp'):
            details += f"RTP Payload Type: {packet_info.get('rtp_payload_type', 'Unknown')}\n"
            details += f"RTP SSRC: 0x{packet_info.get('rtp_ssrc', 0):08x}\n"
        
        details += f"\nInfo: {packet_info.get('info', 'No additional info')}"
        return details

class NetHawkPro(QMainWindow):
    """Main NetHawk Pro application window"""
    
    def __init__(self):
        super().__init__()
        self.config = load_config()
        self.pcap_processor = PCAPProcessor()
        self.live_capture = None
        self.current_packets = []
        self.statistics_engine = StatisticsEngine()
        
        self.setup_ui()
        self.setup_menu()
        self.setup_toolbar()
        self.setup_status_bar()
        
        if self.config.get('dark_mode', True):
            self.apply_dark_theme()
        
        for directory in [self.config.get('pcap_directory', './pcaps'), 
                         self.config.get('export_directory', './exports')]:
            os.makedirs(directory, exist_ok=True)
    
    def setup_ui(self):
        """Setup main user interface"""
        self.setWindowTitle('NetHawk Pro - Advanced PCAP and SIP Analysis')
        self.setGeometry(100, 100, 1600, 1000)
        
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
        self.setup_packet_analysis_tab()
        self.setup_sip_analysis_tab()
        self.setup_rtp_analysis_tab()
        self.setup_voice_quality_tab()
        self.setup_call_comparison_tab()
    
    def create_control_panel(self):
        """Create the main control panel"""
        panel = QGroupBox("PCAP Analysis Control")
        layout = QHBoxLayout(panel)
        
        # File operations
        self.open_pcap_btn = QPushButton('Open PCAP')
        self.open_pcap_btn.clicked.connect(self.open_pcap_file)
        layout.addWidget(self.open_pcap_btn)
        
        self.save_pcap_btn = QPushButton('Save PCAP')
        self.save_pcap_btn.clicked.connect(self.save_pcap_file)
        self.save_pcap_btn.setEnabled(False)
        layout.addWidget(self.save_pcap_btn)
        
        # Live capture
        self.start_capture_btn = QPushButton('Start Live Capture')
        self.start_capture_btn.clicked.connect(self.start_live_capture)
        layout.addWidget(self.start_capture_btn)
        
        self.stop_capture_btn = QPushButton('Stop Capture')
        self.stop_capture_btn.clicked.connect(self.stop_live_capture)
        self.stop_capture_btn.setEnabled(False)
        layout.addWidget(self.stop_capture_btn)
        
        # Clear and export
        self.clear_btn = QPushButton('Clear')
        self.clear_btn.clicked.connect(self.clear_packets)
        layout.addWidget(self.clear_btn)
        
        self.export_btn = QPushButton('Export')
        self.export_btn.clicked.connect(self.export_packets)
        self.export_btn.setEnabled(False)
        layout.addWidget(self.export_btn)
        
        # Status
        self.status_label = QLabel('Ready - Load PCAP or start live capture')
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        
        # Packet count
        self.packet_count_label = QLabel('Packets: 0')
        layout.addWidget(self.packet_count_label)
        
        return panel
    
    def setup_packet_analysis_tab(self):
        """Setup main packet analysis tab"""
        packet_widget = QWidget()
        packet_layout = QVBoxLayout(packet_widget)
        
        # Search and filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel('Search/Filter:'))
        
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText('Advanced search: src:IP, dst:IP, protocol:SIP, call_id:xyz')
        self.filter_edit.textChanged.connect(self.apply_packet_filter)
        filter_layout.addWidget(self.filter_edit)
        
        # Quick filter buttons
        quick_filters = [
            ('SIP', 'protocol:SIP'),
            ('RTP', 'protocol:RTP'),
            ('Clear', '')
        ]
        
        for name, filter_text in quick_filters:
            btn = QPushButton(name)
            btn.clicked.connect(lambda checked, f=filter_text: self.filter_edit.setText(f))
            filter_layout.addWidget(btn)
        
        packet_layout.addLayout(filter_layout)
        
        # Splitter for packets and details
        splitter = QSplitter(Qt.Vertical)
        
        # Packet table
        self.packet_table = ModernPacketTable()
        self.packet_table.packet_selected.connect(self.show_packet_details)
        self.packet_table.filter_changed.connect(lambda f: self.filter_edit.setText(f))
        splitter.addWidget(self.packet_table)
        
        # Bottom panel with details
        bottom_tabs = QTabWidget()
        
        # Packet details
        self.packet_details = PacketDetailsWidget()
        bottom_tabs.addTab(self.packet_details, "Packet Details")
        
        # Hex dump
        self.hex_dump = QTextBrowser()
        self.hex_dump.setFont(QFont("Courier New", 9))
        bottom_tabs.addTab(self.hex_dump, "Hex Dump")
        
        # Statistics
        self.create_statistics_widget()
        bottom_tabs.addTab(self.statistics_widget, "Statistics")
        
        splitter.addWidget(bottom_tabs)
        splitter.setSizes([600, 300])
        
        packet_layout.addWidget(splitter)
        self.tab_widget.addTab(packet_widget, "Packet Analysis")
    
    def setup_sip_analysis_tab(self):
        """Setup SIP analysis tab"""
        sip_widget = QWidget()
        sip_layout = QVBoxLayout(sip_widget)
        
        # SIP call flow
        self.sip_call_flow = SIPCallFlowWidget()
        self.sip_call_flow.call_selected.connect(self.on_sip_call_selected)
        self.sip_call_flow.packet_selected.connect(self.show_packet_details)
        sip_layout.addWidget(self.sip_call_flow)
        
        self.tab_widget.addTab(sip_widget, "SIP Call Flow")
    
    def setup_rtp_analysis_tab(self):
        """Setup RTP analysis tab"""
        rtp_widget = QWidget()
        rtp_layout = QVBoxLayout(rtp_widget)
        
        # RTP stream analyzer
        self.rtp_analyzer = RTPStreamAnalyzer()
        rtp_layout.addWidget(self.rtp_analyzer)
        
        self.tab_widget.addTab(rtp_widget, "RTP Analysis")
    
    def setup_voice_quality_tab(self):
        """Setup voice quality analysis tab"""
        quality_widget = QWidget()
        quality_layout = QVBoxLayout(quality_widget)
        
        # Voice quality analyzer
        self.voice_quality = VoiceQualityAnalyzer()
        quality_layout.addWidget(self.voice_quality)
        
        self.tab_widget.addTab(quality_widget, "Voice Quality")
    
    def setup_call_comparison_tab(self):
        """Setup call comparison tab"""
        comparison_widget = QWidget()
        comparison_layout = QVBoxLayout(comparison_widget)
        
        # Call comparison
        self.call_comparison = CallComparisonWidget()
        comparison_layout.addWidget(self.call_comparison)
        
        self.tab_widget.addTab(comparison_widget, "Call Comparison")
    
    def create_statistics_widget(self):
        """Create statistics widget"""
        self.statistics_widget = QWidget()
        stats_layout = QVBoxLayout(self.statistics_widget)
        
        # Statistics display
        self.statistics_text = QTextBrowser()
        self.statistics_text.setFont(QFont("Consolas", 9))
        self.statistics_text.setMaximumHeight(200)
        stats_layout.addWidget(self.statistics_text)
        
        # Update timer for statistics
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_statistics_display)
        self.stats_timer.start(5000)  # Update every 5 seconds
    
    def setup_menu(self):
        """Setup menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        file_menu.addAction('Open PCAP File', self.open_pcap_file, 'Ctrl+O')
        file_menu.addAction('Save PCAP File', self.save_pcap_file, 'Ctrl+S')
        file_menu.addSeparator()
        file_menu.addAction('Export Packets', self.export_packets, 'Ctrl+E')
        file_menu.addSeparator()
        file_menu.addAction('Exit', self.close, 'Ctrl+Q')
        
        # Capture menu
        capture_menu = menubar.addMenu('Capture')
        capture_menu.addAction('Start Live Capture', self.start_live_capture, 'F5')
        capture_menu.addAction('Stop Live Capture', self.stop_live_capture, 'F6')
        capture_menu.addSeparator()
        capture_menu.addAction('Clear All Packets', self.clear_packets, 'Ctrl+L')
        
        # Analysis menu
        analysis_menu = menubar.addMenu('Analysis')
        analysis_menu.addAction('Analyze SIP Calls', self.analyze_sip_calls)
        analysis_menu.addAction('Analyze RTP Streams', self.analyze_rtp_streams)
        analysis_menu.addAction('Analyze Voice Quality', self.analyze_voice_quality)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        help_menu.addAction('Help', self.show_help, 'F1')
        help_menu.addAction('About', self.show_about)
    
    def setup_toolbar(self):
        """Setup toolbar"""
        toolbar = self.addToolBar('Main')
        
        # File operations
        toolbar.addAction('Open', self.open_pcap_file)
        toolbar.addAction('Save', self.save_pcap_file)
        toolbar.addSeparator()
        
        # Capture operations  
        toolbar.addAction('Start', self.start_live_capture)
        toolbar.addAction('Stop', self.stop_live_capture)
        toolbar.addSeparator()
        
        # Export
        toolbar.addAction('Export', self.export_packets)
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Status widgets
        self.total_packets_label = QLabel("Packets: 0")
        self.status_bar.addPermanentWidget(self.total_packets_label)
        
        self.sip_packets_label = QLabel("SIP: 0")
        self.status_bar.addPermanentWidget(self.sip_packets_label)
        
        self.rtp_packets_label = QLabel("RTP: 0") 
        self.status_bar.addPermanentWidget(self.rtp_packets_label)
        
        self.calls_label = QLabel("Calls: 0")
        self.status_bar.addPermanentWidget(self.calls_label)
        
        self.status_bar.showMessage("NetHawk Pro - Ready to analyze PCAP files and live traffic")
    
    def apply_dark_theme(self):
        """Apply dark theme"""
        self.setStyleSheet("""
        QMainWindow { background-color: #2c3e50; color: white; }
        QTabWidget::pane { border: 1px solid #34495e; background-color: #2c3e50; }
        QTabBar::tab { background-color: #34495e; color: white; padding: 8px 16px; margin: 2px; border-radius: 4px; }
        QTabBar::tab:selected { background-color: #3498db; }
        QGroupBox { font-weight: bold; border: 2px solid #34495e; border-radius: 5px; margin: 10px 0px; padding-top: 10px; color: white; }
        QGroupBox::title { color: #3498db; padding: 0 5px 0 5px; }
        QPushButton { background-color: #34495e; color: white; border: 1px solid #2c3e50; padding: 8px 16px; border-radius: 4px; font-weight: bold; }
        QPushButton:hover { background-color: #3498db; }
        QPushButton:disabled { background-color: #7f8c8d; }
        QLineEdit, QComboBox { background-color: #34495e; color: white; border: 1px solid #2c3e50; padding: 5px; border-radius: 3px; }
        QTextBrowser { background-color: #2c3e50; color: white; }
        QLabel { color: white; }
        """)
    
    # Core functionality methods
    def open_pcap_file(self):
        """Open and load PCAP file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, 'Open PCAP File', 
            self.config.get('pcap_directory', './pcaps'),
            'PCAP Files (*.pcap *.cap *.pcapng);;All Files (*)'
        )
        
        if not filename:
            return
        
        progress = QProgressDialog("Loading PCAP file...", "Cancel", 0, 100, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.show()
        
        def progress_callback(percent, message):
            progress.setValue(percent)
            progress.setLabelText(message)
            QApplication.processEvents()
            return not progress.wasCanceled()
        
        try:
            success, message = self.pcap_processor.load_pcap_file(filename, progress_callback)
            progress.close()
            
            if success:
                self.current_packets = self.pcap_processor.get_packets()
                self.update_all_displays()
                self.status_label.setText(f"Loaded: {os.path.basename(filename)}")
                self.status_bar.showMessage(message)
                self.save_pcap_btn.setEnabled(True)
                self.export_btn.setEnabled(True)
                self.setWindowTitle(f'NetHawk Pro - {os.path.basename(filename)}')
            else:
                QMessageBox.critical(self, "Load Error", message)
                
        except Exception as e:
            progress.close()
            QMessageBox.critical(self, "Load Error", f"Failed to load PCAP: {str(e)}")
    
    def save_pcap_file(self):
        """Save packets to PCAP file"""
        if not self.current_packets:
            QMessageBox.information(self, "Save PCAP", "No packets to save")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 'Save PCAP File',
            self.config.get('pcap_directory', './pcaps'),
            'PCAP Files (*.pcap);;All Files (*)'
        )
        
        if not filename:
            return
        
        try:
            success, message = self.pcap_processor.save_pcap_file(filename, self.current_packets)
            if success:
                QMessageBox.information(self, "Save Complete", message)
            else:
                QMessageBox.critical(self, "Save Error", message)
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save PCAP: {str(e)}")
    
    def start_live_capture(self):
        """Start live packet capture"""
        if self.live_capture and self.live_capture.isRunning():
            return
        
        interfaces = []
        try:
            net_if = psutil.net_if_addrs()
            for interface, addrs in net_if.items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        interfaces.append(interface)
                        break
        except:
            interfaces = ['any']
        
        if not interfaces:
            interfaces = ['any']
        
        interface, ok = QInputDialog.getItem(
            self, 'Select Interface', 'Choose network interface:', 
            interfaces, 0, False
        )
        
        if not ok:
            return
        
        self.live_capture = LiveCapture()
        self.live_capture.packet_received.connect(self.on_live_packet_received)
        self.live_capture.status_changed.connect(self.on_capture_status_changed)
        self.live_capture.error_occurred.connect(self.on_capture_error)
        
        try:
            self.live_capture.start_capture(interface if interface != 'any' else None)
            self.start_capture_btn.setEnabled(False)
            self.stop_capture_btn.setEnabled(True)
            self.status_label.setText('Live capture starting...')
        except Exception as e:
            QMessageBox.critical(self, "Capture Error", f"Failed to start capture: {str(e)}")
    
    def stop_live_capture(self):
        """Stop live packet capture"""
        if self.live_capture:
            self.live_capture.stop_capture()
            self.live_capture.wait(3000)
        
        self.start_capture_btn.setEnabled(True)
        self.stop_capture_btn.setEnabled(False)
        self.status_label.setText('Live capture stopped')
    
    def clear_packets(self):
        """Clear all packets"""
        reply = QMessageBox.question(
            self, 'Clear Packets', 
            'Clear all loaded packets? This cannot be undone.',
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.current_packets.clear()
            self.packet_table.clear_all()
            self.packet_details.clear()
            self.hex_dump.clear()
            self.sip_call_flow.update_sip_packets([])
            self.rtp_analyzer.update_rtp_packets([])
            self.update_status_bar()
            self.status_bar.showMessage('All packets cleared')
            self.save_pcap_btn.setEnabled(False)
            self.export_btn.setEnabled(False)
            self.setWindowTitle('NetHawk Pro - Advanced PCAP and SIP Analysis')
    
    def export_packets(self):
        """Export packets in various formats"""
        if not self.current_packets:
            QMessageBox.information(self, "Export", "No packets to export")
            return
        
        formats = ['CSV', 'JSON', 'XML', 'HTML Report', 'Text', 'PCAP']
        format_choice, ok = QInputDialog.getItem(
            self, 'Export Format', 'Choose export format:', 
            formats, 0, False
        )
        
        if not ok:
            return
        
        ext_map = {
            'CSV': 'csv', 'JSON': 'json', 'XML': 'xml', 
            'HTML Report': 'html', 'Text': 'txt', 'PCAP': 'pcap'
        }
        
        ext = ext_map[format_choice]
        default_name = f'nethawk_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.{ext}'
        
        filename, _ = QFileDialog.getSaveFileName(
            self, f'Export as {format_choice}',
            os.path.join(self.config.get('export_directory', './exports'), default_name),
            f'{format_choice} Files (*.{ext});;All Files (*)'
        )
        
        if not filename:
            return
        
        try:
            export_manager = ExportManager()
            options = {
                'include_sip': True,
                'include_rtp': True,
                'include_ports': True
            }
            
            success, message = export_manager.export_packets(
                self.current_packets, filename, ext.lower(), options
            )
            
            if success:
                QMessageBox.information(self, "Export Complete", message)
            else:
                QMessageBox.critical(self, "Export Error", message)
                
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Export failed: {str(e)}")
    
    # Event handlers
    def on_live_packet_received(self, packet_info):
        """Handle live packet received"""
        self.current_packets.append(packet_info)
        self.packet_table.add_packet(packet_info)
        
        if packet_info.get('is_sip'):
            sip_packets = [p for p in self.current_packets if p.get('is_sip')]
            self.sip_call_flow.update_sip_packets(sip_packets)
        
        if packet_info.get('is_rtp'):
            rtp_packets = [p for p in self.current_packets if p.get('is_rtp')]
            self.rtp_analyzer.update_rtp_packets(rtp_packets)
        
        self.update_status_bar()
        
        max_packets = self.config.get('max_packets', MAX_PACKETS)
        if len(self.current_packets) > max_packets:
            self.current_packets = self.current_packets[-max_packets:]
    
    def on_capture_status_changed(self, status):
        """Handle capture status changes"""
        self.status_label.setText(status)
        self.status_bar.showMessage(status)
    
    def on_capture_error(self, error):
        """Handle capture errors"""
        self.start_capture_btn.setEnabled(True)
        self.stop_capture_btn.setEnabled(False)
        self.status_label.setText('Capture error')
        QMessageBox.critical(self, 'Capture Error', f"Capture failed: {error}")
    
    def apply_packet_filter(self, filter_text):
        """Apply packet filter"""
        self.packet_table.apply_current_filter(filter_text)
        
        filtered_count = len(self.packet_table.filtered_packets)
        total_count = len(self.packet_table.packets)
        
        if filter_text:
            self.status_bar.showMessage(f"Filter applied: showing {filtered_count} of {total_count} packets")
        else:
            self.status_bar.showMessage(f"Showing all {total_count} packets")
    
    def show_packet_details(self, packet_info):
        """Show detailed packet information"""
        self.packet_details.show_packet_details(packet_info)
        
        if 'raw_packet' in packet_info:
            raw_data = packet_info['raw_packet']
            hex_output = self.format_hex_dump(raw_data)
        else:
            hex_output = f"Hex dump for packet #{packet_info.get('no', 'Unknown')}:\n"
            hex_output += f"Raw packet data not available.\n"
            hex_output += f"Packet info: {packet_info.get('info', 'No info')}\n"
            hex_output += f"Protocol: {packet_info.get('protocol', 'Unknown')}\n"
            hex_output += f"Length: {packet_info.get('length', 0)} bytes"
        
        self.hex_dump.setPlainText(hex_output)
    
    def format_hex_dump(self, data):
        """Format binary data as hex dump"""
        if not data:
            return "No data to display"
        
        hex_output = f"Hex dump ({len(data)} bytes):\n"
        hex_output += "Offset   00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ASCII\n"
        hex_output += "-" * 78 + "\n"
        
        for i in range(0, len(data), 16):
            hex_output += f"{i:08x} "
            
            hex_part = ""
            ascii_part = ""
            
            for j in range(16):
                if i + j < len(data):
                    byte_val = data[i + j]
                    hex_part += f"{byte_val:02x} "
                    ascii_part += chr(byte_val) if 32 <= byte_val <= 126 else "."
                else:
                    hex_part += "   "
                    ascii_part += " "
                
                if j == 7:
                    hex_part += " "
            
            hex_output += hex_part + " " + ascii_part + "\n"
        
        return hex_output
    
    def update_all_displays(self):
        """Update all display widgets with current packets"""
        if not self.current_packets:
            return
        
        self.packet_table.clear_all()
        for packet in self.current_packets:
            self.packet_table.add_packet(packet)
        
        sip_packets = [p for p in self.current_packets if p.get('is_sip')]
        rtp_packets = [p for p in self.current_packets if p.get('is_rtp')]
        
        self.sip_call_flow.update_sip_packets(sip_packets)
        self.rtp_analyzer.update_rtp_packets(rtp_packets)
        
        if sip_packets or rtp_packets:
            self.voice_quality.update_call_data(sip_packets, rtp_packets)
            call_flows = self.sip_call_flow.call_flows
            self.call_comparison.update_calls(call_flows)
        
        self.update_status_bar()
    
    def update_status_bar(self):
        """Update status bar with current packet counts"""
        total_packets = len(self.current_packets)
        sip_count = sum(1 for p in self.current_packets if p.get('is_sip'))
        rtp_count = sum(1 for p in self.current_packets if p.get('is_rtp'))
        
        call_ids = set(p.get('call_id') for p in self.current_packets if p.get('call_id'))
        call_count = len(call_ids)
        
        self.total_packets_label.setText(f"Packets: {total_packets:,}")
        self.sip_packets_label.setText(f"SIP: {sip_count:,}")
        self.rtp_packets_label.setText(f"RTP: {rtp_count:,}")
        self.calls_label.setText(f"Calls: {call_count}")
        
        self.packet_count_label.setText(f"Packets: {total_packets:,}")
    
    def update_statistics_display(self):
        """Update statistics display"""
        if not self.current_packets:
            self.statistics_text.setPlainText("No packets loaded for analysis")
            return
        
        stats = self.statistics_engine.generate_statistics(self.current_packets)
        
        stats_text = f"""PACKET ANALYSIS STATISTICS
{'=' * 50}

GENERAL STATISTICS:
Total Packets: {stats['total_packets']:,}
"""
        
        if stats.get('protocols'):
            stats_text += f"\nPROTOCOL DISTRIBUTION:\n"
            for protocol, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / stats['total_packets'] * 100) if stats['total_packets'] > 0 else 0
                stats_text += f"{protocol:<8}: {count:>6,} ({percentage:>5.1f}%)\n"
        
        self.statistics_text.setPlainText(stats_text)
    
    # Analysis methods
    def analyze_sip_calls(self):
        """Analyze SIP calls"""
        sip_packets = [p for p in self.current_packets if p.get('is_sip')]
        if not sip_packets:
            QMessageBox.information(self, "SIP Analysis", "No SIP packets found to analyze")
            return
        
        self.sip_call_flow.update_sip_packets(sip_packets)
        self.tab_widget.setCurrentIndex(1)  # Switch to SIP tab
        
        call_count = len(self.sip_call_flow.call_flows)
        self.status_bar.showMessage(f"SIP Analysis complete: {call_count} calls found")
    
    def analyze_rtp_streams(self):
        """Analyze RTP streams"""
        rtp_packets = [p for p in self.current_packets if p.get('is_rtp')]
        if not rtp_packets:
            QMessageBox.information(self, "RTP Analysis", "No RTP packets found to analyze")
            return
        
        self.rtp_analyzer.update_rtp_packets(rtp_packets)
        self.tab_widget.setCurrentIndex(2)  # Switch to RTP tab
        
        stream_count = len(self.rtp_analyzer.stream_stats)
        self.status_bar.showMessage(f"RTP Analysis complete: {stream_count} streams found")
    
    def analyze_voice_quality(self):
        """Analyze voice quality"""
        sip_packets = [p for p in self.current_packets if p.get('is_sip')]
        rtp_packets = [p for p in self.current_packets if p.get('is_rtp')]
        
        if not sip_packets and not rtp_packets:
            QMessageBox.information(self, "Voice Quality Analysis", "No voice packets (SIP/RTP) found to analyze")
            return
        
        self.voice_quality.update_call_data(sip_packets, rtp_packets)
        self.voice_quality.analyze_quality()
        self.tab_widget.setCurrentIndex(3)  # Switch to Voice Quality tab
        
        self.status_bar.showMessage("Voice quality analysis complete")
    
    def on_sip_call_selected(self, call_id):
        """Handle SIP call selection"""
        self.filter_edit.setText(f"call_id:{call_id}")
        self.status_bar.showMessage(f"Showing packets for call: {call_id[:32]}...")
    
    def show_help(self):
        """Show help dialog"""
        help_text = """NetHawk Pro - Advanced PCAP and SIP Analysis Tool

Features:
- Load and analyze PCAP files
- Interactive SIP call flow visualization
- RTP stream analysis  
- Voice quality assessment
- Live packet capture
- Multiple export formats

Usage:
1. Open PCAP file or start live capture
2. Use filters to focus on specific traffic
3. Analyze SIP calls in the call flow tab
4. Check voice quality metrics
5. Export results for reporting

Filters:
- src:IP - Filter by source IP
- dst:IP - Filter by destination IP  
- protocol:TYPE - Filter by protocol
- call_id:ID - Filter by SIP Call-ID
"""
        
        QMessageBox.about(self, 'NetHawk Pro Help', help_text)
    
    def show_about(self):
        """Show about dialog"""
        about_text = """NetHawk Pro v2.0
Advanced PCAP and SIP Analysis Tool

Professional network packet analysis with focus on voice communications.

Features:
- PCAP file analysis
- SIP call flow visualization  
- RTP stream analysis
- Voice quality assessment
- Real-time capture
- Professional reporting

Built with Python and PyQt5
"""
        
        QMessageBox.about(self, 'About NetHawk Pro', about_text)
    
    def load_pcap_from_cmdline(self, filename):
        """Load PCAP file from command line argument"""
        try:
            progress = QProgressDialog("Loading PCAP from command line...", None, 0, 100, self)
            progress.setWindowModality(Qt.WindowModal)
            progress.show()
            
            def progress_callback(percent, message):
                progress.setValue(percent)
                progress.setLabelText(message)
                QApplication.processEvents()
                return True
            
            success, message = self.pcap_processor.load_pcap_file(filename, progress_callback)
            progress.close()
            
            if success:
                self.current_packets = self.pcap_processor.get_packets()
                self.update_all_displays()
                self.status_label.setText(f"Loaded: {os.path.basename(filename)}")
                self.setWindowTitle(f'NetHawk Pro - {os.path.basename(filename)}')
                self.save_pcap_btn.setEnabled(True)
                self.export_btn.setEnabled(True)
            else:
                QMessageBox.critical(self, "Load Error", f"Failed to load {filename}:\n{message}")
                
        except Exception as e:
            QMessageBox.critical(self, "Load Error", f"Failed to load PCAP from command line:\n{str(e)}")
    
    def closeEvent(self, event):
        """Handle application close"""
        if self.live_capture and self.live_capture.isRunning():
            reply = QMessageBox.question(
                self, 'Exit NetHawk Pro',
                'Live capture is active. Stop capture and exit?',
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.stop_live_capture()
            else:
                event.ignore()
                return
        
        save_config(self.config)
        
        if hasattr(self, 'stats_timer'):
            self.stats_timer.stop()
        
        event.accept()


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("NetHawk Pro")
    app.setApplicationVersion("2.0.0")
    
    # Check for required dependencies
    missing_deps = []
    required_packages = {
        'PyQt5': 'PyQt5',
        'scapy': 'scapy',
        'psutil': 'psutil'
    }
    
    for package, pip_name in required_packages.items():
        try:
            __import__(package.lower().replace('pyqt5', 'PyQt5'))
        except ImportError:
            missing_deps.append(pip_name)
    
    if missing_deps:
        error_msg = f"Missing required packages: {', '.join(missing_deps)}\n\n"
        error_msg += f"Install with: pip install {' '.join(missing_deps)}"
        QMessageBox.critical(None, "Missing Dependencies", error_msg)
        return 1
    
    # Show welcome message
    welcome = QMessageBox()
    welcome.setIcon(QMessageBox.Information)
    welcome.setWindowTitle('Welcome to NetHawk Pro')
    welcome.setText('NetHawk Pro v2.0 - Advanced PCAP and SIP Analysis')
    welcome.setInformativeText(
        'Professional network packet analysis tool\n\n'
        'Features:\n'
        '- PCAP file analysis (like Wireshark)\n'
        '- Interactive SIP call flow visualization\n' 
        '- RTP stream analysis\n'
        '- Voice quality assessment\n'
        '- Real-time packet capture\n'
        '- Professional reporting\n\n'
        'Ready to start analyzing?'
    )
    welcome.setStandardButtons(QMessageBox.Ok)
    welcome.exec_()
    
    # Create and show main window
    try:
        window = NetHawkPro()
        window.show()
        
        # Check for command line arguments
        if len(sys.argv) > 1:
            pcap_file = sys.argv[1]
            if os.path.exists(pcap_file) and pcap_file.lower().endswith(('.pcap', '.cap', '.pcapng')):
                QTimer.singleShot(1000, lambda: window.load_pcap_from_cmdline(pcap_file))
        
        return app.exec_()
        
    except Exception as e:
        QMessageBox.critical(None, "Startup Error", f"Failed to start NetHawk Pro:\n\n{str(e)}")
        return 1


if __name__ == '__main__':
    sys.exit(main())


# END OF PART 4
# 
# To create the complete NetHawk Pro application:
# 1. Concatenate all 4 parts into a single Python file
# 2. Install required packages: pip install PyQt5 scapy psutil requests matplotlib
# 3. Run: python nethawk_complete.py [optional_pcap_file]