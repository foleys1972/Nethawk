#!/usr/bin/env python3
"""
NetHawk Pro - COMPLETE VERSION with Dialog Fix & Advanced Filtering
All original functionality preserved + fixes for visibility and filtering
"""

import sys
import json
import os
import socket
import struct
import time
import csv
import threading
import wave
import subprocess
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
import sqlite3
import pickle
import statistics
import concurrent.futures

# Third-party imports
try:
    from PyQt5.QtWidgets import *
    from PyQt5.QtCore import *
    from PyQt5.QtGui import *
except ImportError:
    print("Error: PyQt5 not installed. Run: pip install PyQt5")
    sys.exit(1)

try:
    import psutil
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, Raw, IPv6, rdpcap, wrpcap
except ImportError as e:
    print(f"Error: Missing packages. Run: pip install psutil scapy")
    print(f"Details: {e}")
    sys.exit(1)

# Configuration
CONFIG_FILE = 'nethawk_config.json'
DB_FILE = 'nethawk_packets.db'
MAX_PACKETS = 10000

# Compact Color Scheme
COLORS = {
    'primary': '#2196F3',
    'secondary': '#1976D2',
    'accent': '#FF9800',
    'success': '#4CAF50',
    'danger': '#F44336',
    'warning': '#FFC107',
    'info': '#00BCD4',
    'dark': '#263238',
    'darker': '#1a1a1a',
    'light': '#ECEFF1',
    'card': '#37474F',
}

# Protocol colors
PROTOCOL_COLORS = {
    'SIP': '#E91E63', 'RTP': '#2196F3', 'RTCP': '#9C27B0',
    'TCP': '#4CAF50', 'UDP': '#FF9800', 'ICMP': '#00BCD4',
    'ARP': '#FF5722', 'HTTP': '#9C27B0', 'HTTPS': '#673AB7',
    'DNS': '#009688', 'SSH': '#607D8B', 'FTP': '#FF5722',
    'SMTP': '#8BC34A', 'Other': '#78909C'
}

# QoS DSCP mappings
DSCP_CLASSES = {
    0: ('Best Effort', 'BE', '#78909C'),
    46: ('Expedited Forwarding', 'EF', '#F44336'),
    34: ('Assured Forwarding 41', 'AF41', '#2196F3'),
    26: ('Assured Forwarding 31', 'AF31', '#4CAF50'),
    18: ('Assured Forwarding 21', 'AF21', '#FF9800'),
    10: ('Assured Forwarding 11', 'AF11', '#9C27B0'),
}

# SIP method colors
SIP_METHOD_COLORS = {
    'INVITE': '#E91E63', 'ACK': '#4CAF50', 'BYE': '#FF9800',
    'CANCEL': '#F44336', 'REGISTER': '#2196F3', 'OPTIONS': '#78909C',
    '100': '#78909C', '180': '#FF9800', '200': '#4CAF50',
}

# Codec information
CODEC_INFO = {
    0: {'name': 'G.711 μ-law', 'rate': 8000, 'bandwidth': '64 kbps', 'quality': 'Excellent'},
    8: {'name': 'G.711 A-law', 'rate': 8000, 'bandwidth': '64 kbps', 'quality': 'Excellent'},
    3: {'name': 'GSM', 'rate': 8000, 'bandwidth': '13 kbps', 'quality': 'Good'},
    18: {'name': 'G.729', 'rate': 8000, 'bandwidth': '8 kbps', 'quality': 'Good'},
    9: {'name': 'G.722', 'rate': 16000, 'bandwidth': '64 kbps', 'quality': 'Excellent'},
}


class FilterParser:
    """Wireshark-style filter parser"""
    
    @staticmethod
    def parse_and_evaluate(filter_text, packet_info):
        """Parse and evaluate filter expression"""
        if not filter_text or not filter_text.strip():
            return True
        
        filter_text = filter_text.strip().lower()
        
        # Handle logical operators
        if ' or ' in filter_text:
            parts = filter_text.split(' or ')
            return any(FilterParser.parse_and_evaluate(p, packet_info) for p in parts)
        
        if ' and ' in filter_text:
            parts = filter_text.split(' and ')
            return all(FilterParser.parse_and_evaluate(p, packet_info) for p in parts)
        
        if filter_text.startswith('not '):
            return not FilterParser.parse_and_evaluate(filter_text[4:], packet_info)
        
        # Remove parentheses for simple parsing
        filter_text = filter_text.replace('(', '').replace(')', '')
        
        # Parse comparison expressions
        operators = ['==', '!=', 'contains', '>=', '<=', '>', '<']
        for op in operators:
            if op in filter_text:
                parts = filter_text.split(op, 1)
                if len(parts) == 2:
                    field = parts[0].strip()
                    value = parts[1].strip().strip('"').strip("'")
                    return FilterParser.evaluate_comparison(field, op, value, packet_info)
        
        # Fallback: simple text search
        return FilterParser.simple_search(filter_text, packet_info)
    
    @staticmethod
    def evaluate_comparison(field, operator, value, packet_info):
        """Evaluate field comparison"""
        # IP address fields
        if field in ['ip.src', 'src', 'source']:
            packet_val = packet_info.get('src', '').lower()
        elif field in ['ip.dst', 'dst', 'destination']:
            packet_val = packet_info.get('dst', '').lower()
        elif field in ['ip.addr', 'ip', 'addr']:
            src = packet_info.get('src', '').lower()
            dst = packet_info.get('dst', '').lower()
            if operator == '==':
                return value in [src, dst]
            elif operator == '!=':
                return value not in [src, dst]
            elif operator == 'contains':
                return value in src or value in dst
            return False
        
        # Port fields
        elif field in ['tcp.port', 'udp.port', 'port']:
            sport = str(packet_info.get('sport', 0))
            dport = str(packet_info.get('dport', 0))
            if operator == '==':
                return value in [sport, dport]
            elif operator == '!=':
                return value not in [sport, dport]
            try:
                val_int = int(value)
                return val_int in [int(sport), int(dport)]
            except:
                return False
        
        elif field in ['tcp.srcport', 'udp.srcport', 'sport', 'src.port']:
            packet_val = str(packet_info.get('sport', 0))
        elif field in ['tcp.dstport', 'udp.dstport', 'dport', 'dst.port']:
            packet_val = str(packet_info.get('dport', 0))
        
        # Protocol field
        elif field in ['protocol', 'proto']:
            packet_val = packet_info.get('protocol', '').lower()
        
        # Length field
        elif field in ['length', 'len', 'frame.len']:
            try:
                packet_val = packet_info.get('length', 0)
                value_num = int(value)
                if operator == '==':
                    return packet_val == value_num
                elif operator == '!=':
                    return packet_val != value_num
                elif operator == '>':
                    return packet_val > value_num
                elif operator == '<':
                    return packet_val < value_num
                elif operator == '>=':
                    return packet_val >= value_num
                elif operator == '<=':
                    return packet_val <= value_num
            except:
                return False
            return False
        
        # Info field
        elif field in ['info', 'description']:
            packet_val = packet_info.get('info', '').lower()
        
        else:
            return False
        
        # Perform comparison
        if operator == '==':
            return packet_val == value
        elif operator == '!=':
            return packet_val != value
        elif operator == 'contains':
            return value in packet_val
        elif operator in ['>', '<', '>=', '<=']:
            try:
                return eval(f"{packet_val} {operator} {value}")
            except:
                return False
        
        return False
    
    @staticmethod
    def simple_search(text, packet_info):
        """Simple text search fallback"""
        text = text.lower()
        
        if packet_info.get('protocol', '').lower() == text:
            return True
        if text in packet_info.get('src', '').lower():
            return True
        if text in packet_info.get('dst', '').lower():
            return True
        if text in packet_info.get('info', '').lower():
            return True
        
        return False


def setup_dark_theme_globally(app):
    """Setup dark theme for entire application including dialogs"""
    app.setStyle('Fusion')
    
    # Create dark palette
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(COLORS['dark']))
    palette.setColor(QPalette.WindowText, QColor(COLORS['light']))
    palette.setColor(QPalette.Base, QColor(COLORS['darker']))
    palette.setColor(QPalette.AlternateBase, QColor(COLORS['card']))
    palette.setColor(QPalette.ToolTipBase, QColor(COLORS['card']))
    palette.setColor(QPalette.ToolTipText, QColor(COLORS['light']))
    palette.setColor(QPalette.Text, QColor(COLORS['light']))
    palette.setColor(QPalette.Button, QColor(COLORS['card']))
    palette.setColor(QPalette.ButtonText, QColor(COLORS['light']))
    palette.setColor(QPalette.BrightText, QColor('white'))
    palette.setColor(QPalette.Link, QColor(COLORS['primary']))
    palette.setColor(QPalette.Highlight, QColor(COLORS['primary']))
    palette.setColor(QPalette.HighlightedText, QColor('white'))
    
    app.setPalette(palette)
    
    # Global stylesheet for dialogs
    app.setStyleSheet(f"""
        QMessageBox {{
            background-color: {COLORS['dark']};
            color: {COLORS['light']};
        }}
        QMessageBox QLabel {{
            color: {COLORS['light']};
            font-size: 9pt;
        }}
        QMessageBox QPushButton {{
            background-color: {COLORS['primary']};
            color: white;
            border: none;
            padding: 6px 20px;
            border-radius: 4px;
            font-weight: 600;
            min-width: 80px;
        }}
        QMessageBox QPushButton:hover {{
            background-color: {COLORS['secondary']};
        }}
        QFileDialog {{
            background-color: {COLORS['dark']};
            color: {COLORS['light']};
        }}
        QInputDialog {{
            background-color: {COLORS['dark']};
            color: {COLORS['light']};
        }}
        QProgressDialog {{
            background-color: {COLORS['dark']};
            color: {COLORS['light']};
        }}
        QDialog {{
            background-color: {COLORS['dark']};
            color: {COLORS['light']};
        }}
        QDialog QLabel {{
            color: {COLORS['light']};
        }}
    """)


def ulaw2lin(data):
    """Convert μ-law to linear PCM"""
    ULAW_BIAS = 0x84
    output = bytearray()
    for byte_val in data:
        byte_val = ~byte_val & 0xFF
        sign = byte_val & 0x80
        exponent = (byte_val >> 4) & 0x07
        mantissa = byte_val & 0x0F
        linear = ((mantissa << 3) + ULAW_BIAS) << exponent
        linear -= ULAW_BIAS
        if sign:
            linear = -linear
        linear = max(-32768, min(32767, linear))
        output.extend(struct.pack('<h', linear))
    return bytes(output)

def alaw2lin(data):
    """Convert A-law to linear PCM"""
    output = bytearray()
    for byte_val in data:
        byte_val ^= 0x55
        sign = byte_val & 0x80
        exponent = (byte_val >> 4) & 0x07
        mantissa = byte_val & 0x0F
        if exponent == 0:
            linear = (mantissa << 4) + 8
        else:
            linear = ((mantissa << 4) + 0x108) << (exponent - 1)
        if not sign:
            linear = -linear
        linear = max(-32768, min(32767, linear))
        output.extend(struct.pack('<h', linear))
    return bytes(output)

def load_config():
    """Load configuration"""
    default = {
        'max_packets': MAX_PACKETS,
        'auto_scroll': True,
        'capture_interface': 'auto',
        'dark_mode': True,
        'update_interval': 200,
        'audio_output_dir': './audio_exports',
        'capture_filter': 'all',
        'store_raw_packets': True,
        'batch_size': 100,
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
    """SQLite database for packet storage"""
    def __init__(self, db_file=DB_FILE):
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Initialize database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='packets'")
        if not cursor.fetchone():
            cursor.execute('''CREATE TABLE packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL, src_ip TEXT, dst_ip TEXT,
                src_port INTEGER, dst_port INTEGER, protocol TEXT,
                length INTEGER, qos_dscp INTEGER, flags TEXT,
                call_id TEXT, sip_method TEXT, rtp_ssrc INTEGER,
                rtp_payload_type INTEGER, raw_data BLOB)''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol ON packets(protocol)')
        conn.commit()
        conn.close()

class RTPStream:
    """RTP stream handler"""
    def __init__(self, ssrc, payload_type=0):
        self.ssrc = ssrc
        self.payload_type = payload_type
        self.packets = []
        self.codec = CODEC_INFO.get(payload_type, {'name': 'Unknown', 'rate': 8000})
        self.sample_rate = self.codec['rate']
        self.start_time = None
        self.end_time = None
        self.packet_count = 0
        self.lost_packets = 0
        self.jitter_samples = []
        self.max_jitter = 0
        self.avg_jitter = 0
    
    def add_packet(self, rtp_packet, timestamp):
        if self.start_time is None:
            self.start_time = timestamp
        self.end_time = timestamp
        self.packets.append({
            'seq': rtp_packet.sequence,
            'timestamp': rtp_packet.timestamp,
            'payload': bytes(rtp_packet.payload),
            'received_at': timestamp
        })
        self.packet_count += 1
        if len(self.packets) > 1:
            self.calculate_jitter()
    
    def calculate_jitter(self):
        if len(self.packets) < 2:
            return
        p1 = self.packets[-2]
        p2 = self.packets[-1]
        arrival_diff = (p2['received_at'] - p1['received_at']) * 1000
        timestamp_diff = (p2['timestamp'] - p1['timestamp']) / (self.sample_rate / 1000.0)
        jitter = abs(arrival_diff - timestamp_diff)
        self.jitter_samples.append(jitter)
        if jitter > self.max_jitter:
            self.max_jitter = jitter
        if self.jitter_samples:
            self.avg_jitter = sum(self.jitter_samples) / len(self.jitter_samples)
    
    def detect_packet_loss(self):
        if len(self.packets) < 2:
            return
        sequences = [p['seq'] for p in self.packets]
        sequences.sort()
        expected_count = sequences[-1] - sequences[0] + 1
        self.lost_packets = expected_count - len(sequences)
    
    def calculate_mos(self):
        self.detect_packet_loss()
        if self.packet_count == 0:
            return 0.0
        loss_rate = (self.lost_packets / (self.packet_count + self.lost_packets)) * 100
        mos = 4.5
        if loss_rate > 0:
            mos -= min(loss_rate * 0.1, 3.0)
        if self.avg_jitter > 20:
            mos -= min((self.avg_jitter - 20) * 0.02, 1.5)
        return max(1.0, min(4.5, mos))
    
    def export_to_wav(self, filename):
        try:
            sorted_packets = sorted(self.packets, key=lambda x: x['seq'])
            audio_data = b''.join([p['payload'] for p in sorted_packets])
            if not audio_data:
                return False
            if self.payload_type == 0:
                pcm_data = ulaw2lin(audio_data)
            elif self.payload_type == 8:
                pcm_data = alaw2lin(audio_data)
            else:
                pcm_data = audio_data
            with wave.open(filename, 'wb') as wav_file:
                wav_file.setnchannels(1)
                wav_file.setsampwidth(2)
                wav_file.setframerate(self.sample_rate)
                wav_file.writeframes(pcm_data)
            return True
        except Exception as e:
            print(f"WAV export error: {e}")
            return False

class SIPCall:
    """SIP call tracker"""
    def __init__(self, call_id):
        self.call_id = call_id
        self.messages = []
        self.rtp_streams = {}
        self.start_time = None
        self.end_time = None
        self.caller = 'Unknown'
        self.callee = 'Unknown'
        self.state = 'Unknown'
    
    def add_message(self, message):
        if self.start_time is None:
            self.start_time = message['timestamp']
        self.end_time = message['timestamp']
        self.messages.append(message)
        if len(self.messages) == 1:
            self.caller = message.get('from', 'Unknown')
            self.callee = message.get('to', 'Unknown')
        method = message.get('method', '')
        if method == 'INVITE':
            self.state = 'Inviting'
        elif method == '180':
            self.state = 'Ringing'
        elif method == '200':
            self.state = 'Connected'
        elif method == 'BYE':
            self.state = 'Terminated'

class RemoteAgentReceiver(QThread):
    """Thread to receive packets from remote agent"""
    packet_received = pyqtSignal(dict)
    connection_closed = pyqtSignal()
    error_occurred = pyqtSignal(str)
    
    def __init__(self, socket_conn):
        super().__init__()
        self.socket = socket_conn
        self.running = False
    
    def run(self):
        self.running = True
        try:
            while self.running:
                size_data = self.socket.recv(4)
                if not size_data or len(size_data) < 4:
                    break
                
                packet_size = struct.unpack('!I', size_data)[0]
                if packet_size == 0 or packet_size > 65535:
                    continue
                
                packet_data = b''
                while len(packet_data) < packet_size:
                    chunk = self.socket.recv(min(4096, packet_size - len(packet_data)))
                    if not chunk:
                        break
                    packet_data += chunk
                
                if len(packet_data) == packet_size:
                    try:
                        packet_info = pickle.loads(packet_data)
                        self.packet_received.emit(packet_info)
                    except:
                        pass
        except Exception as e:
            if self.running:
                self.error_occurred.emit(f"Receiver error: {str(e)}")
        finally:
            self.connection_closed.emit()
            self.running = False
    
    def stop(self):
        self.running = False

class RemoteAgent:
    """Remote capture agent with packet reception"""
    def __init__(self, host, port=9999, auth_key=None):
        self.host = host
        self.port = port
        self.auth_key = auth_key
        self.connected = False
        self.socket = None
        self.receiver = None
    
    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.connect((self.host, self.port))
            if self.auth_key:
                self.socket.send(f"AUTH:{self.auth_key}\n".encode())
                response = self.socket.recv(1024).decode()
                if "OK" not in response:
                    self.socket.close()
                    return False
            self.connected = True
            return True
        except:
            return False
    
    def start_remote_capture(self, filters=None, packet_callback=None):
        if not self.connected:
            return False
        try:
            cmd = "START_CAPTURE"
            if filters:
                cmd += f":{filters}"
            self.socket.send(f"{cmd}\n".encode())
            self.socket.settimeout(None)
            
            if packet_callback:
                self.receiver = RemoteAgentReceiver(self.socket)
                self.receiver.packet_received.connect(packet_callback)
                self.receiver.start()
            
            return True
        except:
            return False
    
    def stop_capture(self):
        if self.receiver:
            self.receiver.stop()
            self.receiver.wait(1000)
            self.receiver = None
        
        if self.connected and self.socket:
            try:
                self.socket.send(b"STOP_CAPTURE\n")
            except:
                pass
    
    
    def try_standard_protocols(self):
        """Try standard remote capture protocols"""
        try:
            # Method 1: Try tshark remote capture
            if self.try_tshark_remote():
                return True
                
            # Method 2: Try SSH tunnel
            if self.try_ssh_tunnel():
                return True
                
            # Method 3: Try direct socket with standard handshake
            if self.try_standard_socket():
                return True
                
            return False
        except Exception as e:
            print(f"Standard protocol connection failed: {e}")
            return False
    
    def try_tshark_remote(self):
        """Try tshark remote capture"""
        try:
            import subprocess
            
            # Build tshark command for remote capture
            cmd = [
                'tshark', '-i', 'any',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'ip.proto',
                '-e', 'tcp.srcport',
                '-e', 'tcp.dstport',
                '-e', 'udp.srcport',
                '-e', 'udp.dstport',
                '-e', 'frame.len',
                '-e', 'frame.protocols'
            ]
            
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            self.connected = True
            return True
            
        except Exception as e:
            print(f"TShark remote capture failed: {e}")
            return False
    
    def try_ssh_tunnel(self):
        """Try SSH tunnel for remote capture"""
        try:
            import subprocess
            import time
            
            # Create SSH tunnel
            tunnel_cmd = [
                'ssh', '-L', f'9999:{self.host}:{self.port}',
                f'user@{self.host}', '-N'
            ]
            
            self.tunnel_process = subprocess.Popen(tunnel_cmd)
            time.sleep(2)  # Wait for tunnel to establish
            
            # Connect to local tunnel
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.connect(('localhost', 9999))
            
            self.connected = True
            return True
            
        except Exception as e:
            print(f"SSH tunnel failed: {e}")
            return False
    
    def try_standard_socket(self):
        """Try standard socket with different handshake methods"""
        try:
            # Try different handshake methods
            handshake_methods = [
                self.try_netHawk_handshake,
                self.try_standard_handshake,
                self.try_wireshark_handshake
            ]
            
            for method in handshake_methods:
                if method():
                    return True
                    
            return False
            
        except Exception as e:
            print(f"Standard socket failed: {e}")
            return False
    
    def try_netHawk_handshake(self):
        """Try NetHawk custom protocol handshake"""
        try:
            if self.auth_key:
                self.socket.send(f"AUTH:{self.auth_key}\n".encode())
                response = self.socket.recv(1024).decode()
                return "OK" in response
            return True
        except:
            return False
    
    def try_standard_handshake(self):
        """Try standard remote capture handshake"""
        try:
            # Send standard start command
            self.socket.send(b"START\n")
            response = self.socket.recv(1024).decode()
            return "OK" in response or "READY" in response
        except:
            return False
    
    def try_wireshark_handshake(self):
        """Try Wireshark-compatible handshake"""
        try:
            # Send Wireshark-style command
            self.socket.send(b"CAPTURE\n")
            response = self.socket.recv(1024).decode()
            return "OK" in response or "READY" in response
        except:
            return False
    
    def start_enhanced_capture(self, filters=None, packet_callback=None):
        """Enhanced capture start with multiple protocol support"""
        if not self.connected:
            return False
            
        try:
            if self.capture_process:
                # Handle tshark process
                return self.start_tshark_capture(filters, packet_callback)
            elif self.socket:
                # Handle socket connection (existing functionality)
                return self.start_remote_capture(filters, packet_callback)
            else:
                return False
                
        except Exception as e:
            print(f"Enhanced capture failed: {e}")
            return False
    
    def start_tshark_capture(self, filters, packet_callback):
        """Start tshark capture"""
        try:
            def tshark_reader():
                packet_count = 0
                for line in self.capture_process.stdout:
                    if not self.running:
                        break
                        
                    try:
                        fields = line.strip().split('\t')
                        if len(fields) >= 8:
                            packet_info = self.parse_tshark_fields(fields)
                            if packet_callback:
                                packet_callback(packet_info)
                            packet_count += 1
                    except Exception as e:
                        print(f"TShark parsing error: {e}")
                        continue
            
            self.running = True
            reader_thread = threading.Thread(target=tshark_reader)
            reader_thread.daemon = True
            reader_thread.start()
            
            return True
            
        except Exception as e:
            print(f"TShark capture error: {e}")
            return False
    
    def parse_tshark_fields(self, fields):
        """Parse tshark output fields"""
        return {
            'timestamp': fields[1] if len(fields) > 1 else str(datetime.now()),
            'src': fields[2] if len(fields) > 2 else '',
            'dst': fields[3] if len(fields) > 3 else '',
            'protocol': fields[4] if len(fields) > 4 else '',
            'length': int(fields[7]) if len(fields) > 7 and fields[7].isdigit() else 0,
            'info': f"{fields[8] if len(fields) > 8 else ''} {fields[5] if len(fields) > 5 else ''} -> {fields[6] if len(fields) > 6 else ''}",
            'frame_number': int(fields[0]) if len(fields) > 0 and fields[0].isdigit() else 0,
            'raw_packet': b''
        }
    
    def enhanced_connect(self):
        """Enhanced connection with multiple protocol support"""
        # First try the original connection method
        if self.connect():
            return True
            
        # If original fails, try standard protocols
        return self.try_standard_protocols()
    def disconnect(self):
        self.stop_capture()
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.connected = False

class PCAPLoader(QThread):
    """THREAD-SAFE PCAP loader"""
    packet_batch_loaded = pyqtSignal(list)
    loading_progress = pyqtSignal(int, int)
    loading_complete = pyqtSignal(int)
    loading_error = pyqtSignal(str)
    
    def __init__(self, filename, max_packets=None):
        super().__init__()
        self.filename = filename
        self.max_packets = max_packets or MAX_PACKETS
        self.should_stop = False
        self._running = False
    
    def run(self):
        self._running = True
        try:
            self.loading_progress.emit(0, 0)
            packets = rdpcap(self.filename)
            total = len(packets)
            
            if self.should_stop:
                return
            
            if total > self.max_packets:
                packets = packets[-self.max_packets:]
                total = self.max_packets
            
            self.loading_progress.emit(0, total)
            
            batch_size = 100
            batch = []
            
            for idx, packet in enumerate(packets):
                if self.should_stop:
                    break
                
                packet_info = self.parse_pcap_packet(packet, idx + 1)
                if packet_info:
                    batch.append(packet_info)
                
                if len(batch) >= batch_size:
                    if not self.should_stop:
                        self.packet_batch_loaded.emit(batch)
                    batch = []
                    self.loading_progress.emit(idx + 1, total)
                    self.msleep(10)
            
            if batch and not self.should_stop:
                self.packet_batch_loaded.emit(batch)
            
            if not self.should_stop:
                self.loading_progress.emit(total, total)
                self.loading_complete.emit(total)
        except Exception as e:
            if not self.should_stop:
                self.loading_error.emit(f"Failed to load PCAP: {str(e)}")
        finally:
            self._running = False
    
    def stop(self):
        self.should_stop = True
    
    def is_running(self):
        return self._running
    
    def parse_pcap_packet(self, packet, packet_no):
        try:
            packet_info = {
                'no': packet_no,
                'timestamp': datetime.fromtimestamp(float(packet.time)).strftime('%H:%M:%S.%f')[:-3],
                'src': 'Unknown', 'dst': 'Unknown',
                'sport': 0, 'dport': 0,
                'protocol': 'Other',
                'length': len(packet),
                'qos_dscp': 0, 'qos_name': 'BE',
                'flags': '', 'info': '',
                'raw_packet': bytes(packet) if len(packet) < 2000 else None
            }
            
            if packet.haslayer(ARP):
                arp = packet[ARP]
                packet_info['protocol'] = 'ARP'
                packet_info['src'] = arp.psrc
                packet_info['dst'] = arp.pdst
                packet_info['info'] = f"Who has {arp.pdst}? Tell {arp.psrc}"
                return packet_info
            
            if not packet.haslayer(IP):
                return None
            
            ip = packet[IP]
            packet_info['src'] = ip.src
            packet_info['dst'] = ip.dst
            packet_info['qos_dscp'] = (ip.tos >> 2) & 0x3F
            packet_info['qos_name'] = DSCP_CLASSES.get(packet_info['qos_dscp'], ('', 'UK', '#78909C'))[1]
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                packet_info['sport'] = tcp.sport
                packet_info['dport'] = tcp.dport
                packet_info['protocol'] = self.detect_protocol(tcp.sport, tcp.dport, packet, 'TCP')
                flags = []
                if tcp.flags.F: flags.append('FIN')
                if tcp.flags.S: flags.append('SYN')
                if tcp.flags.R: flags.append('RST')
                if tcp.flags.P: flags.append('PSH')
                if tcp.flags.A: flags.append('ACK')
                packet_info['flags'] = ','.join(flags)
                packet_info['info'] = f"{packet_info['protocol']} [{packet_info['flags']}] Seq={tcp.seq}"
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                packet_info['sport'] = udp.sport
                packet_info['dport'] = udp.dport
                packet_info['protocol'] = self.detect_protocol(udp.sport, udp.dport, packet, 'UDP')
                packet_info['info'] = f"{packet_info['protocol']} {udp.sport}→{udp.dport}"
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                packet_info['protocol'] = 'ICMP'
                packet_info['info'] = f"ICMP Type {icmp.type}"
            
            return packet_info
        except:
            return None
    
    def detect_protocol(self, sport, dport, packet, transport):
        port_map = {20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS',
                    80: 'HTTP', 443: 'HTTPS', 5060: 'SIP'}
        if sport in port_map:
            return port_map[sport]
        if dport in port_map:
            return port_map[dport]
        
        if sport in [5060, 5061] or dport in [5060, 5061]:
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')[:200]
                    if 'SIP/2.0' in payload_str or 'INVITE sip:' in payload_str or 'REGISTER sip:' in payload_str:
                        return 'SIP'
                except:
                    pass
        
        if transport == 'UDP' and (10000 <= sport <= 20000 or 10000 <= dport <= 20000):
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                if len(payload) >= 12:
                    version = (payload[0] >> 6) & 0x03
                    if version == 2:
                        payload_type = payload[1] & 0x7F
                        if payload_type <= 127:
                            return 'RTP'
        
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            try:
                payload_str = payload.decode('utf-8', errors='ignore')[:50]
                if any(m in payload_str for m in ['GET ', 'POST ', 'HTTP/']):
                    return 'HTTP'
            except:
                pass
        
        return transport

class NetworkCapture(QThread):
    """Network capture thread"""
    packet_received = pyqtSignal(dict)
    sip_message_received = pyqtSignal(dict)
    rtp_packet_received = pyqtSignal(dict)
    status_changed = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.running = False
        self.packet_count = 0
        self.interface = None
        self.capture_filter = 'all'
        self.sip_ports = [5060, 5061]
        self.rtp_port_range = (10000, 20000)
    
    def start_capture(self, interface=None, capture_filter='all'):
        self.interface = interface
        self.capture_filter = capture_filter
        self.running = True
        self.start()
    
    def run(self):
        try:
            self.status_changed.emit("Starting capture...")
            bpf_filter = None if self.capture_filter == 'all' else None
            sniff(iface=self.interface, filter=bpf_filter, prn=self.packet_handler,
                  stop_filter=lambda x: not self.running, store=False)
        except Exception as e:
            self.error_occurred.emit(f"Capture failed: {str(e)}")
    
    def packet_handler(self, packet):
        try:
            packet_info = self.parse_packet(packet)
            if packet_info:
                self.packet_count += 1
                packet_info['no'] = self.packet_count
                packet_info['raw_packet'] = bytes(packet)
                self.packet_received.emit(packet_info)
                
                if packet_info['protocol'] == 'SIP':
                    self.parse_sip_packet(packet)
                elif packet_info['protocol'] == 'RTP':
                    self.parse_rtp_packet(packet)
        except:
            pass
    
    def parse_packet(self, packet):
        try:
            packet_info = {
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'src': 'Unknown', 'dst': 'Unknown',
                'sport': 0, 'dport': 0,
                'protocol': 'Other', 'length': len(packet),
                'qos_dscp': 0, 'qos_name': 'BE',
                'flags': '', 'info': ''
            }
            
            if packet.haslayer(ARP):
                arp = packet[ARP]
                packet_info['protocol'] = 'ARP'
                packet_info['src'] = arp.psrc
                packet_info['dst'] = arp.pdst
                packet_info['info'] = f"ARP {arp.psrc} → {arp.pdst}"
                return packet_info
            
            if not packet.haslayer(IP):
                return None
            
            ip = packet[IP]
            packet_info['src'] = ip.src
            packet_info['dst'] = ip.dst
            packet_info['qos_dscp'] = (ip.tos >> 2) & 0x3F
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                packet_info['sport'] = tcp.sport
                packet_info['dport'] = tcp.dport
                packet_info['protocol'] = self.detect_app_protocol(tcp.sport, tcp.dport, packet, 'TCP')
                flags = []
                if tcp.flags.F: flags.append('FIN')
                if tcp.flags.S: flags.append('SYN')
                if tcp.flags.R: flags.append('RST')
                if tcp.flags.P: flags.append('PSH')
                if tcp.flags.A: flags.append('ACK')
                packet_info['flags'] = ','.join(flags)
                packet_info['info'] = f"{packet_info['protocol']} [{packet_info['flags']}]"
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                packet_info['sport'] = udp.sport
                packet_info['dport'] = udp.dport
                packet_info['protocol'] = self.detect_app_protocol(udp.sport, udp.dport, packet, 'UDP')
                packet_info['info'] = f"{packet_info['protocol']} {udp.sport}→{udp.dport}"
            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
                packet_info['info'] = "ICMP"
            
            return packet_info
        except:
            return None
    
    def detect_app_protocol(self, sport, dport, packet, transport):
        port_map = {21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS',
                    80: 'HTTP', 443: 'HTTPS', 5060: 'SIP'}
        if sport in port_map:
            return port_map[sport]
        if dport in port_map:
            return port_map[dport]
        
        if sport in self.sip_ports or dport in self.sip_ports:
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')[:200]
                    if 'SIP/2.0' in payload_str or 'INVITE sip:' in payload_str or any(m in payload_str for m in ['REGISTER', 'ACK', 'BYE', 'CANCEL']):
                        return 'SIP'
                except:
                    pass
        
        if transport == 'UDP' and (self.rtp_port_range[0] <= sport <= self.rtp_port_range[1] or
                                   self.rtp_port_range[0] <= dport <= self.rtp_port_range[1]):
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                if len(payload) >= 12:
                    version = (payload[0] >> 6) & 0x03
                    if version == 2:
                        payload_type = payload[1] & 0x7F
                        if payload_type <= 127:
                            return 'RTP'
        
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            try:
                payload_str = payload.decode('utf-8', errors='ignore')[:50]
                if any(m in payload_str for m in ['GET ', 'POST ', 'HTTP/']):
                    return 'HTTP'
            except:
                pass
        
        return transport
    
    def parse_sip_packet(self, packet):
        try:
            if not packet.haslayer(Raw):
                return
            raw_data = bytes(packet[Raw].load)
            sip_data = raw_data.decode('utf-8', errors='ignore')
            lines = sip_data.split('\r\n')
            if not lines:
                return
            
            sip_info = {
                'timestamp': time.time(),
                'src': packet[IP].src, 'dst': packet[IP].dst,
                'sport': packet[UDP].sport, 'dport': packet[UDP].dport,
                'raw': sip_data, 'headers': {}
            }
            
            first_line = lines[0]
            if first_line.startswith('SIP/'):
                parts = first_line.split(' ', 2)
                sip_info['type'] = 'response'
                sip_info['status_code'] = parts[1] if len(parts) > 1 else 'Unknown'
                sip_info['method'] = sip_info['status_code']
            else:
                parts = first_line.split(' ')
                sip_info['type'] = 'request'
                sip_info['method'] = parts[0] if parts else 'Unknown'
            
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    sip_info['headers'][key.strip()] = value.strip()
            
            sip_info['call_id'] = sip_info['headers'].get('Call-ID', '')
            sip_info['from'] = sip_info['headers'].get('From', '')
            sip_info['to'] = sip_info['headers'].get('To', '')
            self.sip_message_received.emit(sip_info)
        except:
            pass
    
    def parse_rtp_packet(self, packet):
        try:
            if not packet.haslayer(Raw):
                return
            payload = bytes(packet[Raw].load)
            if len(payload) < 12:
                return
            
            version = (payload[0] >> 6) & 0x03
            if version != 2:
                return
            
            cc = payload[0] & 0x0F
            payload_type = payload[1] & 0x7F
            sequence = struct.unpack('!H', payload[2:4])[0]
            timestamp = struct.unpack('!I', payload[4:8])[0]
            ssrc = struct.unpack('!I', payload[8:12])[0]
            
            header_len = 12 + (cc * 4)
            rtp_payload = payload[header_len:]
            
            rtp_info = {
                'timestamp': time.time(),
                'src': packet[IP].src, 'dst': packet[IP].dst,
                'sport': packet[UDP].sport, 'dport': packet[UDP].dport,
                'ssrc': ssrc, 'sequence': sequence,
                'rtp_timestamp': timestamp,
                'payload_type': payload_type,
                'payload': rtp_payload
            }
            self.rtp_packet_received.emit(rtp_info)
        except:
            pass
    
    def stop_capture(self):
        self.running = False

class ModernPacketTable(QTableWidget):
    """COMPACT & THREAD-SAFE packet table with ADVANCED FILTERING"""
    packet_selected = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.packets = []
        self.filtered_packets = []
        self.filter_text = ''
        self.max_packets = MAX_PACKETS
        self.setup_table()
        self.itemSelectionChanged.connect(self.on_selection)
        
        self._pending_packets = []
        self._pending_lock = threading.Lock()
        self.batch_timer = QTimer()
        self.batch_timer.timeout.connect(self.flush_pending_packets)
        self.batch_timer.start(100)
    
    def setup_table(self):
        headers = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'QoS', 'Length', 'Info']
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        
        self.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['dark']};
                color: {COLORS['light']};
                gridline-color: {COLORS['card']};
                selection-background-color: {COLORS['primary']};
                border: none;
                font-size: 8pt;
            }}
            QHeaderView::section {{
                background-color: {COLORS['darker']};
                color: {COLORS['light']};
                border: none;
                padding: 6px 4px;
                font-weight: 600;
                font-size: 8pt;
            }}
            QTableWidget::item {{
                padding: 4px;
                border-bottom: 1px solid {COLORS['card']};
            }}
            QTableWidget::item:alternate {{
                background-color: rgba(55, 71, 79, 0.3);
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['primary']};
                color: white;
            }}
        """)
        
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.setSortingEnabled(False)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(20)
        
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.Stretch)
    
    def add_packet(self, packet_info):
        with self._pending_lock:
            if len(self.packets) >= self.max_packets:
                self.packets.pop(0)
                if self.filtered_packets:
                    self.filtered_packets.pop(0)
            
            self.packets.append(packet_info)
            
            if self.should_display(packet_info):
                display_info = {k: v for k, v in packet_info.items() if k != 'raw_packet'}
                self.filtered_packets.append(display_info)
                self._pending_packets.append(display_info)
    
    def flush_pending_packets(self):
        with self._pending_lock:
            if not self._pending_packets:
                return
            
            batch = self._pending_packets[:]
            self._pending_packets.clear()
        
        self.setUpdatesEnabled(False)
        try:
            while self.rowCount() >= self.max_packets:
                self.removeRow(0)
            
            for packet_info in batch:
                self.display_packet_fast(packet_info)
        finally:
            self.setUpdatesEnabled(True)
            scrollbar = self.verticalScrollBar()
            if scrollbar.value() >= scrollbar.maximum() - 10:
                self.scrollToBottom()
    
    def display_packet_fast(self, packet_info):
        row = self.rowCount()
        self.insertRow(row)
        
        no_item = QTableWidgetItem(str(packet_info['no']))
        no_item.setTextAlignment(Qt.AlignCenter)
        self.setItem(row, 0, no_item)
        
        time_item = QTableWidgetItem(packet_info['timestamp'])
        time_item.setFont(QFont("Consolas", 8))
        self.setItem(row, 1, time_item)
        
        self.setItem(row, 2, QTableWidgetItem(packet_info['src']))
        self.setItem(row, 3, QTableWidgetItem(packet_info['dst']))
        
        protocol_item = QTableWidgetItem(packet_info['protocol'])
        protocol_item.setTextAlignment(Qt.AlignCenter)
        protocol_item.setFont(QFont("Arial", 8, QFont.Bold))
        color = QColor(PROTOCOL_COLORS.get(packet_info['protocol'], PROTOCOL_COLORS['Other']))
        protocol_item.setBackground(QBrush(color))
        protocol_item.setForeground(QBrush(QColor('white')))
        self.setItem(row, 4, protocol_item)
        
        qos_item = QTableWidgetItem(packet_info.get('qos_name', 'BE'))
        qos_item.setTextAlignment(Qt.AlignCenter)
        qos_color = QColor(DSCP_CLASSES.get(packet_info.get('qos_dscp', 0), ('', '', '#78909C'))[2])
        qos_item.setBackground(QBrush(qos_color))
        qos_item.setForeground(QBrush(QColor('white')))
        self.setItem(row, 5, qos_item)
        
        len_item = QTableWidgetItem(str(packet_info['length']))
        len_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.setItem(row, 6, len_item)
        
        info = packet_info.get('info', '')
        if len(info) > 100:
            info = info[:97] + '...'
        self.setItem(row, 7, QTableWidgetItem(info))
    
    def should_display(self, packet_info):
        """Use advanced filter parser"""
        if not self.filter_text:
            return True
        
        try:
            return FilterParser.parse_and_evaluate(self.filter_text, packet_info)
        except:
            filter_lower = self.filter_text.lower()
            if packet_info['protocol'].lower() == filter_lower:
                return True
            if filter_lower in packet_info['src'].lower() or filter_lower in packet_info['dst'].lower():
                return True
            if filter_lower in packet_info.get('info', '').lower():
                return True
            return False
    
    def apply_filter(self, filter_text):
        """Apply advanced filter"""
        self.filter_text = filter_text
        self.filtered_packets.clear()
        
        self.setUpdatesEnabled(False)
        self.setRowCount(0)
        try:
            for packet in self.packets:
                if self.should_display(packet):
                    display_info = {k: v for k, v in packet.items() if k != 'raw_packet'}
                    self.filtered_packets.append(display_info)
                    self.display_packet_fast(display_info)
        finally:
            self.setUpdatesEnabled(True)
    
    def on_selection(self):
        row = self.currentRow()
        if 0 <= row < len(self.filtered_packets):
            packet_no = self.filtered_packets[row]['no']
            full_packet = next((p for p in self.packets if p['no'] == packet_no), None)
            if full_packet:
                self.packet_selected.emit(full_packet)
    
    def clear_all(self):
        with self._pending_lock:
            self.packets.clear()
            self.filtered_packets.clear()
            self._pending_packets.clear()
        
        self.setUpdatesEnabled(False)
        try:
            self.setRowCount(0)
        finally:
            self.setUpdatesEnabled(True)

class PacketDetailsWidget(QTextBrowser):
    """Compact packet details viewer"""
    def __init__(self):
        super().__init__()
        self.setFont(QFont("Consolas", 8))
        self.setStyleSheet(f"""
            QTextBrowser {{
                background-color: {COLORS['dark']};
                color: {COLORS['light']};
                border: none;
                padding: 8px;
                font-size: 8pt;
            }}
        """)
    
    def show_packet_details(self, packet_info):
        html = f"""
        <style>
        body {{
            background-color: {COLORS['dark']};
            color: {COLORS['light']};
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 8pt;
            margin: 0;
            padding: 0;
        }}
        h3 {{
            color: {COLORS['primary']};
            border-bottom: 1px solid {COLORS['primary']};
            padding-bottom: 4px;
            margin: 8px 0 4px 0;
            font-size: 10pt;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: 100px 1fr;
            gap: 4px;
            margin: 8px 0;
            font-size: 8pt;
        }}
        .label {{
            color: {COLORS['info']};
            font-weight: 600;
        }}
        .value {{
            color: {COLORS['light']};
            font-family: Consolas, monospace;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 8px;
            font-size: 8pt;
            font-weight: 600;
        }}
        </style>
        
        <h3>📦 Packet #{packet_info['no']}</h3>
        
        <div class="info-grid">
            <div class="label">Time:</div>
            <div class="value">{packet_info['timestamp']}</div>
            
            <div class="label">Source:</div>
            <div class="value">{packet_info['src']}:{packet_info.get('sport', '')}</div>
            
            <div class="label">Destination:</div>
            <div class="value">{packet_info['dst']}:{packet_info.get('dport', '')}</div>
            
            <div class="label">Protocol:</div>
            <div class="value">
                <span class="badge" style="background-color: {PROTOCOL_COLORS.get(packet_info['protocol'], '#78909C')}; color: white;">
                    {packet_info['protocol']}
                </span>
            </div>
            
            <div class="label">Length:</div>
            <div class="value">{packet_info['length']} bytes</div>
            
            <div class="label">Flags:</div>
            <div class="value">{packet_info.get('flags', 'N/A')}</div>
            
            <div class="label">QoS:</div>
            <div class="value">
                <span class="badge" style="background-color: {DSCP_CLASSES.get(packet_info.get('qos_dscp', 0), ('', '', '#78909C'))[2]}; color: white;">
                    {packet_info.get('qos_name', 'BE')}
                </span>
            </div>
            
            <div class="label">Info:</div>
            <div class="value">{packet_info.get('info', 'N/A')}</div>
        </div>
        """
        self.setHtml(html)
    
    def format_hex_dump(self, data):
        if not data:
            return "No raw data available"
        if len(data) > 256:
            data = data[:256]
            truncated = True
        else:
            truncated = False
        
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            hex_part = hex_part.ljust(48)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{i:04x}  {hex_part}  {ascii_part}')
        
        result = '\n'.join(lines)
        if truncated:
            result += '\n... (truncated)'
        return result

class CallFlowDiagram(QGraphicsView):
    """Compact SIP call flow diagram"""
    message_selected = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.scene = QGraphicsScene()
        self.setScene(self.scene)
        self.setRenderHint(QPainter.Antialiasing)
        self.setStyleSheet(f"QGraphicsView {{ background-color: {COLORS['dark']}; border: none; }}")
    
    def draw_call_flow(self, sip_call):
        self.scene.clear()
        
        if not sip_call.messages:
            text = self.scene.addText("No SIP messages", QFont("Arial", 10))
            text.setDefaultTextColor(QColor(COLORS['light']))
            text.setPos(50, 50)
            return
        
        endpoints = set()
        for msg in sip_call.messages:
            endpoints.add(msg['src'])
            endpoints.add(msg['dst'])
        endpoints = sorted(list(endpoints))
        
        if len(endpoints) < 2:
            return
        
        spacing = 250
        start_y = 60
        msg_spacing = 40
        
        positions = {}
        for i, endpoint in enumerate(endpoints):
            x = i * spacing + 120
            positions[endpoint] = x
            
            rect = QGraphicsRectItem(x-60, start_y, 120, 30)
            rect.setBrush(QBrush(QColor(COLORS['card'])))
            rect.setPen(QPen(QColor(COLORS['primary']), 2))
            self.scene.addItem(rect)
            
            text = self.scene.addText(endpoint, QFont("Arial", 8, QFont.Bold))
            text.setDefaultTextColor(QColor(COLORS['light']))
            text.setPos(x - text.boundingRect().width()/2, start_y + 8)
            
            line = QGraphicsLineItem(x, start_y + 30, x, start_y + 30 + len(sip_call.messages) * msg_spacing + 30)
            line.setPen(QPen(QColor(COLORS['card']), 2, Qt.DashLine))
            self.scene.addItem(line)
        
        y = start_y + 60
        for msg in sip_call.messages:
            src_x = positions.get(msg['src'], positions[endpoints[0]])
            dst_x = positions.get(msg['dst'], positions[endpoints[-1]])
            
            method = msg.get('method', 'Unknown')
            color = SIP_METHOD_COLORS.get(method, '#78909C')
            
            line = QGraphicsLineItem(src_x, y, dst_x, y)
            line.setPen(QPen(QColor(color), 2))
            self.scene.addItem(line)
            
            if src_x < dst_x:
                points = [QPointF(dst_x-8, y-5), QPointF(dst_x, y), QPointF(dst_x-8, y+5)]
            else:
                points = [QPointF(dst_x+8, y-5), QPointF(dst_x, y), QPointF(dst_x+8, y+5)]
            arrow = QGraphicsPolygonItem(QPolygonF(points))
            arrow.setBrush(QBrush(QColor(color)))
            arrow.setPen(QPen(QColor(color)))
            self.scene.addItem(arrow)
            
            label_text = QGraphicsTextItem(method)
            label_text.setDefaultTextColor(QColor('white'))
            label_text.setFont(QFont("Arial", 7, QFont.Bold))
            
            label_bg = QGraphicsRectItem(
                (src_x + dst_x)/2 - 25, y - 18,
                50, 16
            )
            label_bg.setBrush(QBrush(QColor(color)))
            label_bg.setPen(QPen(Qt.NoPen))
            self.scene.addItem(label_bg)
            
            label_text.setPos((src_x + dst_x)/2 - label_text.boundingRect().width()/2, y - 18)
            self.scene.addItem(label_text)
            
            y += msg_spacing
        
        self.scene.setSceneRect(self.scene.itemsBoundingRect())

class SIPMessageDetailsWidget(QTextBrowser):
    """Compact SIP message details"""
    def __init__(self):
        super().__init__()
        self.setFont(QFont("Consolas", 8))
        self.setStyleSheet(f"""
            QTextBrowser {{
                background-color: {COLORS['dark']};
                color: {COLORS['light']};
                border: none;
                padding: 8px;
                font-size: 8pt;
            }}
        """)
    
    def show_message_details(self, sip_message):
        method = sip_message.get('method', 'Unknown')
        html = f"""
        <style>
        body {{
            background-color: {COLORS['dark']};
            color: {COLORS['light']};
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 8pt;
        }}
        h3 {{
            color: {COLORS['primary']};
            border-bottom: 1px solid {COLORS['primary']};
            padding-bottom: 4px;
            font-size: 10pt;
        }}
        .field {{
            margin: 6px 0;
            padding: 6px;
            background-color: {COLORS['card']};
            border-radius: 4px;
        }}
        .field-label {{
            color: {COLORS['info']};
            font-weight: 600;
        }}
        pre {{
            background-color: {COLORS['darker']};
            padding: 8px;
            border-radius: 4px;
            border-left: 2px solid {COLORS['primary']};
            overflow-x: auto;
            font-size: 7pt;
        }}
        </style>
        
        <h3>📡 SIP Message: {method}</h3>
        
        <div class="field">
            <div class="field-label">From:</div>
            <div>{sip_message.get('from', 'N/A')}</div>
        </div>
        
        <div class="field">
            <div class="field-label">To:</div>
            <div>{sip_message.get('to', 'N/A')}</div>
        </div>
        
        <div class="field">
            <div class="field-label">Call-ID:</div>
            <div style="font-family: Consolas; font-size: 7pt;">{sip_message.get('call_id', 'N/A')}</div>
        </div>
        
        <h3 style="margin-top: 12px;">Raw Message</h3>
        <pre>{sip_message.get('raw', 'Not available')[:1000]}</pre>
        """
        self.setHtml(html)

class RTPStreamWidget(QWidget):
    """Compact RTP stream widget"""
    def __init__(self):
        super().__init__()
        self.streams = {}
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        
        header = QLabel("🎵 RTP Streams")
        header.setStyleSheet(f"""
            QLabel {{
                font-size: 10pt;
                font-weight: 600;
                color: {COLORS['primary']};
                padding: 6px;
                background-color: {COLORS['card']};
            }}
        """)
        layout.addWidget(header)
        
        self.stream_table = QTableWidget()
        self.stream_table.setColumnCount(8)
        self.stream_table.setHorizontalHeaderLabels([
            'SSRC', 'Codec', 'Pkts', 'Lost', 'Jitter', 'MOS', 'Dur', 'Actions'
        ])
        self.stream_table.verticalHeader().setDefaultSectionSize(24)
        self.stream_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['dark']};
                color: {COLORS['light']};
                gridline-color: {COLORS['card']};
                border: none;
                font-size: 8pt;
            }}
            QHeaderView::section {{
                background-color: {COLORS['darker']};
                color: {COLORS['light']};
                padding: 6px;
                border: none;
                font-weight: 600;
                font-size: 8pt;
            }}
        """)
        layout.addWidget(self.stream_table)
        
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(6)
        
        export_all = QPushButton("💾 Export All")
        export_all.setStyleSheet(self.get_button_style(COLORS['success']))
        export_all.clicked.connect(self.export_all)
        btn_layout.addWidget(export_all)
        
        clear_btn = QPushButton("🗑️ Clear")
        clear_btn.setStyleSheet(self.get_button_style(COLORS['danger']))
        clear_btn.clicked.connect(self.clear_streams_with_confirm)
        btn_layout.addWidget(clear_btn)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
    
    def get_button_style(self, color):
        return f"""
            QPushButton {{
                background-color: {color};
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
                font-weight: 600;
                font-size: 8pt;
            }}
            QPushButton:hover {{
                opacity: 0.8;
            }}
        """
    
    def add_stream(self, ssrc, stream):
        self.streams[ssrc] = stream
        self.update_display()
    
    def update_display(self):
        self.stream_table.setRowCount(len(self.streams))
        
        for row, (ssrc, stream) in enumerate(self.streams.items()):
            self.stream_table.setItem(row, 0, QTableWidgetItem(str(ssrc)))
            self.stream_table.setItem(row, 1, QTableWidgetItem(stream.codec['name'][:15]))
            self.stream_table.setItem(row, 2, QTableWidgetItem(str(stream.packet_count)))
            
            stream.detect_packet_loss()
            lost = QTableWidgetItem(str(stream.lost_packets))
            if stream.lost_packets > 0:
                lost.setBackground(QBrush(QColor(COLORS['danger'])))
            self.stream_table.setItem(row, 3, lost)
            
            jitter = QTableWidgetItem(f"{stream.avg_jitter:.1f}")
            if stream.avg_jitter > 30:
                jitter.setBackground(QBrush(QColor(COLORS['danger'])))
            self.stream_table.setItem(row, 4, jitter)
            
            mos = stream.calculate_mos()
            mos_item = QTableWidgetItem(f"{mos:.2f}")
            if mos < 3.0:
                mos_item.setBackground(QBrush(QColor(COLORS['danger'])))
            elif mos < 4.0:
                mos_item.setBackground(QBrush(QColor(COLORS['warning'])))
            else:
                mos_item.setBackground(QBrush(QColor(COLORS['success'])))
            self.stream_table.setItem(row, 5, mos_item)
            
            duration = stream.end_time - stream.start_time if stream.start_time and stream.end_time else 0
            self.stream_table.setItem(row, 6, QTableWidgetItem(f"{duration:.1f}s"))
            
            action_w = QWidget()
            action_l = QHBoxLayout(action_w)
            action_l.setContentsMargins(2, 2, 2, 2)
            action_l.setSpacing(2)
            
            export = QPushButton("💾")
            export.setMaximumWidth(30)
            export.setStyleSheet(f"QPushButton {{ background-color: {COLORS['success']}; color: white; border: none; padding: 2px; font-size: 10pt; }}")
            export.clicked.connect(lambda _, s=ssrc: self.export_stream(s))
            action_l.addWidget(export)
            
            play = QPushButton("▶️")
            play.setMaximumWidth(30)
            play.setStyleSheet(f"QPushButton {{ background-color: {COLORS['primary']}; color: white; border: none; padding: 2px; font-size: 10pt; }}")
            play.clicked.connect(lambda _, s=ssrc: self.play_stream(s))
            action_l.addWidget(play)
            
            self.stream_table.setCellWidget(row, 7, action_w)
        
        self.stream_table.resizeColumnsToContents()
    
    def export_stream(self, ssrc):
        if ssrc not in self.streams:
            return
        
        stream = self.streams[ssrc]
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Audio', f'rtp_{ssrc}.wav', 'WAV Files (*.wav)')
        if filename:
            if stream.export_to_wav(filename):
                QMessageBox.information(self, 'Success', f'Audio exported to:\n{filename}')
            else:
                QMessageBox.critical(self, 'Error', 'Export failed')
    
    def play_stream(self, ssrc):
        if ssrc not in self.streams:
            return
        
        stream = self.streams[ssrc]
        temp = f'temp_{ssrc}.wav'
        if stream.export_to_wav(temp):
            try:
                if sys.platform == "win32":
                    os.startfile(temp)
                elif sys.platform == "darwin":
                    subprocess.call(['open', temp])
                else:
                    subprocess.call(['xdg-open', temp])
            except Exception as e:
                QMessageBox.warning(self, 'Error', f'Could not play audio: {e}')
    
    def export_all(self):
        if not self.streams:
            QMessageBox.information(self, 'No Streams', 'No RTP streams to export')
            return
        
        dir_path = QFileDialog.getExistingDirectory(self, 'Select Export Directory')
        if dir_path:
            count = 0
            for ssrc, stream in self.streams.items():
                if stream.export_to_wav(os.path.join(dir_path, f'rtp_{ssrc}.wav')):
                    count += 1
            QMessageBox.information(self, 'Export Complete', f'Exported {count} of {len(self.streams)} streams')
    
    def clear_streams(self):
        self.streams.clear()
        self.stream_table.setRowCount(0)
    
    def clear_streams_with_confirm(self):
        if QMessageBox.question(self, 'Clear Streams', 'Clear all RTP streams?') == QMessageBox.Yes:
            self.clear_streams()

class StatsDashboard(QWidget):
    """Compact statistics dashboard"""
    def __init__(self):
        super().__init__()
        self.setup_ui()
    
    def setup_ui(self):
        layout = QGridLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.stat_widgets = {}
        stats = [
            ('packets', '📦 Packets', '0', COLORS['primary']),
            ('calls', '📞 Calls', '0', COLORS['success']),
            ('streams', '🎵 Streams', '0', COLORS['info']),
            ('data', '📊 Rate', '0 KB/s', COLORS['warning'])
        ]
        
        for idx, (key, label, value, color) in enumerate(stats):
            widget = self.create_stat_card(label, value, color)
            self.stat_widgets[key] = widget
            layout.addWidget(widget, 0, idx)
    
    def create_stat_card(self, label, value, color):
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['card']};
                border-radius: 6px;
                border-left: 3px solid {color};
            }}
        """)
        
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(8, 6, 8, 6)
        card_layout.setSpacing(2)
        
        label_widget = QLabel(label)
        label_widget.setStyleSheet(f"color: {COLORS['light']}; font-size: 8pt; font-weight: 600;")
        card_layout.addWidget(label_widget)
        
        value_widget = QLabel(value)
        value_widget.setStyleSheet(f"color: {color}; font-size: 14pt; font-weight: 700;")
        value_widget.setObjectName("value")
        card_layout.addWidget(value_widget)
        
        return card
    
    def update_stats(self, packets=None, calls=None, streams=None, data_rate=None):
        if packets is not None:
            self.stat_widgets['packets'].findChild(QLabel, "value").setText(str(packets))
        if calls is not None:
            self.stat_widgets['calls'].findChild(QLabel, "value").setText(str(calls))
        if streams is not None:
            self.stat_widgets['streams'].findChild(QLabel, "value").setText(str(streams))
        if data_rate is not None:
            self.stat_widgets['data'].findChild(QLabel, "value").setText(f"{data_rate:.1f} KB/s")

class NetHawkPro(QMainWindow):
    """PROFESSIONAL Main Application - COMPLETE with FIXES"""
    def __init__(self):
        super().__init__()
        self.config = load_config()
        self.capture_thread = None
        self.capturing = False
        self.packet_db = PacketDatabase()
        self.sip_calls = {}
        self.rtp_streams = {}
        self.remote_agents = []
        self.pcap_loader = None
        self._is_loading = False
        
        self.voip_parse_queue = []
        self.voip_queue_lock = threading.Lock()
        self.voip_parse_timer = QTimer()
        self.voip_parse_timer.timeout.connect(self.process_voip_queue)
        self.voip_parse_timer.start(100)
        
        self.packet_batch = []
        self.packet_batch_lock = threading.Lock()
        self.batch_timer = QTimer()
        self.batch_timer.timeout.connect(self.process_packet_batch)
        self.batch_timer.start(self.config.get('update_interval', 200))
        
        self.setup_ui()
        self.setup_menu()
        self.setup_toolbar()
        self.setup_status_bar()
        self.apply_modern_theme()
        
        os.makedirs(self.config.get('audio_output_dir', './audio_exports'), exist_ok=True)
    
    def setup_ui(self):
        self.setWindowTitle('NetHawk Pro - Professional Network Analyzer')
        self.setGeometry(100, 100, 1600, 900)
        
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(8)
        main_layout.setContentsMargins(8, 8, 8, 8)
        
        # Compact control panel
        control = QGroupBox()
        control.setStyleSheet(f"""
            QGroupBox {{
                background-color: {COLORS['card']};
                border-radius: 6px;
                padding: 8px;
                border: none;
            }}
        """)
        control_layout = QHBoxLayout(control)
        control_layout.setSpacing(8)
        control_layout.setContentsMargins(8, 8, 8, 8)
        
        control_layout.addWidget(QLabel("🌐 Interface:"))
        self.interface_combo = QComboBox()
        self.interface_combo.addItem("Auto-detect", None)
        self.interface_combo.setStyleSheet(self.get_combo_style())
        control_layout.addWidget(self.interface_combo)
        
        control_layout.addWidget(QLabel("🔍 Filter:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("All Traffic", "all")
        self.filter_combo.addItem("VoIP Only", "voip")
        self.filter_combo.setStyleSheet(self.get_combo_style())
        control_layout.addWidget(self.filter_combo)
        
        self.start_btn = QPushButton('▶ Start')
        self.start_btn.clicked.connect(self.start_capture)
        self.start_btn.setStyleSheet(self.get_button_style(COLORS['success']))
        control_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton('⏸ Stop')
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet(self.get_button_style(COLORS['danger']))
        control_layout.addWidget(self.stop_btn)
        
        self.clear_btn = QPushButton('🗑️ Clear')
        self.clear_btn.clicked.connect(self.clear_all)
        self.clear_btn.setStyleSheet(self.get_button_style(COLORS['warning']))
        control_layout.addWidget(self.clear_btn)
        
        self.status_label = QLabel('● Ready')
        self.status_label.setStyleSheet(f"""
            QLabel {{
                color: {COLORS['success']};
                font-weight: 600;
                font-size: 9pt;
                padding: 6px 12px;
                background-color: rgba(76, 175, 80, 0.1);
                border-radius: 4px;
            }}
        """)
        control_layout.addWidget(self.status_label)
        control_layout.addStretch()
        
        main_layout.addWidget(control)
        
        self.stats_dashboard = StatsDashboard()
        main_layout.addWidget(self.stats_dashboard)
        
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
                background-color: {COLORS['card']};
                border-radius: 6px;
            }}
            QTabBar::tab {{
                background-color: {COLORS['darker']};
                color: {COLORS['light']};
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                font-weight: 600;
                font-size: 9pt;
            }}
            QTabBar::tab:selected {{
                background-color: {COLORS['primary']};
            }}
        """)
        main_layout.addWidget(self.tabs)
        
        self.setup_packet_tab()
        self.setup_voip_tab()
        self.setup_remote_tab()
    
    def get_combo_style(self):
        return f"""
            QComboBox {{
                background-color: {COLORS['darker']};
                color: {COLORS['light']};
                border: none;
                padding: 6px 10px;
                border-radius: 4px;
                min-width: 120px;
                font-size: 8pt;
            }}
            QComboBox QAbstractItemView {{
                background-color: {COLORS['darker']};
                color: {COLORS['light']};
                selection-background-color: {COLORS['primary']};
            }}
        """
    
    def get_button_style(self, color):
        return f"""
            QPushButton {{
                background-color: {color};
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
                font-weight: 600;
                font-size: 9pt;
            }}
            QPushButton:hover {{
                opacity: 0.9;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['card']};
                color: {COLORS['light']};
            }}
        """
    
    def setup_packet_tab(self):
        """Setup packet tab with ADVANCED FILTERING"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(6)
        layout.setContentsMargins(6, 6, 6, 6)
        
        # Filter panel with quick buttons
        filter_panel = QHBoxLayout()
        filter_panel.addWidget(QLabel("🔍 Display Filter:"))
        
        self.display_filter = QLineEdit()
        self.display_filter.setPlaceholderText("e.g., ip.addr == 192.168.1.1 or tcp.port == 80 or protocol == SIP")
        self.display_filter.textChanged.connect(self.apply_filter)
        self.display_filter.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS['darker']};
                color: {COLORS['light']};
                border: 2px solid {COLORS['card']};
                padding: 6px;
                border-radius: 4px;
                font-size: 8pt;
            }}
            QLineEdit:focus {{
                border: 2px solid {COLORS['primary']};
            }}
        """)
        filter_panel.addWidget(self.display_filter, 1)
        
        # Filter help button
        help_btn = QPushButton("❓")
        help_btn.setMaximumWidth(30)
        help_btn.setToolTip("Show filter syntax help")
        help_btn.clicked.connect(self.show_filter_help)
        help_btn.setStyleSheet(self.get_button_style(COLORS['info']))
        filter_panel.addWidget(help_btn)
        
        layout.addLayout(filter_panel)
        
        # Quick filter buttons
        quick_filter_layout = QHBoxLayout()
        quick_filter_layout.addWidget(QLabel("⚡ Quick:"))
        
        quick_filters = [
            ("SIP", "protocol == sip", COLORS['danger']),
            ("RTP", "protocol == rtp", COLORS['primary']),
            ("TCP", "protocol == tcp", COLORS['success']),
            ("UDP", "protocol == udp", COLORS['warning']),
            ("HTTP", "protocol == http", PROTOCOL_COLORS['HTTP']),
            ("Clear", "", COLORS['card'])
        ]
        
        for label, filter_text, color in quick_filters:
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked, f=filter_text: self.display_filter.setText(f))
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color};
                    color: white;
                    border: none;
                    padding: 4px 10px;
                    border-radius: 3px;
                    font-weight: 600;
                    font-size: 8pt;
                }}
                QPushButton:hover {{
                    opacity: 0.8;
                }}
            """)
            quick_filter_layout.addWidget(btn)
        
        quick_filter_layout.addStretch()
        layout.addLayout(quick_filter_layout)
        
        splitter = QSplitter(Qt.Vertical)
        
        self.packet_table = ModernPacketTable()
        self.packet_table.packet_selected.connect(self.show_packet_details)
        splitter.addWidget(self.packet_table)
        
        detail_tabs = QTabWidget()
        detail_tabs.setStyleSheet(f"""
            QTabBar::tab {{
                padding: 6px 12px;
                font-size: 8pt;
            }}
        """)
        self.packet_details = PacketDetailsWidget()
        detail_tabs.addTab(self.packet_details, "📋 Details")
        
        self.hex_dump = QTextBrowser()
        self.hex_dump.setFont(QFont("Consolas", 8))
        self.hex_dump.setStyleSheet(f"""
            QTextBrowser {{
                background-color: {COLORS['darker']};
                color: {COLORS['light']};
                border: none;
                padding: 8px;
                font-size: 8pt;
            }}
        """)
        detail_tabs.addTab(self.hex_dump, "🔢 Hex")
        
        splitter.addWidget(detail_tabs)
        splitter.setSizes([600, 250])
        layout.addWidget(splitter)
        
        self.tabs.addTab(widget, "📦 Packets")
    
    def show_filter_help(self):
        """Show filter syntax help dialog"""
        help_text = """
<h3 style="color: #2196F3;">NetHawk Filter Syntax</h3>

<h4>Basic Examples:</h4>
<pre>
ip.addr == 192.168.1.1        # Packets with this IP (src or dst)
ip.src == 10.0.0.1            # Packets from this source IP
ip.dst == 10.0.0.1            # Packets to this destination IP
</pre>

<h4>Port Filters:</h4>
<pre>
tcp.port == 80                # TCP packets on port 80 (src or dst)
udp.port == 5060              # UDP packets on port 5060
tcp.dstport == 443            # TCP destination port 443
</pre>

<h4>Protocol Filters:</h4>
<pre>
protocol == tcp               # All TCP packets
protocol == sip               # All SIP packets
protocol == rtp               # All RTP packets
</pre>

<h4>Length Filters:</h4>
<pre>
length > 1000                 # Packets larger than 1000 bytes
length < 100                  # Small packets
</pre>

<h4>Logical Operators:</h4>
<pre>
ip.addr == 192.168.1.1 and tcp.port == 80
ip.addr == 10.0.0.1 or ip.addr == 10.0.0.2
not protocol == arp
</pre>

<h4>Text Search:</h4>
<pre>
info contains INVITE          # SIP packets with INVITE
</pre>
        """
        
        msg = QMessageBox(self)
        msg.setWindowTitle("Filter Syntax Help")
        msg.setTextFormat(Qt.RichText)
        msg.setText(help_text)
        msg.setIcon(QMessageBox.Information)
        msg.exec_()
    
    def setup_voip_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(6)
        layout.setContentsMargins(6, 6, 6, 6)
        
        selector = QHBoxLayout()
        selector.addWidget(QLabel("📞 Call:"))
        self.call_combo = QComboBox()
        self.call_combo.currentTextChanged.connect(self.show_call)
        self.call_combo.setStyleSheet(self.get_combo_style())
        selector.addWidget(self.call_combo)
        
        refresh = QPushButton("🔄 Refresh")
        refresh.clicked.connect(self.refresh_calls)
        refresh.setStyleSheet(self.get_button_style(COLORS['info']))
        selector.addWidget(refresh)
        selector.addStretch()
        
        layout.addLayout(selector)
        
        splitter = QSplitter(Qt.Vertical)
        
        self.call_flow = CallFlowDiagram()
        splitter.addWidget(self.call_flow)
        
        bottom_tabs = QTabWidget()
        bottom_tabs.setStyleSheet(f"""
            QTabBar::tab {{
                padding: 6px 12px;
                font-size: 8pt;
            }}
        """)
        self.sip_details = SIPMessageDetailsWidget()
        bottom_tabs.addTab(self.sip_details, "📡 SIP")
        
        self.rtp_widget = RTPStreamWidget()
        bottom_tabs.addTab(self.rtp_widget, "🎵 RTP")
        
        splitter.addWidget(bottom_tabs)
        splitter.setSizes([400, 250])
        layout.addWidget(splitter)
        
        self.tabs.addTab(widget, "📞 VoIP")
    
    def setup_remote_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(6)
        layout.setContentsMargins(6, 6, 6, 6)
        
        control_box = QGroupBox("🔗 Remote Agent Control")
        control_box.setStyleSheet(f"""
            QGroupBox {{
                background-color: {COLORS['card']};
                border-radius: 6px;
                padding: 8px;
                font-weight: 600;
                font-size: 9pt;
                color: {COLORS['primary']};
            }}
        """)
        control_layout = QHBoxLayout(control_box)
        control_layout.setSpacing(8)
        
        control_layout.addWidget(QLabel("Host:"))
        self.agent_host = QLineEdit()
        self.agent_host.setPlaceholderText("192.168.1.100")
        self.agent_host.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS['darker']};
                color: {COLORS['light']};
                border: none;
                padding: 6px;
                border-radius: 4px;
                font-size: 8pt;
            }}
        """)
        control_layout.addWidget(self.agent_host)
        
        control_layout.addWidget(QLabel("Port:"))
        self.agent_port = QLineEdit("9999")
        self.agent_port.setMaximumWidth(60)
        self.agent_port.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS['darker']};
                color: {COLORS['light']};
                border: none;
                padding: 6px;
                border-radius: 4px;
                font-size: 8pt;
            }}
        """)
        control_layout.addWidget(self.agent_port)
        
        add_agent_btn = QPushButton("➕ Add")
        add_agent_btn.clicked.connect(self.add_remote_agent)
        add_agent_btn.setStyleSheet(self.get_button_style(COLORS['primary']))
        control_layout.addWidget(add_agent_btn)
        
        layout.addWidget(control_box)
        
        self.agent_table = QTableWidget()
        self.agent_table.setColumnCount(5)
        self.agent_table.setHorizontalHeaderLabels(['Host', 'Port', 'Status', 'Actions', 'Remove'])
        self.agent_table.verticalHeader().setDefaultSectionSize(28)
        self.agent_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['dark']};
                color: {COLORS['light']};
                gridline-color: {COLORS['card']};
                border: none;
                font-size: 8pt;
            }}
            QHeaderView::section {{
                background-color: {COLORS['darker']};
                color: {COLORS['light']};
                padding: 6px;
                border: none;
                font-size: 8pt;
            }}
        """)
        layout.addWidget(self.agent_table)
        
        info = QLabel("ℹ️ Remote agents must be running NetHawk Server (port 9999)")
        info.setStyleSheet(f"color: {COLORS['info']}; font-size: 8pt; padding: 6px;")
        layout.addWidget(info)
        
        self.tabs.addTab(widget, "🔗 Remote")
    
    def setup_menu(self):
        menu = self.menuBar()
        menu.setStyleSheet(f"QMenuBar {{ font-size: 9pt; }}")
        
        file = menu.addMenu('File')
        file.addAction('📂 Open PCAP...', self.open_pcap, 'Ctrl+O')
        file.addAction('💾 Save PCAP...', self.save_pcap, 'Ctrl+Shift+S')
        file.addSeparator()
        file.addAction('📊 Export CSV...', self.export_csv, 'Ctrl+E')
        file.addSeparator()
        file.addAction('❌ Exit', self.close, 'Ctrl+Q')
        
        capture = menu.addMenu('Capture')
        capture.addAction('▶ Start', self.start_capture, 'F5')
        capture.addAction('⏸ Stop', self.stop_capture, 'F6')
        capture.addAction('🗑️ Clear', self.clear_all, 'Ctrl+L')
        
        help_menu = menu.addMenu('Help')
        help_menu.addAction('ℹ️ About', self.show_about)
    
    def setup_toolbar(self):
        tb = self.addToolBar('Main')
        tb.setMovable(False)
        tb.setStyleSheet(f"""
            QToolBar {{
                background-color: {COLORS['darker']};
                border: none;
                spacing: 6px;
                padding: 6px;
            }}
            QToolButton {{
                color: {COLORS['light']};
                background-color: {COLORS['card']};
                border: none;
                border-radius: 4px;
                padding: 6px;
                font-size: 9pt;
            }}
            QToolButton:hover {{
                background-color: {COLORS['primary']};
            }}
        """)
        
        tb.addAction('📂 Open', self.open_pcap)
        tb.addAction('💾 Save', self.save_pcap)
        tb.addSeparator()
        tb.addAction('▶ Start', self.start_capture)
        tb.addAction('⏸ Stop', self.stop_capture)
    
    def setup_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.setStyleSheet(f"""
            QStatusBar {{
                background-color: {COLORS['darker']};
                color: {COLORS['light']};
                font-size: 8pt;
            }}
        """)
        
        self.pkts_lbl = QLabel("📦 Packets: 0")
        self.status_bar.addPermanentWidget(self.pkts_lbl)
        
        self.calls_lbl = QLabel("📞 Calls: 0")
        self.status_bar.addPermanentWidget(self.calls_lbl)
        
        self.status_bar.showMessage("Ready to capture!")
    
    def apply_modern_theme(self):
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {COLORS['dark']};
                color: {COLORS['light']};
            }}
            QLabel {{
                color: {COLORS['light']};
                font-size: 8pt;
            }}
            QMenuBar {{
                background-color: {COLORS['darker']};
                color: {COLORS['light']};
            }}
            QMenuBar::item:selected {{
                background-color: {COLORS['primary']};
            }}
            QMenu {{
                background-color: {COLORS['darker']};
                color: {COLORS['light']};
                font-size: 9pt;
            }}
            QMenu::item:selected {{
                background-color: {COLORS['primary']};
            }}
        """)
    
    def lock_ui(self):
        self._is_loading = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self.clear_btn.setEnabled(False)
        self.tabs.setEnabled(False)
        self.status_label.setText('⏳ Loading...')
        self.status_label.setStyleSheet(f"""
            QLabel {{
                color: {COLORS['warning']};
                font-weight: 600;
                font-size: 9pt;
                padding: 6px 12px;
                background-color: rgba(255, 193, 7, 0.1);
                border-radius: 4px;
            }}
        """)
    
    def unlock_ui(self):
        self._is_loading = False
        self.start_btn.setEnabled(not self.capturing)
        self.stop_btn.setEnabled(self.capturing)
        self.clear_btn.setEnabled(True)
        self.tabs.setEnabled(True)
        self.status_label.setText('● Ready')
        self.status_label.setStyleSheet(f"""
            QLabel {{
                color: {COLORS['success']};
                font-weight: 600;
                font-size: 9pt;
                padding: 6px 12px;
                background-color: rgba(76, 175, 80, 0.1);
                border-radius: 4px;
            }}
        """)
    
    def process_packet_batch(self):
        with self.packet_batch_lock:
            if not self.packet_batch:
                return
            batch = self.packet_batch[:]
            self.packet_batch.clear()
        
        for pkt in batch:
            self.packet_table.add_packet(pkt)
        
        if len(batch) > 0:
            self.update_status()
    
    def start_capture(self):
        if self.capturing or self._is_loading:
            return
        
        interface = self.interface_combo.currentData()
        filter_mode = self.filter_combo.currentData()
        
        self.capture_thread = NetworkCapture()
        self.capture_thread.packet_received.connect(self.on_packet)
        self.capture_thread.sip_message_received.connect(self.on_sip)
        self.capture_thread.rtp_packet_received.connect(self.on_rtp)
        self.capture_thread.status_changed.connect(self.on_status)
        self.capture_thread.error_occurred.connect(self.on_error)
        self.capture_thread.start_capture(interface, filter_mode)
        
        self.capturing = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText('● Capturing')
        self.status_label.setStyleSheet(f"""
            QLabel {{
                color: {COLORS['success']};
                font-weight: 600;
                font-size: 9pt;
                padding: 6px 12px;
                background-color: rgba(76, 175, 80, 0.2);
                border-radius: 4px;
            }}
        """)
    
    def stop_capture(self):
        if self.capture_thread:
            self.capture_thread.stop_capture()
            self.capture_thread.wait(3000)
        
        self.capturing = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText('● Stopped')
    
    def clear_all(self):
        if self._is_loading:
            QMessageBox.warning(self, 'Busy', 'Please wait for loading to complete')
            return
        
        if QMessageBox.question(self, 'Clear All', 'Clear all captured data?') == QMessageBox.Yes:
            with self.packet_batch_lock:
                self.packet_batch.clear()
            with self.voip_queue_lock:
                self.voip_parse_queue.clear()
            
            self.packet_table.clear_all()
            self.sip_calls.clear()
            self.rtp_streams.clear()
            self.call_combo.clear()
            self.rtp_widget.clear_streams()
            self.update_status()
    
    def on_packet(self, pkt):
        with self.packet_batch_lock:
            self.packet_batch.append(pkt)
    
    def on_sip(self, sip):
        cid = sip.get('call_id', '')
        if cid:
            if cid not in self.sip_calls:
                self.sip_calls[cid] = SIPCall(cid)
                self.call_combo.addItem(f"Call {cid[:20]}...", cid)
            self.sip_calls[cid].add_message(sip)
            self.update_status()
    
    def on_rtp(self, rtp):
        ssrc = rtp['ssrc']
        if ssrc not in self.rtp_streams:
            self.rtp_streams[ssrc] = RTPStream(ssrc, rtp['payload_type'])
        
        class MockRTP:
            def __init__(self, s, t, p):
                self.sequence = s
                self.timestamp = t
                self.payload = p
        
        self.rtp_streams[ssrc].add_packet(
            MockRTP(rtp['sequence'], rtp['rtp_timestamp'], rtp['payload']),
            rtp['timestamp']
        )
        self.rtp_widget.add_stream(ssrc, self.rtp_streams[ssrc])
    
    def on_status(self, msg):
        self.status_bar.showMessage(msg)
    
    def on_error(self, err):
        self.stop_capture()
        QMessageBox.critical(self, 'Capture Error', err)
    
    def show_packet_details(self, pkt):
        self.packet_details.show_packet_details(pkt)
        if pkt.get('raw_packet'):
            hex_text = "Hex Dump:\n\n" + self.packet_details.format_hex_dump(pkt['raw_packet'])
            self.hex_dump.setPlainText(hex_text)
    
    def show_call(self, text):
        cid = self.call_combo.currentData()
        if cid and cid in self.sip_calls:
            self.call_flow.draw_call_flow(self.sip_calls[cid])
    
    def refresh_calls(self):
        self.call_combo.clear()
        for cid, call in self.sip_calls.items():
            self.call_combo.addItem(f"{call.caller}→{call.callee}", cid)
    
    def apply_filter(self, text):
        self.packet_table.apply_filter(text)
    
    def update_status(self):
        packet_count = len(self.packet_table.packets)
        call_count = len(self.sip_calls)
        stream_count = len(self.rtp_streams)
        
        self.pkts_lbl.setText(f"📦 Packets: {packet_count}")
        self.calls_lbl.setText(f"📞 Calls: {call_count}")
        self.stats_dashboard.update_stats(
            packets=packet_count,
            calls=call_count,
            streams=stream_count
        )
    
    def open_pcap(self):
        """THREAD-SAFE PCAP loading"""
        if self._is_loading:
            QMessageBox.warning(self, 'Busy', 'Already loading a file. Please wait...')
            return
        
        if self.pcap_loader and self.pcap_loader.is_running():
            QMessageBox.warning(self, 'Busy', 'Already loading a file. Please wait...')
            return
        
        filename, _ = QFileDialog.getOpenFileName(
            self, 'Open PCAP File',
            '', 'PCAP Files (*.pcap *.pcapng *.cap)'
        )
        if not filename:
            return
        
        if self.packet_table.packets:
            reply = QMessageBox.question(
                self, 'Clear Current Data?',
                'Clear current packets before loading?',
                QMessageBox.Yes | QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return
        
        self.lock_ui()
        
        with self.packet_batch_lock:
            self.packet_batch.clear()
        with self.voip_queue_lock:
            self.voip_parse_queue.clear()
        
        self.packet_table.clear_all()
        self.sip_calls.clear()
        self.rtp_streams.clear()
        self.call_combo.clear()
        self.rtp_widget.clear_streams()
        
        progress = QProgressDialog("Loading PCAP file...", "Cancel", 0, 100, self)
        progress.setWindowTitle("Loading")
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)
        
        def cancel_load():
            if self.pcap_loader:
                self.pcap_loader.stop()
                self.pcap_loader.wait(1000)
                self.pcap_loader = None
            self.unlock_ui()
        
        progress.canceled.connect(cancel_load)
        progress.show()
        
        self.pcap_loader = PCAPLoader(filename, self.config.get('max_packets', MAX_PACKETS))
        self.pcap_loader.packet_batch_loaded.connect(self.on_pcap_batch_loaded)
        self.pcap_loader.loading_progress.connect(
            lambda curr, total: progress.setValue(int((curr / total * 100)) if total > 0 else 0)
        )
        self.pcap_loader.loading_complete.connect(
            lambda count: self.on_pcap_load_complete(progress, filename, count)
        )
        self.pcap_loader.loading_error.connect(
            lambda err: self.on_pcap_load_error(progress, err)
        )
        
        self.pcap_loader.start()
    
    def on_pcap_batch_loaded(self, packet_batch):
        for packet_info in packet_batch:
            self.packet_table.add_packet(packet_info)
            
            if self.is_likely_voip(packet_info):
                with self.voip_queue_lock:
                    self.voip_parse_queue.append(packet_info)
    
    def process_voip_queue(self):
        with self.voip_queue_lock:
            if not self.voip_parse_queue:
                return
            
            batch_size = 50
            batch = self.voip_parse_queue[:batch_size]
            self.voip_parse_queue = self.voip_parse_queue[batch_size:]
        
        for packet_info in batch:
            try:
                self.parse_voip_from_packet_info_fast(packet_info)
            except:
                pass
    
    def is_likely_voip(self, packet_info):
        protocol = packet_info.get('protocol', '')
        sport = packet_info.get('sport', 0)
        dport = packet_info.get('dport', 0)
        
        if protocol in ['SIP', 'RTP']:
            return True
        
        if sport in [5060, 5061] or dport in [5060, 5061]:
            return True
        
        if 10000 <= sport <= 20000 or 10000 <= dport <= 20000:
            return True
        
        return False
    
    def parse_voip_from_packet_info_fast(self, packet_info):
        if not packet_info.get('raw_packet'):
            return
        
        protocol = packet_info.get('protocol', '')
        sport = packet_info.get('sport', 0)
        dport = packet_info.get('dport', 0)
        
        try:
            from scapy.all import Ether, Raw
            packet = Ether(packet_info['raw_packet'])
            
            if not packet.haslayer(Raw):
                return
            
            raw_data = bytes(packet[Raw].load)
            
            if protocol == 'SIP' or sport in [5060, 5061] or dport in [5060, 5061]:
                if b'SIP/' not in raw_data and b'INVITE' not in raw_data:
                    return
                
                try:
                    sip_data = raw_data.decode('utf-8', errors='ignore')
                    
                    if 'SIP/' not in sip_data:
                        return
                    
                    lines = sip_data.split('\r\n')
                    if not lines or len(lines) < 2:
                        return
                    
                    sip_info = {
                        'timestamp': time.time(),
                        'src': packet_info['src'],
                        'dst': packet_info['dst'],
                        'sport': sport,
                        'dport': dport,
                        'raw': sip_data[:500],
                        'headers': {}
                    }
                    
                    first_line = lines[0]
                    if first_line.startswith('SIP/'):
                        parts = first_line.split(' ', 2)
                        sip_info['type'] = 'response'
                        sip_info['status_code'] = parts[1] if len(parts) > 1 else 'Unknown'
                        sip_info['method'] = sip_info['status_code']
                    else:
                        parts = first_line.split(' ')
                        sip_info['type'] = 'request'
                        sip_info['method'] = parts[0] if parts else 'Unknown'
                    
                    for line in lines[1:20]:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip()
                            if key in ['Call-ID', 'From', 'To']:
                                sip_info['headers'][key] = value.strip()
                    
                    sip_info['call_id'] = sip_info['headers'].get('Call-ID', '')
                    sip_info['from'] = sip_info['headers'].get('From', '')
                    sip_info['to'] = sip_info['headers'].get('To', '')
                    
                    if sip_info['call_id']:
                        self.on_sip(sip_info)
                except:
                    pass
            
            elif protocol == 'RTP' or (10000 <= sport <= 20000) or (10000 <= dport <= 20000):
                if len(raw_data) < 12:
                    return
                
                version = (raw_data[0] >> 6) & 0x03
                if version != 2:
                    return
                
                payload_type = raw_data[1] & 0x7F
                if payload_type > 127:
                    return
                
                try:
                    cc = raw_data[0] & 0x0F
                    sequence = struct.unpack('!H', raw_data[2:4])[0]
                    timestamp = struct.unpack('!I', raw_data[4:8])[0]
                    ssrc = struct.unpack('!I', raw_data[8:12])[0]
                    
                    header_len = 12 + (cc * 4)
                    if header_len <= len(raw_data):
                        rtp_payload = raw_data[header_len:header_len+100]
                        
                        rtp_info = {
                            'timestamp': time.time(),
                            'src': packet_info['src'],
                            'dst': packet_info['dst'],
                            'sport': sport,
                            'dport': dport,
                            'ssrc': ssrc,
                            'sequence': sequence,
                            'rtp_timestamp': timestamp,
                            'payload_type': payload_type,
                            'payload': rtp_payload
                        }
                        
                        self.on_rtp(rtp_info)
                except:
                    pass
        except:
            pass
    
    def on_pcap_load_complete(self, progress, filename, count):
        progress.close()
        self.unlock_ui()
        
        sip_count = len(self.sip_calls)
        rtp_count = len(self.rtp_streams)
        
        voip_info = ""
        if sip_count > 0 or rtp_count > 0:
            voip_info = f"\n\n📞 VoIP Data Found:\n   • SIP Calls: {sip_count}\n   • RTP Streams: {rtp_count}"
        
        QMessageBox.information(
            self,
            'PCAP Loaded Successfully',
            f'✅ Loaded {count:,} packets from:\n{os.path.basename(filename)}{voip_info}'
        )
        
        self.status_bar.showMessage(
            f"Loaded: {os.path.basename(filename)} ({sip_count} calls, {rtp_count} streams)"
        )
        self.update_status()
        self.pcap_loader = None
        
        if sip_count > 0:
            self.tabs.setCurrentIndex(1)
    
    def on_pcap_load_error(self, progress, error):
        progress.close()
        self.unlock_ui()
        QMessageBox.critical(self, 'Load Error', f'Failed to load PCAP:\n{error}')
        self.pcap_loader = None
    
    def save_pcap(self):
        if self._is_loading:
            QMessageBox.warning(self, 'Busy', 'Please wait for loading to complete')
            return
        
        if not self.packet_table.packets:
            QMessageBox.information(self, 'No Packets', 'No packets to save')
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 'Save PCAP',
            f'nethawk_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pcap',
            'PCAP Files (*.pcap)'
        )
        if not filename:
            return
        
        try:
            raw_packets = []
            for pkt_info in self.packet_table.packets:
                if 'raw_packet' in pkt_info and pkt_info['raw_packet']:
                    try:
                        pkt = Ether(pkt_info['raw_packet'])
                        raw_packets.append(pkt)
                    except:
                        pass
            
            if not raw_packets:
                QMessageBox.warning(self, 'No Raw Data', 'No raw packet data available for export')
                return
            
            wrpcap(filename, raw_packets)
            QMessageBox.information(
                self, 'PCAP Saved',
                f'✅ Saved {len(raw_packets):,} packets to:\n{filename}'
            )
        except Exception as e:
            QMessageBox.critical(self, 'Save Error', f'Failed to save PCAP:\n{str(e)}')
    
    def add_remote_agent(self):
        if self._is_loading:
            QMessageBox.warning(self, 'Busy', 'Please wait for loading to complete')
            return
        
        host = self.agent_host.text().strip()
        port = int(self.agent_port.text() or 9999)
        
        if not host:
            QMessageBox.warning(self, 'Input Error', 'Please enter a host address')
            return
        
        progress = QProgressDialog(f"Connecting to {host}:{port}...", None, 0, 0, self)
        progress.setWindowTitle("Connecting")
        progress.setWindowModality(Qt.WindowModal)
        progress.show()
        QApplication.processEvents()
        
        agent = RemoteAgent(host, port)
        if agent.connect() or agent.enhanced_connect():
            self.remote_agents.append(agent)
            
            row = self.agent_table.rowCount()
            self.agent_table.insertRow(row)
            self.agent_table.setItem(row, 0, QTableWidgetItem(host))
            self.agent_table.setItem(row, 1, QTableWidgetItem(str(port)))
            
            status_item = QTableWidgetItem("Connected")
            status_item.setForeground(QBrush(QColor(COLORS['success'])))
            self.agent_table.setItem(row, 2, status_item)
            
            action_w = QWidget()
            action_l = QHBoxLayout(action_w)
            action_l.setContentsMargins(2, 2, 2, 2)
            action_l.setSpacing(2)
            
            start_btn = QPushButton("▶")
            start_btn.setMaximumWidth(30)
            start_btn.setStyleSheet(f"QPushButton {{ background-color: {COLORS['success']}; color: white; border: none; padding: 2px; }}")
            start_btn.clicked.connect(lambda _, r=row: self.start_remote_capture(r))
            action_l.addWidget(start_btn)
            
            stop_btn = QPushButton("⏸")
            stop_btn.setMaximumWidth(30)
            stop_btn.setStyleSheet(f"QPushButton {{ background-color: {COLORS['danger']}; color: white; border: none; padding: 2px; }}")
            stop_btn.clicked.connect(lambda _, r=row: self.stop_remote_capture(r))
            action_l.addWidget(stop_btn)
            
            self.agent_table.setCellWidget(row, 3, action_w)
            
            remove_btn = QPushButton("❌")
            remove_btn.setMaximumWidth(30)
            remove_btn.setStyleSheet(f"QPushButton {{ background-color: {COLORS['warning']}; color: white; border: none; padding: 2px; }}")
            remove_btn.clicked.connect(lambda _, r=row: self.remove_remote_agent(r))
            self.agent_table.setCellWidget(row, 4, remove_btn)
            
            progress.close()
            self.agent_host.clear()
            QMessageBox.information(self, 'Connected', f'✅ Connected to {host}:{port}\n\nClick ▶ to start remote capture.')
        else:
            progress.close()
            QMessageBox.critical(self, 'Connection Failed', f'Failed to connect to {host}:{port}\n\nMake sure NetHawk Server is running on the remote host.')
    
    def start_remote_capture(self, row):
        if row >= len(self.remote_agents):
            return
        
        agent = self.remote_agents[row]
        if agent.start_remote_capture(filters=None, packet_callback=self.on_remote_packet) or agent.start_enhanced_capture(filters=None, packet_callback=self.on_remote_packet):
            self.agent_table.item(row, 2).setText("Capturing")
            self.agent_table.item(row, 2).setForeground(QBrush(QColor(COLORS['warning'])))
            QMessageBox.information(self, 'Remote Capture Started', 'Remote capture is now active.\n\nPackets will appear in the Packets tab.')
        else:
            QMessageBox.critical(self, 'Error', 'Failed to start remote capture')
    
    def stop_remote_capture(self, row):
        if row >= len(self.remote_agents):
            return
        
        agent = self.remote_agents[row]
        agent.stop_capture()
        self.agent_table.item(row, 2).setText("Connected")
        self.agent_table.item(row, 2).setForeground(QBrush(QColor(COLORS['success'])))
        QMessageBox.information(self, 'Remote Capture Stopped', 'Remote capture has been stopped.')
    
    def remove_remote_agent(self, row):
        if row >= len(self.remote_agents):
            return
        
        reply = QMessageBox.question(
            self, 'Remove Agent',
            'Remove this agent?',
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            agent = self.remote_agents[row]
            agent.disconnect()
            del self.remote_agents[row]
            self.agent_table.removeRow(row)
    
    def on_remote_packet(self, packet_info):
        """Handle packets received from remote agent"""
        self.on_packet(packet_info)
        
        if self.is_likely_voip(packet_info):
            with self.voip_queue_lock:
                self.voip_parse_queue.append(packet_info)
    
    def export_csv(self):
        if self._is_loading:
            QMessageBox.warning(self, 'Busy', 'Please wait for loading to complete')
            return
        
        if not self.packet_table.packets:
            QMessageBox.information(self, 'No Packets', 'No packets to export')
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 'Export CSV',
            f'nethawk_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
            'CSV Files (*.csv)'
        )
        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        'No', 'Time', 'Source', 'Destination',
                        'Protocol', 'Length', 'QoS', 'Info'
                    ])
                    for p in self.packet_table.packets:
                        writer.writerow([
                            p['no'], p['timestamp'], p['src'], p['dst'],
                            p['protocol'], p['length'],
                            p.get('qos_name', 'BE'), p.get('info', '')
                        ])
                QMessageBox.information(
                    self, 'CSV Exported',
                    f'✅ Exported {len(self.packet_table.packets):,} packets to:\n{filename}'
                )
            except Exception as e:
                QMessageBox.critical(self, 'Export Error', f'Failed to export CSV:\n{str(e)}')
    
    def show_about(self):
        QMessageBox.about(
            self, 'About NetHawk Pro',
            f'''<h2 style="color: {COLORS['primary']};">NetHawk Pro</h2>
            <p><b>Professional Network Protocol Analyzer</b></p>
            <p>Version 2.1 - Complete Fixed Edition</p>
            
            <h3 style="color: {COLORS['info']};">Features</h3>
            <ul>
                <li>✅ Thread-Safe Architecture</li>
                <li>✅ Fixed Dialog Visibility</li>
                <li>✅ Wireshark-Style Filtering</li>
                <li>✅ Working Remote Capture</li>
                <li>✅ Fast PCAP Loading</li>
                <li>✅ Complete Protocol Support</li>
                <li>✅ Advanced VoIP Analysis</li>
                <li>✅ RTP Stream Export & Playback</li>
            </ul>
            
            <p style="margin-top: 20px;">
                <b>Filter Examples:</b><br>
                • ip.addr == 192.168.1.1<br>
                • tcp.port == 80<br>
                • protocol == sip or protocol == rtp
            </p>
            
            <p style="margin-top: 20px; color: {COLORS['primary']};">
                <i>Professional Network Analysis Tool</i>
            </p>
            '''
        )
    
    def closeEvent(self, event):
        if self._is_loading:
            reply = QMessageBox.question(
                self, 'Loading in Progress',
                'File loading in progress. Stop and exit?',
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                event.ignore()
                return
            
            if self.pcap_loader:
                self.pcap_loader.stop()
                self.pcap_loader.wait(1000)
        
        if self.capturing:
            reply = QMessageBox.question(
                self, 'Capture in Progress',
                'Capture in progress. Stop and exit?',
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                event.ignore()
                return
            self.stop_capture()
        
        for agent in self.remote_agents:
            agent.disconnect()
        
        save_config(self.config)
        event.accept()

def main():
    """Main entry point with FIXED THEME"""
    app = QApplication(sys.argv)
    app.setApplicationName("NetHawk Pro - Professional Network Analyzer")
    
    # Apply dark theme globally for ALL dialogs
    setup_dark_theme_globally(app)
    
    try:
        window = NetHawkPro()
        window.show()
        return app.exec_()
    except Exception as e:
        QMessageBox.critical(None, "Fatal Error", f"Application failed to start:\n{str(e)}")
        return 1

if __name__ == '__main__':
    sys.exit(main())