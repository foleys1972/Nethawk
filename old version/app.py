#!/usr/bin/env python3
"""
Full SIP/QoS Web Analyzer - Built from Working Minimal Version
"""

import os
import json
import logging
import tempfile
from datetime import datetime
from collections import defaultdict

from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from scapy.all import rdpcap, IP, UDP, TCP, Raw
    logger.info("Scapy imported successfully")
except ImportError as e:
    print("Please install scapy: pip install flask scapy werkzeug")
    exit(1)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

SIP_PORTS = [5060, 5061, 5062, 5063, 5070, 5080]
SIP_METHODS = ["INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", "PRACK", "SUBSCRIBE", "NOTIFY", "INFO", "REFER", "MESSAGE", "UPDATE"]

class FullSipQosAnalyzer:
    def __init__(self):
        self.reset()
        
        # DSCP name mappings
        self.dscp_names = {
            0: 'BE', 46: 'EF',
            10: 'AF11', 12: 'AF12', 14: 'AF13',
            18: 'AF21', 20: 'AF22', 22: 'AF23',
            26: 'AF31', 28: 'AF32', 30: 'AF33',
            34: 'AF41', 36: 'AF42', 38: 'AF43',
            8: 'CS1', 16: 'CS2', 24: 'CS3', 32: 'CS4',
            40: 'CS5', 48: 'CS6', 56: 'CS7'
        }
        
        # Human explanations
        self.sip_explanations = {
            'INVITE': 'Call setup request - someone is trying to start a call',
            'ACK': 'Call acknowledgment - confirming the call was accepted',
            'BYE': 'Call termination - someone is hanging up',
            'CANCEL': 'Call cancellation - canceling a call before it connects',
            'REGISTER': 'User registration - device signing in to the network',
            'OPTIONS': 'Capability check - asking what features are supported',
            '100': 'Call setup in progress - the system is working on connecting your call',
            '180': 'Phone is ringing - the other party\'s phone is ringing',
            '200': 'Call successful - everything worked perfectly',
            '400': 'Bad request - the call request was malformed',
            '404': 'User not found - the number doesn\'t exist',
            '486': 'Busy here - the person is already on another call',
            '487': 'Request terminated - the call was canceled',
            '500': 'Server error - problem with the phone system',
            '503': 'Service unavailable - phone service is down'
        }
        
    def reset(self):
        self.packet_count = 0
        self.dscp_counts = defaultdict(int)
        self.sip_methods = defaultdict(int)
        self.sip_response_codes = defaultdict(int)
        self.qos_packets = []  # Store packets with QoS info
        self.sip_events = []   # Human-readable SIP events
        self.raw_packets = []  # Raw packet data
        
    def get_dscp_name(self, dscp):
        return self.dscp_names.get(dscp, f'DSCP-{dscp}')
    
    def packet_to_hex(self, packet):
        """Convert packet to hex safely"""
        try:
            raw_bytes = bytes(packet)
            hex_lines = []
            for i in range(0, min(len(raw_bytes), 256), 16):  # Limit to first 256 bytes
                chunk = raw_bytes[i:i+16]
                hex_part = ' '.join([f'{b:02x}' for b in chunk])
                ascii_part = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in chunk])
                hex_lines.append(f"{i:04x}: {hex_part:<48} {ascii_part}")
            return '\n'.join(hex_lines)
        except:
            return "Could not convert to hex"
    
    def analyze_pcap(self, file_path):
        try:
            packets = rdpcap(file_path)
            logger.info(f"Loaded {len(packets)} packets")
            
            for packet in packets:
                self.packet_count += 1
                
                # Extract timestamp and IPs safely
                try:
                    timestamp_str = datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                    src_ip = str(packet[IP].src) if packet.haslayer(IP) else 'Unknown'
                    dst_ip = str(packet[IP].dst) if packet.haslayer(IP) else 'Unknown'
                except:
                    timestamp_str = 'Unknown'
                    src_ip = 'Unknown'
                    dst_ip = 'Unknown'
                
                # Extract QoS info safely - ONLY basic types
                qos_info = {'dscp': 0, 'tos': 0, 'ecn': 0}
                if packet.haslayer(IP):
                    try:
                        tos = int(packet[IP].tos)
                        dscp = int((tos >> 2) & 0x3F)
                        ecn = int(tos & 0x03)
                        qos_info = {'dscp': dscp, 'tos': tos, 'ecn': ecn}
                        self.dscp_counts[dscp] += 1
                    except:
                        self.dscp_counts[0] += 1
                
                # Store raw packet data with ONLY JSON-safe types
                raw_data = {
                    'packet_number': int(self.packet_count),
                    'timestamp': str(timestamp_str),
                    'source': str(src_ip),
                    'destination': str(dst_ip),
                    'size': int(len(packet)),
                    'dscp': int(qos_info['dscp']),
                    'dscp_name': str(self.get_dscp_name(qos_info['dscp'])),
                    'hex_dump': str(self.packet_to_hex(packet))
                }
                self.raw_packets.append(raw_data)
                
                # Check for SIP
                if packet.haslayer(UDP) and packet.haslayer(Raw):
                    try:
                        if packet[UDP].sport in SIP_PORTS or packet[UDP].dport in SIP_PORTS:
                            payload = packet[Raw].load.decode('utf-8', errors='ignore')
                            
                            sip_code = None
                            sip_type = None
                            
                            # Check for SIP methods
                            for method in SIP_METHODS:
                                if payload.startswith(method + ' '):
                                    self.sip_methods[method] += 1
                                    sip_code = method
                                    sip_type = 'method'
                                    break
                            
                            # Check for SIP responses
                            if not sip_code and payload.startswith('SIP/2.0 '):
                                parts = payload.split(' ')
                                if len(parts) >= 2:
                                    code = parts[1]
                                    if code.isdigit():
                                        self.sip_response_codes[code] += 1
                                        sip_code = code
                                        sip_type = 'response'
                            
                            # Create human-readable event
                            if sip_code:
                                explanation = self.sip_explanations.get(sip_code, f'SIP {sip_code}')
                                qos_text = f"QoS: {self.get_dscp_name(qos_info['dscp'])}" if qos_info['dscp'] != 0 else "QoS: No priority"
                                
                                event = {
                                    'packet_number': int(self.packet_count),
                                    'timestamp': str(timestamp_str),
                                    'time_friendly': str(datetime.fromtimestamp(float(packet.time)).strftime('%I:%M:%S %p')),
                                    'source': str(src_ip),
                                    'destination': str(dst_ip),
                                    'sip_code': str(sip_code),
                                    'sip_type': str(sip_type),
                                    'explanation': str(explanation),
                                    'dscp': int(qos_info['dscp']),
                                    'dscp_name': str(self.get_dscp_name(qos_info['dscp'])),
                                    'qos_text': str(qos_text),
                                    'payload_preview': str(payload[:200]),
                                    'full_message': str(payload[:2000])  # Store more of the message
                                }
                                self.sip_events.append(event)
                    except:
                        pass
                        
            return True
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return False
    
    def get_report(self):
        # Generate insights
        insights = []
        total_sip = sum(self.sip_methods.values()) + sum(self.sip_response_codes.values())
        if total_sip > 0:
            insights.append(f"Found {total_sip} SIP messages in the capture")
        
        qos_marked = sum(count for dscp, count in self.dscp_counts.items() if dscp != 0)
        if qos_marked > 0:
            qos_percent = (qos_marked / self.packet_count * 100)
            insights.append(f"QoS markings detected on {qos_percent:.1f}% of traffic")
            
            if self.dscp_counts.get(46, 0) > 0:
                insights.append("Voice traffic prioritization (EF) detected")
            if any(dscp in self.dscp_counts for dscp in [34, 36, 38]):
                insights.append("High-priority application traffic (AF4x) detected")
        else:
            insights.append("No QoS markings found - all traffic treated as best effort")
        
        return {
            'summary': {
                'total_packets': int(self.packet_count),
                'sip_packet_count': int(len(self.sip_events)),
                'qos_marked_packets': int(qos_marked),
                'qos_percentage': float(round((qos_marked / self.packet_count * 100) if self.packet_count > 0 else 0, 2)),
                'unique_dscp_values': int(len(self.dscp_counts))
            },
            'dscp_distribution': {int(k): int(v) for k, v in self.dscp_counts.items()},
            'dscp_names': {int(k): str(v) for k, v in self.dscp_names.items()},
            'sip_methods': {str(k): int(v) for k, v in self.sip_methods.items()},
            'sip_response_codes': {str(k): int(v) for k, v in self.sip_response_codes.items()},
            'sip_events': self.sip_events[-20:],  # Last 20 events
            'insights': insights
        }

analyzer = FullSipQosAnalyzer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded', 'success': False}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected', 'success': False}), 400
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        analyzer.reset()
        
        if analyzer.analyze_pcap(filepath):
            report = analyzer.get_report()
            
            # Test JSON serialization
            json.dumps(report)
            
            os.remove(filepath)
            
            return jsonify({
                'success': True,
                'report': report
            })
        else:
            os.remove(filepath)
            return jsonify({'error': 'Analysis failed', 'success': False}), 500
            
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({'error': f'Server error: {str(e)}', 'success': False}), 500

@app.route('/packets/qos/<dscp_value>')
def get_qos_packets(dscp_value):
    try:
        dscp_val = int(dscp_value)
        
        # Find packets with this DSCP value
        matching_packets = []
        for packet in analyzer.raw_packets:
            if packet['dscp'] == dscp_val:
                matching_packets.append(packet)
        
        response = {
            'success': True,
            'dscp_value': int(dscp_val),
            'dscp_marking': str(analyzer.get_dscp_name(dscp_val)),
            'total_packets': int(len(matching_packets)),
            'packets': matching_packets[:50]  # Limit to 50 for performance
        }
        
        # Test JSON serialization
        json.dumps(response)
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"QoS error: {e}")
        return jsonify({'error': f'Failed: {str(e)}', 'success': False}), 500

@app.route('/packet/<int:packet_id>')
def get_packet_details(packet_id):
    try:
        if packet_id < 1 or packet_id > len(analyzer.raw_packets):
            return jsonify({'error': 'Packet not found', 'success': False}), 404
        
        packet = analyzer.raw_packets[packet_id - 1]
        
        return jsonify({
            'success': True,
            'packet': packet
        })
        
    except Exception as e:
        logger.error(f"Packet details error: {e}")
        return jsonify({'error': f'Failed: {str(e)}', 'success': False}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)