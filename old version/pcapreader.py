#!/usr/bin/env python3
"""
SIP/QoS Web Analyzer - Fixed Version with Better Error Handling
"""

import os
import json
import logging
import tempfile
import traceback
from datetime import datetime
from collections import defaultdict
from typing import Dict, List

from flask import Flask, render_template_string, request, jsonify, send_file
from werkzeug.utils import secure_filename
import io

# Configure logging for debugging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Try to import required libraries with better error messages
try:
    from scapy.all import rdpcap, IP, UDP, TCP, Raw
    from scapy.layers.inet6 import IPv6
    logger.info("Scapy imported successfully")
except ImportError as e:
    logger.error(f"Scapy import failed: {e}")
    print("Please install scapy: pip install scapy")
    exit(1)

# Optional imports for visualization
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import base64
    MATPLOTLIB_AVAILABLE = True
    logger.info("Matplotlib imported successfully")
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    logger.warning("Matplotlib not available - visualizations disabled")

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

# SIP Configuration
SIP_PORTS = [5060, 5061, 5062, 5063, 5070, 5080]
SIP_METHODS = [
    "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", 
    "PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER", 
    "MESSAGE", "UPDATE"
]

class SipQosAnalyzer:
    def __init__(self):
        self.reset()
        
    def reset(self):
        self.packet_count = 0
        self.sip_packets = []
        self.qos_packets = []
        self.sip_methods = defaultdict(int)
        self.sip_response_codes = defaultdict(int)
        self.call_flows = {}
        self.qos_indicators = {
            'dscp_values': defaultdict(int),
            'traffic_classes': defaultdict(int),
            'tos_values': defaultdict(int),
            'ecn_values': defaultdict(int)
        }
        
    def is_sip_packet(self, packet) -> bool:
        """Check if packet contains SIP protocol data"""
        try:
            if not packet.haslayer(Raw):
                return False
                
            # Check ports first
            port_match = False
            if packet.haslayer(UDP):
                if packet[UDP].sport in SIP_PORTS or packet[UDP].dport in SIP_PORTS:
                    port_match = True
            elif packet.haslayer(TCP):
                if packet[TCP].sport in SIP_PORTS or packet[TCP].dport in SIP_PORTS:
                    port_match = True
                    
            if not port_match:
                return False
                
            # Check payload content
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Look for SIP methods
            for method in SIP_METHODS:
                if payload.startswith(method + ' '):
                    return True
                    
            # Look for SIP responses
            if payload.startswith('SIP/2.0'):
                return True
                
            return False
            
        except Exception as e:
            logger.debug(f"Error checking SIP packet: {e}")
            return False
    
    def extract_qos_info(self, packet):
        """Extract QoS information from packet"""
        qos_info = {}
        
        try:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                tos = ip_layer.tos
                dscp = (tos >> 2) & 0x3F
                ecn = tos & 0x03
                
                qos_info = {
                    'dscp': dscp,
                    'ecn': ecn,
                    'tos': tos,
                    'traffic_class': self.get_traffic_class(dscp),
                    'ip_version': 4
                }
                
            elif packet.haslayer(IPv6):
                ipv6_layer = packet[IPv6]
                tc = ipv6_layer.tc
                dscp = (tc >> 2) & 0x3F
                ecn = tc & 0x03
                
                qos_info = {
                    'dscp': dscp,
                    'ecn': ecn,
                    'traffic_class': self.get_traffic_class(dscp),
                    'flow_label': ipv6_layer.fl,
                    'ip_version': 6
                }
                
        except Exception as e:
            logger.debug(f"Error extracting QoS info: {e}")
            
        return qos_info
    
    def get_traffic_class(self, dscp: int) -> str:
        """Map DSCP value to traffic class"""
        if dscp == 0:
            return "Best Effort"
        elif dscp == 46:
            return "Expedited Forwarding"
        elif dscp in [8, 10, 12, 14, 16, 18, 20, 22]:
            return "Assured Forwarding"
        elif dscp in [48, 56]:
            return "Voice"
        elif dscp == 40:
            return "Video"
        elif dscp in [32, 34]:
            return "Real-Time Interactive"
        else:
            return f"Custom (DSCP {dscp})"
    
    def analyze_packet(self, packet):
        """Analyze a single packet"""
        self.packet_count += 1
        
        # Extract QoS info from all packets
        qos_info = self.extract_qos_info(packet)
        if qos_info:
            dscp = qos_info.get('dscp', 0)
            self.qos_indicators['dscp_values'][dscp] += 1
            self.qos_indicators['traffic_classes'][qos_info.get('traffic_class', 'Unknown')] += 1
            self.qos_indicators['tos_values'][qos_info.get('tos', 0)] += 1
            self.qos_indicators['ecn_values'][qos_info.get('ecn', 0)] += 1
        
        # Check for SIP
        if self.is_sip_packet(packet):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Extract method or response code
                lines = payload.split('\n')
                first_line = lines[0].strip() if lines else ''
                
                sip_info = {}
                if ' SIP/2.0' in first_line and not first_line.startswith('SIP/2.0'):
                    # Request
                    method = first_line.split(' ')[0]
                    self.sip_methods[method] += 1
                    sip_info = {'type': 'request', 'method': method}
                elif first_line.startswith('SIP/2.0 '):
                    # Response
                    parts = first_line.split(' ')
                    if len(parts) >= 2:
                        code = parts[1]
                        self.sip_response_codes[code] += 1
                        sip_info = {'type': 'response', 'code': code}
                
                # Store SIP packet info
                packet_info = {
                    'packet_num': self.packet_count,
                    'timestamp': datetime.fromtimestamp(float(packet.time)),
                    'src': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                    'dst': packet[IP].dst if packet.haslayer(IP) else 'Unknown',
                    'sip_info': sip_info,
                    'qos_info': qos_info,
                    'payload': payload[:500]  # First 500 chars
                }
                
                self.sip_packets.append(packet_info)
                
            except Exception as e:
                logger.error(f"Error processing SIP packet: {e}")
    
    def analyze_pcap(self, file_path):
        """Analyze PCAP file"""
        try:
            logger.info(f"Starting analysis of: {file_path}")
            
            # Check if file exists and is readable
            if not os.path.exists(file_path):
                raise Exception(f"File does not exist: {file_path}")
                
            if not os.access(file_path, os.R_OK):
                raise Exception(f"Cannot read file: {file_path}")
            
            # Read packets
            packets = rdpcap(file_path)
            logger.info(f"Loaded {len(packets)} packets")
            
            if len(packets) == 0:
                raise Exception("No packets found in PCAP file")
            
            # Analyze each packet
            for i, packet in enumerate(packets):
                try:
                    self.analyze_packet(packet)
                    if (i + 1) % 1000 == 0:
                        logger.info(f"Processed {i + 1} packets")
                except Exception as e:
                    logger.debug(f"Error processing packet {i}: {e}")
                    
            logger.info(f"Analysis complete - Found {len(self.sip_packets)} SIP packets")
            return True
            
        except Exception as e:
            logger.error(f"PCAP analysis failed: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False
    
    def generate_report(self):
        """Generate analysis report"""
        sip_detected = len(self.sip_packets) > 0
        qos_detected = any(dscp != 0 for dscp in self.qos_indicators['dscp_values'].keys())
        
        total_qos_packets = sum(self.qos_indicators['dscp_values'].values())
        qos_marked_packets = sum(count for dscp, count in self.qos_indicators['dscp_values'].items() if dscp != 0)
        qos_percentage = (qos_marked_packets / total_qos_packets * 100) if total_qos_packets > 0 else 0
        
        return {
            'summary': {
                'total_packets': self.packet_count,
                'sip_detected': sip_detected,
                'sip_packet_count': len(self.sip_packets),
                'qos_detected': qos_detected,
                'qos_marked_packets': qos_marked_packets,
                'qos_percentage': round(qos_percentage, 2),
                'unique_dscp_values': len(self.qos_indicators['dscp_values'])
            },
            'sip_analysis': {
                'methods_used': dict(self.sip_methods),
                'response_codes': dict(self.sip_response_codes)
            },
            'qos_analysis': {
                'dscp_distribution': dict(self.qos_indicators['dscp_values']),
                'traffic_classes': dict(self.qos_indicators['traffic_classes']),
                'tos_distribution': dict(self.qos_indicators['tos_values']),
                'ecn_distribution': dict(self.qos_indicators['ecn_values'])
            }
        }

# Global analyzer
analyzer = SipQosAnalyzer()

# HTML template embedded in code
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>SIP/QoS Analyzer</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }
        .upload-area { border: 2px dashed #ccc; padding: 40px; text-align: center; margin: 20px 0; border-radius: 10px; }
        .upload-area:hover { border-color: #007bff; background: #f8f9fa; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        .btn:hover { background: #0056b3; }
        .results { margin-top: 20px; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #007bff; }
        .stat-card h3 { margin: 0; color: #007bff; font-size: 2em; }
        .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .success { background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .hidden { display: none; }
        #loading { text-align: center; padding: 20px; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #007bff; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <h1>SIP/QoS Network Analyzer</h1>
        
        <div class="upload-area" onclick="document.getElementById('fileInput').click()">
            <h3>Upload PCAP File</h3>
            <p>Click here or drag and drop your PCAP file</p>
            <input type="file" id="fileInput" accept=".pcap,.pcapng" style="display: none;">
            <button class="btn">Choose File</button>
        </div>
        
        <div id="loading" class="hidden">
            <div class="spinner"></div>
            <p>Analyzing PCAP file...</p>
        </div>
        
        <div id="error" class="error hidden"></div>
        
        <div id="results" class="results hidden">
            <h2>Analysis Results</h2>
            <div id="summary" class="stat-grid"></div>
            
            <h3>SIP Analysis</h3>
            <div id="sip-methods"></div>
            <div id="sip-responses"></div>
            
            <h3>QoS Analysis</h3>
            <div id="qos-dscp"></div>
            <div id="qos-classes"></div>
            
            <button class="btn" onclick="exportData()">Export JSON</button>
        </div>
    </div>

    <script>
        let currentData = null;
        
        document.getElementById('fileInput').addEventListener('change', handleFile);
        
        // Drag and drop
        const uploadArea = document.querySelector('.upload-area');
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = '#007bff';
        });
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.style.borderColor = '#ccc';
        });
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = '#ccc';
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                handleFile({target: {files: files}});
            }
        });
        
        function handleFile(event) {
            const file = event.target.files[0];
            if (!file) return;
            
            console.log('Selected file:', file.name, 'Size:', file.size);
            
            const formData = new FormData();
            formData.append('file', file);
            
            showLoading();
            hideError();
            hideResults();
            
            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                console.log('Response status:', response.status);
                return response.json();
            })
            .then(data => {
                console.log('Response data:', data);
                hideLoading();
                
                if (data.success) {
                    currentData = data;
                    displayResults(data.report);
                } else {
                    showError(data.error || 'Analysis failed');
                }
            })
            .catch(error => {
                console.error('Upload error:', error);
                hideLoading();
                showError('Upload failed: ' + error.message);
            });
        }
        
        function displayResults(report) {
            // Summary
            const summaryHtml = `
                <div class="stat-card">
                    <h3>${report.summary.total_packets}</h3>
                    <p>Total Packets</p>
                </div>
                <div class="stat-card">
                    <h3>${report.summary.sip_packet_count}</h3>
                    <p>SIP Packets</p>
                </div>
                <div class="stat-card">
                    <h3>${report.summary.qos_marked_packets}</h3>
                    <p>QoS Marked</p>
                </div>
                <div class="stat-card">
                    <h3>${report.summary.qos_percentage}%</h3>
                    <p>QoS Usage</p>
                </div>
            `;
            document.getElementById('summary').innerHTML = summaryHtml;
            
            // SIP Methods
            let methodsHtml = '<h4>SIP Methods:</h4><div class="stat-grid">';
            for (const [method, count] of Object.entries(report.sip_analysis.methods_used)) {
                methodsHtml += `<div class="stat-card"><h3>${count}</h3><p>${method}</p></div>`;
            }
            methodsHtml += '</div>';
            document.getElementById('sip-methods').innerHTML = methodsHtml;
            
            // QoS DSCP
            let dscpHtml = '<h4>DSCP Values:</h4><div class="stat-grid">';
            for (const [dscp, count] of Object.entries(report.qos_analysis.dscp_distribution)) {
                dscpHtml += `<div class="stat-card"><h3>${count}</h3><p>DSCP ${dscp}</p></div>`;
            }
            dscpHtml += '</div>';
            document.getElementById('qos-dscp').innerHTML = dscpHtml;
            
            showResults();
        }
        
        function showLoading() { document.getElementById('loading').classList.remove('hidden'); }
        function hideLoading() { document.getElementById('loading').classList.add('hidden'); }
        function showError(msg) { 
            document.getElementById('error').textContent = msg;
            document.getElementById('error').classList.remove('hidden'); 
        }
        function hideError() { document.getElementById('error').classList.add('hidden'); }
        function showResults() { document.getElementById('results').classList.remove('hidden'); }
        function hideResults() { document.getElementById('results').classList.add('hidden'); }
        
        function exportData() {
            if (currentData) {
                const blob = new Blob([JSON.stringify(currentData, null, 2)], {type: 'application/json'});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'sip_qos_analysis.json';
                a.click();
            }
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload with extensive error checking"""
    try:
        logger.info("Upload request received")
        
        # Check if file was uploaded
        if 'file' not in request.files:
            logger.error("No file in request")
            return jsonify({'error': 'No file uploaded', 'success': False}), 400
        
        file = request.files['file']
        if file.filename == '':
            logger.error("Empty filename")
            return jsonify({'error': 'No file selected', 'success': False}), 400
        
        logger.info(f"Received file: {file.filename}")
        
        # Save file
        filename = secure_filename(file.filename)
        if not filename:
            return jsonify({'error': 'Invalid filename', 'success': False}), 400
            
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        logger.info(f"Saving to: {filepath}")
        
        file.save(filepath)
        
        # Verify file was saved
        if not os.path.exists(filepath):
            return jsonify({'error': 'Failed to save file', 'success': False}), 500
            
        file_size = os.path.getsize(filepath)
        logger.info(f"File saved successfully, size: {file_size} bytes")
        
        # Reset and analyze
        analyzer.reset()
        
        if analyzer.analyze_pcap(filepath):
            report = analyzer.generate_report()
            logger.info("Analysis completed successfully")
            
            # Clean up
            try:
                os.remove(filepath)
            except:
                pass
                
            return jsonify({
                'success': True,
                'report': report,
                'message': f'Analyzed {report["summary"]["total_packets"]} packets'
            })
        else:
            # Clean up
            try:
                os.remove(filepath)
            except:
                pass
                
            return jsonify({'error': 'PCAP analysis failed', 'success': False}), 500
            
    except Exception as e:
        logger.error(f"Upload error: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Server error: {str(e)}', 'success': False}), 500

@app.route('/debug')
def debug_info():
    """Debug endpoint to check system status"""
    info = {
        'python_version': os.sys.version,
        'scapy_available': True,
        'matplotlib_available': MATPLOTLIB_AVAILABLE,
        'upload_folder': app.config['UPLOAD_FOLDER'],
        'upload_folder_writable': os.access(app.config['UPLOAD_FOLDER'], os.W_OK),
        'temp_dir': tempfile.gettempdir(),
        'max_content_length': app.config['MAX_CONTENT_LENGTH']
    }
    return jsonify(info)

if __name__ == '__main__':
    logger.info("Starting SIP/QoS Web Analyzer")
    logger.info(f"Upload folder: {app.config['UPLOAD_FOLDER']}")
    logger.info(f"Max file size: {app.config['MAX_CONTENT_LENGTH']} bytes")
    
    # Test scapy
    try:
        from scapy.all import Ether
        logger.info("Scapy test successful")
    except Exception as e:
        logger.error(f"Scapy test failed: {e}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)