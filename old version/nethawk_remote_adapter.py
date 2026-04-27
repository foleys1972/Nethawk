#!/usr/bin/env python3
"""
NetHawk Remote Capture Adapter
Converts standard remote capture protocols to NetHawk's custom protocol
"""

import socket
import struct
import threading
import time
import pickle
from datetime import datetime
import subprocess
import sys

class NetHawkRemoteAdapter:
    """Adapter to convert standard remote capture to NetHawk protocol"""
    
    def __init__(self, local_port=9999, remote_host=None, remote_port=None):
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.server_socket = None
        self.running = False
        self.capture_thread = None
        self.connected_clients = []
        
    def start_server(self):
        """Start the NetHawk protocol server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.local_port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"🌐 NetHawk Remote Adapter listening on port {self.local_port}")
            print(f"📡 Connect NetHawk to: localhost:{self.local_port}")
            
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    print(f"✅ Client connected from {addr}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        print(f"❌ Server error: {e}")
                        
        except Exception as e:
            print(f"❌ Failed to start server: {e}")
            
    def handle_client(self, client_socket, addr):
        """Handle individual client connection"""
        try:
            # Wait for authentication or start command
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                    
                message = data.decode().strip()
                print(f"📨 Received: {message}")
                
                if message.startswith("AUTH:"):
                    # Handle authentication
                    client_socket.send(b"OK\n")
                    continue
                    
                elif message.startswith("START_CAPTURE"):
                    # Start capture
                    filters = message.split(":", 1)[1] if ":" in message else ""
                    print(f"🎯 Starting capture with filters: {filters}")
                    
                    # Start packet forwarding
                    self.start_packet_forwarding(client_socket, filters)
                    break
                    
                elif message == "STOP_CAPTURE":
                    print("⏹️ Stopping capture")
                    break
                    
        except Exception as e:
            print(f"❌ Client handler error: {e}")
        finally:
            client_socket.close()
            print(f"🔌 Client {addr} disconnected")
            
    def start_packet_forwarding(self, client_socket, filters=""):
        """Start forwarding packets to NetHawk client"""
        try:
            # Method 1: Try to use tshark for remote capture
            if self.remote_host:
                self.forward_from_remote_tshark(client_socket, filters)
            else:
                # Method 2: Use local interface capture
                self.forward_from_local_interface(client_socket, filters)
                
        except Exception as e:
            print(f"❌ Packet forwarding error: {e}")
            
    def forward_from_remote_tshark(self, client_socket, filters):
        """Forward packets from remote host using tshark"""
        try:
            # Build tshark command for remote capture
            cmd = [
                'tshark', '-i', 'any',  # Capture from any interface
                '-T', 'fields',  # Output fields
                '-e', 'frame.number',  # Packet number
                '-e', 'frame.time',  # Timestamp
                '-e', 'ip.src',  # Source IP
                '-e', 'ip.dst',  # Destination IP
                '-e', 'ip.proto',  # Protocol
                '-e', 'tcp.srcport',  # TCP source port
                '-e', 'tcp.dstport',  # TCP destination port
                '-e', 'udp.srcport',  # UDP source port
                '-e', 'udp.dstport',  # UDP destination port
                '-e', 'frame.len',  # Packet length
                '-e', 'frame.protocols'  # Protocol stack
            ]
            
            if filters:
                cmd.extend(['-f', filters])
                
            print(f"🚀 Running: {' '.join(cmd)}")
            
            # Start tshark process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            packet_count = 0
            
            # Read tshark output and forward to NetHawk
            for line in process.stdout:
                if not self.running:
                    break
                    
                try:
                    fields = line.strip().split('\t')
                    if len(fields) >= 8:
                        # Parse tshark output
                        packet_info = self.parse_tshark_fields(fields)
                        
                        # Convert to NetHawk format
                        nethawk_packet = self.convert_to_nethawk_format(packet_info)
                        
                        # Send to NetHawk client
                        self.send_packet_to_client(client_socket, nethawk_packet)
                        packet_count += 1
                        
                        if packet_count % 100 == 0:
                            print(f"📦 Forwarded {packet_count} packets")
                            
                except Exception as e:
                    print(f"⚠️ Error parsing packet: {e}")
                    continue
                    
        except Exception as e:
            print(f"❌ TShark forwarding error: {e}")
            
    def forward_from_local_interface(self, client_socket, filters):
        """Forward packets from local interface using scapy"""
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether
            
            def packet_handler(packet):
                if not self.running:
                    return
                    
                try:
                    # Convert scapy packet to NetHawk format
                    nethawk_packet = self.convert_scapy_to_nethawk(packet)
                    
                    # Send to NetHawk client
                    self.send_packet_to_client(client_socket, nethawk_packet)
                    
                except Exception as e:
                    print(f"⚠️ Error processing packet: {e}")
                    
            # Start sniffing
            print(f"🎯 Starting local capture with filters: {filters}")
            sniff(
                iface=None,  # Auto-detect interface
                filter=filters if filters else None,
                prn=packet_handler,
                store=0  # Don't store packets
            )
            
        except ImportError:
            print("❌ Scapy not available. Install with: pip install scapy")
        except Exception as e:
            print(f"❌ Local capture error: {e}")
            
    def parse_tshark_fields(self, fields):
        """Parse tshark output fields"""
        return {
            'frame_number': fields[0] if len(fields) > 0 else '0',
            'timestamp': fields[1] if len(fields) > 1 else str(datetime.now()),
            'src': fields[2] if len(fields) > 2 else '',
            'dst': fields[3] if len(fields) > 3 else '',
            'proto': fields[4] if len(fields) > 4 else '',
            'src_port': fields[5] if len(fields) > 5 else '',
            'dst_port': fields[6] if len(fields) > 6 else '',
            'length': fields[7] if len(fields) > 7 else '0',
            'protocols': fields[8] if len(fields) > 8 else ''
        }
        
    def convert_to_nethawk_format(self, packet_info):
        """Convert parsed packet info to NetHawk format"""
        return {
            'timestamp': packet_info.get('timestamp', str(datetime.now())),
            'src': packet_info.get('src', ''),
            'dst': packet_info.get('dst', ''),
            'protocol': packet_info.get('proto', ''),
            'length': int(packet_info.get('length', 0)),
            'info': f"{packet_info.get('protocols', '')} {packet_info.get('src_port', '')} -> {packet_info.get('dst_port', '')}",
            'frame_number': int(packet_info.get('frame_number', 0)),
            'raw_packet': b''  # No raw data from tshark fields
        }
        
    def convert_scapy_to_nethawk(self, packet):
        """Convert scapy packet to NetHawk format"""
        try:
            # Extract basic info
            src = packet[IP].src if IP in packet else 'Unknown'
            dst = packet[IP].dst if IP in packet else 'Unknown'
            protocol = packet[IP].proto if IP in packet else 0
            
            # Determine protocol name
            proto_name = 'Unknown'
            if TCP in packet:
                proto_name = 'TCP'
            elif UDP in packet:
                proto_name = 'UDP'
            elif ICMP in packet:
                proto_name = 'ICMP'
            elif ARP in packet:
                proto_name = 'ARP'
                
            # Extract ports if available
            src_port = ''
            dst_port = ''
            if TCP in packet:
                src_port = str(packet[TCP].sport)
                dst_port = str(packet[TCP].dport)
            elif UDP in packet:
                src_port = str(packet[UDP].sport)
                dst_port = str(packet[UDP].dport)
                
            return {
                'timestamp': str(datetime.now()),
                'src': src,
                'dst': dst,
                'protocol': proto_name,
                'length': len(packet),
                'info': f"{proto_name} {src_port} -> {dst_port}",
                'frame_number': 0,  # Will be assigned by NetHawk
                'raw_packet': bytes(packet)
            }
            
        except Exception as e:
            print(f"⚠️ Error converting packet: {e}")
            return {
                'timestamp': str(datetime.now()),
                'src': 'Unknown',
                'dst': 'Unknown',
                'protocol': 'Unknown',
                'length': 0,
                'info': 'Error parsing packet',
                'frame_number': 0,
                'raw_packet': b''
            }
            
    def send_packet_to_client(self, client_socket, packet_info):
        """Send packet to NetHawk client using NetHawk protocol"""
        try:
            # Serialize packet info
            packet_data = pickle.dumps(packet_info)
            packet_size = len(packet_data)
            
            # Send size header (4 bytes, big-endian)
            size_header = struct.pack('!I', packet_size)
            client_socket.send(size_header)
            
            # Send packet data
            client_socket.send(packet_data)
            
        except Exception as e:
            print(f"❌ Error sending packet: {e}")
            
    def stop_server(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("🛑 Server stopped")

def main():
    """Main entry point"""
    print("🌐 NetHawk Remote Capture Adapter")
    print("=" * 50)
    
    # Configuration
    LOCAL_PORT = 9999
    REMOTE_HOST = None  # Set to remote host if using remote capture
    REMOTE_PORT = None
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        LOCAL_PORT = int(sys.argv[1])
    if len(sys.argv) > 2:
        REMOTE_HOST = sys.argv[2]
    if len(sys.argv) > 3:
        REMOTE_PORT = int(sys.argv[3])
    
    print(f"📡 Local Port: {LOCAL_PORT}")
    if REMOTE_HOST:
        print(f"🌍 Remote Host: {REMOTE_HOST}:{REMOTE_PORT}")
    else:
        print("🏠 Local Interface Capture")
    
    # Create and start adapter
    adapter = NetHawkRemoteAdapter(
        local_port=LOCAL_PORT,
        remote_host=REMOTE_HOST,
        remote_port=REMOTE_PORT
    )
    
    try:
        adapter.start_server()
    except KeyboardInterrupt:
        print("\n🛑 Stopping server...")
        adapter.stop_server()
    except Exception as e:
        print(f"❌ Fatal error: {e}")

if __name__ == '__main__':
    main()
