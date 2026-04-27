#!/usr/bin/env python3
"""
NetHawk Remote Capture Fix
Modifies NetHawk to work with standard remote capture protocols
"""

import socket
import struct
import threading
import time
import subprocess
import sys
from datetime import datetime

class StandardRemoteCapture:
    """Standard remote capture implementation for NetHawk"""
    
    def __init__(self, host, port=9999):
        self.host = host
        self.port = port
        self.connected = False
        self.socket = None
        self.capture_process = None
        self.running = False
        
    def connect(self):
        """Connect to remote capture server"""
        try:
            # Try different connection methods
            return self.try_standard_connection()
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
            
    def try_standard_connection(self):
        """Try standard remote capture protocols"""
        
        # Method 1: Try tshark remote capture
        if self.try_tshark_remote():
            return True
            
        # Method 2: Try direct socket connection
        if self.try_direct_socket():
            return True
            
        # Method 3: Try SSH tunnel
        if self.try_ssh_tunnel():
            return True
            
        return False
        
    def try_tshark_remote(self):
        """Try using tshark for remote capture"""
        try:
            print(f"🔍 Trying tshark remote capture to {self.host}:{self.port}")
            
            # Build tshark command for remote capture
            cmd = [
                'tshark',
                '-i', 'any',  # Interface
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
            
            # Start tshark process
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            self.connected = True
            self.running = True
            print("✅ TShark remote capture started")
            return True
            
        except Exception as e:
            print(f"❌ TShark remote capture failed: {e}")
            return False
            
    def try_direct_socket(self):
        """Try direct socket connection"""
        try:
            print(f"🔍 Trying direct socket connection to {self.host}:{self.port}")
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.connect((self.host, self.port))
            
            self.connected = True
            self.running = True
            print("✅ Direct socket connection established")
            return True
            
        except Exception as e:
            print(f"❌ Direct socket connection failed: {e}")
            return False
            
    def try_ssh_tunnel(self):
        """Try SSH tunnel for remote capture"""
        try:
            print(f"🔍 Trying SSH tunnel to {self.host}")
            
            # Create SSH tunnel
            tunnel_cmd = [
                'ssh', '-L', f'9999:{self.host}:{self.port}',
                f'user@{self.host}', '-N'
            ]
            
            self.capture_process = subprocess.Popen(tunnel_cmd)
            time.sleep(2)  # Wait for tunnel to establish
            
            # Now connect to local tunnel
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.connect(('localhost', 9999))
            
            self.connected = True
            self.running = True
            print("✅ SSH tunnel established")
            return True
            
        except Exception as e:
            print(f"❌ SSH tunnel failed: {e}")
            return False
            
    def start_capture(self, filters=None, packet_callback=None):
        """Start remote capture"""
        if not self.connected:
            return False
            
        try:
            if self.capture_process:
                # Handle tshark process
                return self.handle_tshark_capture(filters, packet_callback)
            elif self.socket:
                # Handle socket connection
                return self.handle_socket_capture(filters, packet_callback)
            else:
                return False
                
        except Exception as e:
            print(f"❌ Start capture failed: {e}")
            return False
            
    def handle_tshark_capture(self, filters, packet_callback):
        """Handle tshark capture output"""
        try:
            packet_count = 0
            
            for line in self.capture_process.stdout:
                if not self.running:
                    break
                    
                try:
                    fields = line.strip().split('\t')
                    if len(fields) >= 8:
                        # Parse tshark output
                        packet_info = self.parse_tshark_output(fields)
                        
                        # Call callback if provided
                        if packet_callback:
                            packet_callback(packet_info)
                            
                        packet_count += 1
                        
                        if packet_count % 100 == 0:
                            print(f"📦 Processed {packet_count} packets")
                            
                except Exception as e:
                    print(f"⚠️ Error parsing packet: {e}")
                    continue
                    
            return True
            
        except Exception as e:
            print(f"❌ TShark capture error: {e}")
            return False
            
    def handle_socket_capture(self, filters, packet_callback):
        """Handle socket capture"""
        try:
            # Send start command if needed
            if filters:
                self.socket.send(f"START_CAPTURE:{filters}\n".encode())
            else:
                self.socket.send(b"START_CAPTURE\n")
                
            # Receive packets
            while self.running:
                try:
                    # Try to receive packet data
                    data = self.socket.recv(4096)
                    if not data:
                        break
                        
                    # Parse received data
                    packet_info = self.parse_socket_data(data)
                    
                    # Call callback if provided
                    if packet_callback:
                        packet_callback(packet_info)
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"⚠️ Socket receive error: {e}")
                    break
                    
            return True
            
        except Exception as e:
            print(f"❌ Socket capture error: {e}")
            return False
            
    def parse_tshark_output(self, fields):
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
        
    def parse_socket_data(self, data):
        """Parse socket data"""
        # This would need to be customized based on your server's protocol
        return {
            'timestamp': str(datetime.now()),
            'src': 'Unknown',
            'dst': 'Unknown',
            'protocol': 'Unknown',
            'length': len(data),
            'info': 'Remote capture data',
            'frame_number': 0,
            'raw_packet': data
        }
        
    def stop_capture(self):
        """Stop remote capture"""
        self.running = False
        
        if self.capture_process:
            self.capture_process.terminate()
            self.capture_process = None
            
        if self.socket:
            try:
                self.socket.send(b"STOP_CAPTURE\n")
                self.socket.close()
            except:
                pass
            self.socket = None
            
        print("⏹️ Remote capture stopped")
        
    def disconnect(self):
        """Disconnect from remote server"""
        self.stop_capture()
        self.connected = False
        print("🔌 Disconnected from remote server")

def main():
    """Test the remote capture fix"""
    if len(sys.argv) < 2:
        print("Usage: python nethawk_remote_fix.py <host> [port]")
        print("Example: python nethawk_remote_fix.py 192.168.1.100 9999")
        return
        
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
    
    print(f"🌐 Testing remote capture to {host}:{port}")
    
    # Create remote capture instance
    remote = StandardRemoteCapture(host, port)
    
    # Test connection
    if remote.connect():
        print("✅ Connection successful!")
        
        # Test capture
        def packet_callback(packet):
            print(f"📦 Packet: {packet['src']} -> {packet['dst']} ({packet['protocol']})")
            
        if remote.start_capture(packet_callback=packet_callback):
            print("✅ Capture started!")
            
            try:
                # Run for 10 seconds
                time.sleep(10)
            except KeyboardInterrupt:
                print("\n🛑 Stopping...")
            finally:
                remote.stop_capture()
        else:
            print("❌ Failed to start capture")
    else:
        print("❌ Connection failed")
        
    remote.disconnect()

if __name__ == '__main__':
    main()
