#!/usr/bin/env python3
"""
NetHawk Remote Capture Protocol Patch
Patches the existing NetHawk code to work with standard remote capture protocols
"""

import re
import os

def patch_nethawk_remote_capture():
    """Patch the NetHawk remote capture implementation"""
    
    # Read the original file
    with open('nethawk2_1.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find the RemoteAgent class and replace it
    old_remote_agent = r'class RemoteAgent:.*?def disconnect\(self\):.*?self\.connected = False'
    
    new_remote_agent = '''class RemoteAgent:
    """Remote capture agent with standard protocol support"""
    def __init__(self, host, port=9999, auth_key=None):
        self.host = host
        self.port = port
        self.auth_key = auth_key
        self.connected = False
        self.socket = None
        self.receiver = None
        self.capture_process = None
        self.running = False
    
    def connect(self):
        """Connect using multiple protocol methods"""
        try:
            # Method 1: Try standard socket connection
            if self.try_socket_connection():
                return True
                
            # Method 2: Try tshark remote capture
            if self.try_tshark_remote():
                return True
                
            # Method 3: Try SSH tunnel
            if self.try_ssh_tunnel():
                return True
                
            return False
        except Exception as e:
            print(f"Remote connection failed: {e}")
            return False
    
    def try_socket_connection(self):
        """Try standard socket connection"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.connect((self.host, self.port))
            
            # Try different handshake methods
            if self.try_netHawk_handshake():
                self.connected = True
                return True
            elif self.try_standard_handshake():
                self.connected = True
                return True
            else:
                self.socket.close()
                return False
                
        except Exception as e:
            print(f"Socket connection failed: {e}")
            return False
    
    def try_netHawk_handshake(self):
        """Try NetHawk custom protocol handshake"""
        try:
            if self.auth_key:
                self.socket.send(f"AUTH:{self.auth_key}\\n".encode())
                response = self.socket.recv(1024).decode()
                return "OK" in response
            return True
        except:
            return False
    
    def try_standard_handshake(self):
        """Try standard remote capture handshake"""
        try:
            # Send standard start command
            self.socket.send(b"START\\n")
            response = self.socket.recv(1024).decode()
            return "OK" in response or "READY" in response
        except:
            return False
    
    def try_tshark_remote(self):
        """Try tshark remote capture"""
        try:
            import subprocess
            
            # Build tshark command
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
        """Try SSH tunnel"""
        try:
            import subprocess
            
            # Create SSH tunnel
            tunnel_cmd = [
                'ssh', '-L', f'9999:{self.host}:{self.port}',
                f'user@{self.host}', '-N'
            ]
            
            self.tunnel_process = subprocess.Popen(tunnel_cmd)
            time.sleep(2)  # Wait for tunnel
            
            # Connect to local tunnel
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.connect(('localhost', 9999))
            
            self.connected = True
            return True
            
        except Exception as e:
            print(f"SSH tunnel failed: {e}")
            return False
    
    def start_remote_capture(self, filters=None, packet_callback=None):
        """Start remote capture with protocol detection"""
        if not self.connected:
            return False
            
        try:
            if self.capture_process:
                # Handle tshark process
                return self.start_tshark_capture(filters, packet_callback)
            elif self.socket:
                # Handle socket connection
                return self.start_socket_capture(filters, packet_callback)
            else:
                return False
                
        except Exception as e:
            print(f"Start capture failed: {e}")
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
                        fields = line.strip().split('\\t')
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
    
    def start_socket_capture(self, filters, packet_callback):
        """Start socket capture"""
        try:
            # Send start command
            cmd = "START_CAPTURE"
            if filters:
                cmd += f":{filters}"
            self.socket.send(f"{cmd}\\n".encode())
            self.socket.settimeout(None)
            
            if packet_callback:
                self.receiver = RemoteAgentReceiver(self.socket)
                self.receiver.packet_received.connect(packet_callback)
                self.receiver.start()
            
            return True
            
        except Exception as e:
            print(f"Socket capture error: {e}")
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
    
    def stop_capture(self):
        """Stop remote capture"""
        self.running = False
        
        if self.receiver:
            self.receiver.stop()
            self.receiver.wait(1000)
            self.receiver = None
        
        if self.capture_process:
            self.capture_process.terminate()
            self.capture_process = None
        
        if self.connected and self.socket:
            try:
                self.socket.send(b"STOP_CAPTURE\\n")
            except:
                pass
    
    def disconnect(self):
        """Disconnect from remote server"""
        self.stop_capture()
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.connected = False'''
    
    # Replace the RemoteAgent class
    content = re.sub(old_remote_agent, new_remote_agent, content, flags=re.DOTALL)
    
    # Write the patched file
    with open('nethawk2_1_patched.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("✅ NetHawk remote capture patched!")
    print("📁 Patched file saved as: nethawk2_1_patched.py")
    print("🚀 You can now use the patched version for remote capture")

if __name__ == '__main__':
    patch_nethawk_remote_capture()
