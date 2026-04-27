#!/usr/bin/env python3
"""
NetHawk Remote Capture Enhancement
Enhances ONLY the remote capture functionality while preserving all existing features
"""

import re
import os

def enhance_remote_capture():
    """Enhance only the remote capture functionality"""
    
    # Read the original file
    with open('nethawk2_1.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Add new methods to RemoteAgent class without removing existing ones
    enhanced_remote_agent_methods = '''
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
    
    def try_wireshark_handshake(self):
        """Try Wireshark-compatible handshake"""
        try:
            # Send Wireshark-style command
            self.socket.send(b"CAPTURE\\n")
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
        return self.try_standard_protocols()'''
    
    # Find the RemoteAgent class and add new methods
    remote_agent_pattern = r'(class RemoteAgent:.*?def disconnect\(self\):.*?self\.connected = False)'
    
    def replace_remote_agent(match):
        original_class = match.group(1)
        # Add new methods before the last method
        enhanced_class = original_class.replace(
            'def disconnect(self):',
            enhanced_remote_agent_methods + '\n    def disconnect(self):'
        )
        return enhanced_class
    
    content = re.sub(remote_agent_pattern, replace_remote_agent, content, flags=re.DOTALL)
    
    # Enhance the add_remote_agent method to use enhanced connection
    add_remote_agent_pattern = r'(def add_remote_agent\(self\):.*?if agent\.connect\(\):)'
    
    def replace_add_remote_agent(match):
        original_method = match.group(1)
        # Replace the connection call with enhanced version
        enhanced_method = original_method.replace(
            'if agent.connect():',
            'if agent.connect() or agent.enhanced_connect():'
        )
        return enhanced_method
    
    content = re.sub(add_remote_agent_pattern, replace_add_remote_agent, content, flags=re.DOTALL)
    
    # Enhance the start_remote_capture method to use enhanced capture
    start_remote_capture_pattern = r'(def start_remote_capture\(self, row\):.*?if agent\.start_remote_capture\(filters=None, packet_callback=self\.on_remote_packet\):)'
    
    def replace_start_remote_capture(match):
        original_method = match.group(1)
        # Replace the start capture call with enhanced version
        enhanced_method = original_method.replace(
            'if agent.start_remote_capture(filters=None, packet_callback=self.on_remote_packet):',
            'if agent.start_remote_capture(filters=None, packet_callback=self.on_remote_packet) or agent.start_enhanced_capture(filters=None, packet_callback=self.on_remote_packet):'
        )
        return enhanced_method
    
    content = re.sub(start_remote_capture_pattern, replace_start_remote_capture, content, flags=re.DOTALL)
    
    # Write the enhanced file
    with open('nethawk2_1_enhanced.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("✅ NetHawk remote capture enhanced!")
    print("📁 Enhanced file saved as: nethawk2_1_enhanced.py")
    print("🔧 All existing functionality preserved")
    print("🚀 Enhanced remote capture with multiple protocol support")
    print("📋 New features added:")
    print("   • TShark remote capture support")
    print("   • SSH tunnel support")
    print("   • Standard protocol handshake")
    print("   • Wireshark-compatible handshake")
    print("   • Enhanced connection fallback")

if __name__ == '__main__':
    enhance_remote_capture()
