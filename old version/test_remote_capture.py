#!/usr/bin/env python3
"""
Test NetHawk Enhanced Remote Capture
Tests the enhanced remote capture functionality
"""

import sys
import os
import time
import threading
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_enhanced_remote_capture():
    """Test the enhanced remote capture functionality"""
    
    print("🧪 Testing NetHawk Enhanced Remote Capture")
    print("=" * 50)
    
    try:
        # Import the enhanced NetHawk
        from nethawk2_1_enhanced import RemoteAgent
        
        # Test configuration
        test_host = "192.168.1.100"  # Replace with your server IP
        test_port = 9999
        
        print(f"🌐 Testing connection to {test_host}:{test_port}")
        
        # Create remote agent
        agent = RemoteAgent(test_host, test_port)
        
        # Test enhanced connection
        print("🔍 Testing enhanced connection...")
        if agent.enhanced_connect():
            print("✅ Enhanced connection successful!")
            
            # Test enhanced capture
            print("🎯 Testing enhanced capture...")
            
            def packet_callback(packet):
                print(f"📦 Packet: {packet.get('src', 'Unknown')} -> {packet.get('dst', 'Unknown')} ({packet.get('protocol', 'Unknown')})")
            
            if agent.start_enhanced_capture(packet_callback=packet_callback):
                print("✅ Enhanced capture started!")
                
                try:
                    # Run for 10 seconds
                    print("⏱️ Running capture for 10 seconds...")
                    time.sleep(10)
                except KeyboardInterrupt:
                    print("\n🛑 Stopping capture...")
                finally:
                    agent.stop_capture()
                    print("⏹️ Capture stopped")
            else:
                print("❌ Failed to start enhanced capture")
        else:
            print("❌ Enhanced connection failed")
            
        # Cleanup
        agent.disconnect()
        print("🔌 Disconnected")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure nethawk2_1_enhanced.py exists")
    except Exception as e:
        print(f"❌ Test error: {e}")

def test_connection_methods():
    """Test different connection methods"""
    
    print("\n🔍 Testing Connection Methods")
    print("=" * 30)
    
    try:
        from nethawk2_1_enhanced import RemoteAgent
        
        # Test different hosts/ports
        test_configs = [
            ("localhost", 9999),
            ("127.0.0.1", 9999),
            ("192.168.1.100", 9999),
            ("192.168.1.100", 22),  # SSH port
        ]
        
        for host, port in test_configs:
            print(f"\n🌐 Testing {host}:{port}")
            
            agent = RemoteAgent(host, port)
            
            # Test original connection
            if agent.connect():
                print("✅ Original connection successful")
                agent.disconnect()
            else:
                print("❌ Original connection failed")
                
            # Test enhanced connection
            if agent.enhanced_connect():
                print("✅ Enhanced connection successful")
                agent.disconnect()
            else:
                print("❌ Enhanced connection failed")
                
    except Exception as e:
        print(f"❌ Connection test error: {e}")

def main():
    """Main test function"""
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "connection":
            test_connection_methods()
        else:
            print("Usage: python test_remote_capture.py [connection]")
            print("  connection - Test different connection methods")
    else:
        test_enhanced_remote_capture()

if __name__ == '__main__':
    main()
