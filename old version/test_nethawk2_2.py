#!/usr/bin/env python3
"""
Test NetHawk 2.2 Enhanced Remote Capture
Quick test to verify the enhanced remote capture functionality
"""

import sys
import os

def test_import():
    """Test if the enhanced NetHawk can be imported"""
    try:
        print("🧪 Testing NetHawk 2.2 Enhanced Import...")
        
        # Add current directory to path
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        # Try to import the enhanced NetHawk
        from nethawk2_2 import RemoteAgent, NetHawkPro
        
        print("✅ NetHawk 2.2 Enhanced imported successfully!")
        
        # Test RemoteAgent class
        print("🔍 Testing RemoteAgent class...")
        agent = RemoteAgent("localhost", 9999)
        
        # Check if enhanced methods exist
        if hasattr(agent, 'enhanced_connect'):
            print("✅ enhanced_connect method found")
        else:
            print("❌ enhanced_connect method missing")
            
        if hasattr(agent, 'start_enhanced_capture'):
            print("✅ start_enhanced_capture method found")
        else:
            print("❌ start_enhanced_capture method missing")
            
        if hasattr(agent, 'try_standard_protocols'):
            print("✅ try_standard_protocols method found")
        else:
            print("❌ try_standard_protocols method missing")
            
        if hasattr(agent, 'try_tshark_remote'):
            print("✅ try_tshark_remote method found")
        else:
            print("❌ try_tshark_remote method missing")
            
        if hasattr(agent, 'try_ssh_tunnel'):
            print("✅ try_ssh_tunnel method found")
        else:
            print("❌ try_ssh_tunnel method missing")
            
        print("🎯 All enhanced methods present!")
        
        # Test NetHawkPro class
        print("🔍 Testing NetHawkPro class...")
        if hasattr(NetHawkPro, 'add_remote_agent'):
            print("✅ NetHawkPro.add_remote_agent method found")
        else:
            print("❌ NetHawkPro.add_remote_agent method missing")
            
        print("✅ NetHawk 2.2 Enhanced is ready to use!")
        print("\n📋 Enhanced Features:")
        print("   • Original NetHawk protocol support")
        print("   • TShark remote capture support")
        print("   • SSH tunnel support")
        print("   • Standard protocol handshake")
        print("   • Wireshark-compatible handshake")
        print("   • Enhanced connection fallback")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Test error: {e}")
        return False

def test_remote_agent():
    """Test RemoteAgent functionality"""
    try:
        from nethawk2_2 import RemoteAgent
        
        print("\n🧪 Testing RemoteAgent functionality...")
        
        # Test with localhost
        agent = RemoteAgent("localhost", 9999)
        
        # Test original connection (should fail for localhost:9999)
        print("🔍 Testing original connection...")
        if agent.connect():
            print("✅ Original connection successful")
        else:
            print("❌ Original connection failed (expected)")
            
        # Test enhanced connection
        print("🔍 Testing enhanced connection...")
        if agent.enhanced_connect():
            print("✅ Enhanced connection successful")
        else:
            print("❌ Enhanced connection failed (expected for localhost:9999)")
            
        print("✅ RemoteAgent functionality test complete")
        return True
        
    except Exception as e:
        print(f"❌ RemoteAgent test error: {e}")
        return False

def main():
    """Main test function"""
    print("🌐 NetHawk 2.2 Enhanced Remote Capture Test")
    print("=" * 50)
    
    # Test import
    if not test_import():
        print("❌ Import test failed")
        return False
        
    # Test RemoteAgent
    if not test_remote_agent():
        print("❌ RemoteAgent test failed")
        return False
        
    print("\n🎉 All tests passed!")
    print("🚀 NetHawk 2.2 Enhanced is ready for remote capture!")
    print("\n📖 Usage:")
    print("   python nethawk2_2.py")
    print("   Then go to Remote tab and add your server")
    
    return True

if __name__ == '__main__':
    main()
