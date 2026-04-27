print("Testing imports...")

try:
    import sys
    print("✓ sys")
    
    import psutil
    print("✓ psutil")
    
    from PyQt5.QtWidgets import QApplication
    print("✓ PyQt5")
    
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    print("✓ scapy basic")
    
    from scapy.all import RTP
    print("✓ scapy RTP")
    
    print("\n✅ All imports successful!")
    
except ImportError as e:
    print(f"\n❌ Import failed: {e}")
    import traceback
    traceback.print_exc()