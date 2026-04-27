#!/usr/bin/env python3
"""
NetHawk Remote Capture Service
A lightweight service that runs on remote machines to capture packets
and send them to the main NetHawk application via RPCAP protocol.
"""

import socket
import struct
import sys
import os
import time
import signal
import logging
import re
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

# Try to import pcap libraries
try:
    import pcap
    PCAP_AVAILABLE = True
except ImportError:
    PCAP_AVAILABLE = False
    try:
        from scapy.all import get_if_list, sniff
        SCAPY_AVAILABLE = True
    except ImportError:
        SCAPY_AVAILABLE = False

# RPCAP Protocol Constants
RPCAP_VERSION = 0
RPCAP_MSG_FINDALLIF_REQ = 1
RPCAP_MSG_FINDALLIF_REPLY = 129
RPCAP_MSG_OPEN_REQ = 2
RPCAP_MSG_OPEN_REPLY = 130
RPCAP_MSG_STARTCAP_REQ = 3
RPCAP_MSG_STARTCAP_REPLY = 131
RPCAP_MSG_ENDCAP_REQ = 4
RPCAP_MSG_PACKET = 6
RPCAP_MSG_AUTH_REQ = 7
RPCAP_MSG_AUTH_REPLY = 128 + 7
RPCAP_MSG_ERROR = 8

# Configuration
DEFAULT_PORT = 2002
LOG_DIR = os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'NetHawk')
# Daily log file with date suffix: nethawk_service_YYYYMMDD.log
LOG_FILE_BASE = os.path.join(LOG_DIR, 'nethawk_service')
current_date = datetime.now().strftime('%Y%m%d')
LOG_FILE = f"{LOG_FILE_BASE}_{current_date}.log"

# Setup logging with daily rotation
def setup_logging():
    """Setup logging with daily file rotation"""
    logger = logging.getLogger('NetHawkService')
    logger.setLevel(logging.DEBUG)  # Capture all levels
    
    # Remove any existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Create log directory if it doesn't exist
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except (PermissionError, OSError) as e:
        print(f"Warning: Could not create log directory {LOG_DIR}: {e}")
        print("Logging to console only. Run as Administrator to enable file logging.")
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)-8s] [%(filename)s:%(lineno)d] %(funcName)s() - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler with daily rotation (like main app)
    try:
        # Custom namer to format rotated files as: nethawk_service_YYYYMMDD.log
        def namer(name):
            """Custom namer to create log files with format: nethawk_service_YYYYMMDD.log"""
            if name.endswith('.log'):
                base_part = name[:-4]  # Everything before .log
                if '.' in base_part:
                    base, date = base_part.split('.', 1)
                    return f"{base}_{date}.log"
            else:
                if '.' in name:
                    base, date = name.split('.', 1)
                    return f"{base}_{date}.log"
                else:
                    return f"{name}.log"
            return name
        
        file_handler = TimedRotatingFileHandler(
            filename=LOG_FILE_BASE,  # Base name: nethawk_service (without extension)
            when='midnight',
            interval=1,
            backupCount=30,  # Keep 30 days of logs
            encoding='utf-8',
            delay=False  # Don't delay file creation - create immediately
        )
        file_handler.namer = namer
        file_handler.suffix = '%Y%m%d'
        # Set baseFilename to include .log extension for current file
        file_handler.baseFilename = LOG_FILE
        file_handler.setLevel(logging.DEBUG)  # Log all levels to file
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Force immediate file creation and verify it works
        logger.debug("Service logging system initialized")
        file_handler.flush()
        if os.path.exists(LOG_FILE):
            logger.info(f"Service log file created successfully: {LOG_FILE}")
        else:
            logger.warning(f"Service log file path may not be writable: {LOG_FILE}")
    except (PermissionError, OSError) as e:
        # Can't write to log file (permissions issue), continue with console only
        print(f"Warning: Could not create service log file {LOG_FILE}: {e}")
        print("Logging to console only. Run as Administrator to enable file logging.")
    
    # Console handler for immediate feedback
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)  # INFO and above to console
    console_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    return logger

LOGGER = setup_logging()

class RPCAPServer:
    """RPCAP protocol server for remote packet capture"""
    
    def __init__(self, host='0.0.0.0', port=DEFAULT_PORT, interface=None, password=None):
        self.host = host
        self.port = port
        self.interface = interface or 'any'
        self.password = password
        self.socket = None
        self.capturing = False
        self.capture_thread = None
        self.running = False
        self.authenticated = False
        self.capture_conn = None  # Connection reference for capture thread
        
    def check_port_available(self, host, port):
        """Check if a port is available for binding"""
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test_socket.bind((host, port))
            test_socket.close()
            return (True, None)
        except OSError as e:
            if hasattr(e, 'winerror'):
                if e.winerror == 10013:  # Windows: Access denied
                    return (False, "Port requires administrator privileges or is blocked by firewall")
                elif e.winerror == 10048:  # Windows: Address already in use
                    return (False, f"Port {port} is already in use by another process")
                else:
                    return (False, f"Port check failed (winerror {e.winerror}): {e}")
            else:
                return (False, f"Port check failed: {e}")
        except Exception as e:
            return (False, f"Port check error: {e}")
    
    def find_available_port(self, start_port, max_attempts=10):
        """Find an available port starting from start_port"""
        for i in range(max_attempts):
            port = start_port + i
            available, error = self.check_port_available(self.host, port)
            if available:
                return port
        return None
    
    def start(self):
        """Start the RPCAP server"""
        try:
            # Check if port is available first
            LOGGER.info(f"Checking if port {self.port} is available on {self.host}...")
            available, error_msg = self.check_port_available(self.host, self.port)
            
            if not available:
                # Port not available - try to find alternative
                LOGGER.warning(f"Port {self.port} is not available: {error_msg}")
                LOGGER.info(f"Attempting to find alternative port...")
                alt_port = self.find_available_port(self.port + 1, 10)
                if alt_port:
                    LOGGER.warning(f"Port {self.port} unavailable, using alternative port {alt_port}")
                    self.port = alt_port
                else:
                    error_msg_full = f"Cannot bind to port {self.port}: {error_msg}"
                    LOGGER.error(error_msg_full)
                    LOGGER.error("")
                    LOGGER.error("Possible solutions:")
                    LOGGER.error("  1. Run as Administrator (required for some ports)")
                    LOGGER.error("  2. Check if another service is using the port:")
                    LOGGER.error(f"     netstat -ano | findstr :{self.port}")
                    LOGGER.error("  3. Configure Windows Firewall to allow the port:")
                    LOGGER.error(f"     netsh advfirewall firewall add rule name=\"NetHawk RPCAP\" dir=in action=allow protocol=TCP localport={self.port}")
                    LOGGER.error("  4. Use a different port: --port <port_number>")
                    raise OSError(error_msg_full)
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Try to bind with better error handling
            try:
                self.socket.bind((self.host, self.port))
            except OSError as e:
                if e.winerror == 10013:
                    error_msg = f"Permission denied binding to {self.host}:{self.port}"
                    LOGGER.error(error_msg)
                    LOGGER.error("This usually means:")
                    LOGGER.error("  1. Port requires Administrator privileges - run as Administrator")
                    LOGGER.error("  2. Windows Firewall is blocking the port")
                    LOGGER.error("  3. Another process is using the port")
                    LOGGER.error("")
                    LOGGER.error("To check what's using the port:")
                    LOGGER.error(f"  netstat -ano | findstr :{self.port}")
                    LOGGER.error("")
                    LOGGER.error("To allow through firewall:")
                    LOGGER.error(f"  netsh advfirewall firewall add rule name=\"NetHawk RPCAP\" dir=in action=allow protocol=TCP localport={self.port}")
                    raise
                elif e.winerror == 10048:
                    error_msg = f"Port {self.port} is already in use"
                    LOGGER.error(error_msg)
                    LOGGER.error(f"Check what's using the port: netstat -ano | findstr :{self.port}")
                    raise
                else:
                    raise
            
            self.socket.listen(5)
            self.running = True
            LOGGER.info(f"NetHawk Service started on {self.host}:{self.port}")
            return True
        except Exception as e:
            LOGGER.error(f"Failed to start server: {e}")
            return False
    
    def send_message(self, conn, msg_type, value=0, payload=b''):
        """Send RPCAP protocol message"""
        header = struct.pack('!BBHI', RPCAP_VERSION, msg_type, value, len(payload))
        conn.sendall(header + payload)
    
    def recv_message(self, conn):
        """Receive RPCAP protocol message"""
        try:
            # Ensure socket has a timeout set to prevent indefinite blocking
            if conn.gettimeout() is None:
                conn.settimeout(30.0)  # 30 second timeout
            
            # Wrap recv in try-except to catch connection errors immediately
            try:
                header = conn.recv(8)
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as conn_err:
                # Connection closed during recv - log at debug level
                error_type = type(conn_err).__name__
                if hasattr(conn_err, 'winerror'):
                    winerror = conn_err.winerror
                    LOGGER.debug(f"Connection closed during recv: {error_type} (Windows error {winerror}) - this is normal")
                else:
                    LOGGER.debug(f"Connection closed during recv: {error_type} - this is normal")
                return None, None, None, None
            if len(header) < 8:
                if len(header) == 0:
                    LOGGER.debug("Connection closed by client (EOF)")
                else:
                    LOGGER.debug(f"Incomplete header received: {len(header)}/8 bytes (connection may be closing)")
                return None, None, None, None
            ver, msg_type, value, plen = struct.unpack('!BBHI', header)
            
            payload = b''
            if plen > 0:
                # Read full payload - may need multiple recv calls
                while len(payload) < plen:
                    try:
                        chunk = conn.recv(plen - len(payload))
                        if not chunk:
                            LOGGER.debug(f"Incomplete payload received: {len(payload)}/{plen} bytes (connection closed)")
                            break
                        payload += chunk
                    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
                        # Connection closed while reading payload
                        LOGGER.debug(f"Connection closed while reading payload: {type(e).__name__}")
                        return None, None, None, None
            return ver, msg_type, value, payload
        except socket.timeout:
            LOGGER.debug("Timeout receiving message (this may be normal)")
            return None, None, None, None
        except OSError as e:
            # Handle OS-level connection errors FIRST (ConnectionResetError, ConnectionAbortedError are OSError subclasses on Windows)
            # Check exception type for connection errors FIRST (works on all platforms)
            if isinstance(e, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
                error_type = type(e).__name__
                # Also check for Windows error codes if available
                if hasattr(e, 'winerror'):
                    winerror = e.winerror
                    LOGGER.debug(f"Connection closed: {error_type} (Windows error {winerror}) - this is normal during handshake")
                else:
                    LOGGER.debug(f"Connection closed: {error_type} - this is normal during handshake")
                return None, None, None, None
            # Check for Windows error codes for other OSErrors
            elif hasattr(e, 'winerror'):
                winerror = e.winerror
                # Windows-specific error codes for connection issues
                if winerror in (10053, 10054, 10058):  # Connection aborted, reset, or already closed
                    LOGGER.debug(f"Connection closed: Windows error {winerror} (this is normal during handshake)")
                    return None, None, None, None
                else:
                    LOGGER.debug(f"OS error: Windows error {winerror}")
            else:
                LOGGER.debug(f"OS error: {e}")
            return None, None, None, None
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            # Catch connection errors explicitly (for non-Windows or if not caught as OSError)
            error_type = type(e).__name__
            LOGGER.debug(f"Connection closed by client: {error_type} (this is normal during handshake)")
            return None, None, None, None
        except Exception as e:
            # Only log unexpected errors at ERROR level
            LOGGER.error(f"Unexpected error receiving message: {e}", exc_info=True)
            return None, None, None, None
    
    def handle_findallif(self, conn):
        """Handle FINDALLIF request - list available interfaces (RPCAP format)"""
        try:
            if PCAP_AVAILABLE:
                interfaces = pcap.findalldevs()
            elif SCAPY_AVAILABLE:
                try:
                    # Suppress warnings about pcap/npcap
                    import warnings
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore")
                        interfaces = get_if_list()
                except Exception as e:
                    LOGGER.warning(f"Could not list interfaces with Scapy: {e}")
                    LOGGER.warning("This is normal if Npcap/WinPcap is not installed")
                    interfaces = ['any']  # Fallback
            else:
                interfaces = ['any']
            
            LOGGER.info(f"Listing {len(interfaces)} interfaces: {interfaces}")
            
            # Build interface list in RPCAP format:
            # - Number of interfaces (4 bytes, big-endian)
            # - For each interface:
            #   - Name length (4 bytes)
            #   - Name (variable length)
            #   - Description length (4 bytes)
            #   - Description (variable length)
            #   - Flags (4 bytes)
            #   - Address count (4 bytes)
            #   - (Addresses omitted for simplicity)
            
            iface_data = struct.pack('!I', len(interfaces))  # Number of interfaces
            
            for iface in interfaces:
                # Interface name
                iface_name_bytes = iface.encode('utf-8')
                iface_data += struct.pack('!I', len(iface_name_bytes))  # Name length
                iface_data += iface_name_bytes  # Name
                
                # Interface description (same as name for simplicity)
                desc_bytes = iface.encode('utf-8')
                iface_data += struct.pack('!I', len(desc_bytes))  # Description length
                iface_data += desc_bytes  # Description
                
                # Flags (4 bytes) - 0 means no flags
                iface_data += struct.pack('!I', 0)
                
                # Address count (4 bytes) - 0 means no addresses
                # The client reads address count and skips addresses if count is 0
                iface_data += struct.pack('!I', 0)
            
            self.send_message(conn, RPCAP_MSG_FINDALLIF_REPLY, 0, iface_data)
            LOGGER.info(f"Sent FINDALLIF_REPLY with {len(interfaces)} interfaces")
        except Exception as e:
            LOGGER.error(f"Error listing interfaces: {e}", exc_info=True)
            self.send_message(conn, RPCAP_MSG_ERROR, 1, str(e).encode('utf-8'))
    
    def handle_open(self, conn, payload):
        """Handle OPEN request - open interface for capture"""
        try:
            iface_name = payload.rstrip(b'\x00').decode('utf-8', errors='ignore')
            if not iface_name or iface_name == 'any':
                iface_name = self.interface
            
            self.interface = iface_name
            self.send_message(conn, RPCAP_MSG_OPEN_REPLY, 0, b'')
            LOGGER.info(f"Opened interface: {iface_name}")
            return True
        except Exception as e:
            LOGGER.error(f"Error opening interface: {e}")
            self.send_message(conn, RPCAP_MSG_OPEN_REPLY, 1, str(e).encode('utf-8'))
            return False
    
    def handle_startcap(self, conn, payload):
        """Handle STARTCAP request - start packet capture"""
        try:
            if len(payload) >= 16:
                snaplen, read_timeout, flags, packet_count = struct.unpack('!IIII', payload[:16])
            else:
                snaplen = 65535
                read_timeout = 1000
                flags = 0
                packet_count = 0
            
            LOGGER.info(f"Received STARTCAP request: interface={self.interface}, snaplen={snaplen}, timeout={read_timeout}ms")
            
            # Stop any existing capture first
            if self.capturing:
                LOGGER.warning("Capture already active, stopping previous capture...")
                self.capturing = False
                if self.capture_thread and self.capture_thread.is_alive():
                    # Wait a bit for thread to stop
                    import time
                    time.sleep(1.0)  # Increased wait time for Scapy to stop
                    if self.capture_thread.is_alive():
                        LOGGER.warning("Previous capture thread still running, forcing stop...")
                        # Scapy sniff should stop when self.capturing is False
                        # The stop_filter will handle it
            
            self.capturing = True
            # Send success reply with buffer size
            buffer_size = struct.pack('!I', 1024 * 1024)  # 1MB buffer
            self.send_message(conn, RPCAP_MSG_STARTCAP_REPLY, 0, buffer_size)
            LOGGER.info(f"Sent STARTCAP_REPLY (success), starting capture thread on {self.interface}")
            
            # Start capture in a separate thread
            import threading
            self.capture_thread = threading.Thread(
                target=self.capture_loop,
                args=(conn, snaplen),
                daemon=True
            )
            self.capture_thread.start()
            LOGGER.info(f"Capture thread started (thread_id={self.capture_thread.ident})")
            return True
        except Exception as e:
            LOGGER.error(f"Error starting capture: {e}", exc_info=True)
            self.send_message(conn, RPCAP_MSG_STARTCAP_REPLY, 1, str(e).encode('utf-8'))
            return False
    
    def capture_loop(self, conn, snaplen):
        """Main capture loop - sends packets to client"""
        packet_num = 0
        packet_counter = [0]  # For Scapy nested function
        
        LOGGER.info(f"Capture loop started: interface={self.interface}, snaplen={snaplen}, capturing={self.capturing}, running={self.running}")
        
        # Store connection reference for checking
        self.capture_conn = conn
        
        try:
            if PCAP_AVAILABLE:
                try:
                    pc = pcap.pcap(name=self.interface, snaplen=snaplen, promisc=True)
                    pc.setnonblock()
                    
                    while self.capturing and self.running:
                        try:
                            # Check if connection is still valid
                            try:
                                conn.getpeername()
                            except (OSError, socket.error):
                                LOGGER.debug("Connection closed during capture")
                                self.capturing = False
                                break
                            
                            timestamp, packet = pc.next()
                            if packet:
                                if not self.send_packet(conn, timestamp, packet, packet_num):
                                    # send_packet returned False - connection closed
                                    break
                                packet_num += 1
                                if packet_num == 1:
                                    LOGGER.info(f"First packet captured and sent (packet_num={packet_num})")
                                elif packet_num % 100 == 0:
                                    LOGGER.debug(f"Captured {packet_num} packets so far")
                            else:
                                time.sleep(0.01)
                        except Exception as e:
                            if self.capturing:
                                LOGGER.debug(f"Capture error: {e}")
                            break
                    LOGGER.info(f"Pcap capture loop ended: captured {packet_num} packets total")
                except Exception as e:
                    LOGGER.error(f"Failed to open pcap interface {self.interface}: {e}")
                    self.send_message(conn, RPCAP_MSG_ERROR, 1, f"Failed to open interface: {e}".encode('utf-8'))
            elif SCAPY_AVAILABLE:
                # Use a list to hold packet_num so it can be modified in nested function
                packet_counter = [0]
                
                def packet_handler(pkt):
                    if self.capturing:
                        try:
                            # Check if connection is still valid
                            try:
                                conn.getpeername()
                            except (OSError, socket.error):
                                LOGGER.debug("Connection closed during Scapy capture")
                                self.capturing = False
                                return
                            
                            timestamp = time.time()
                            packet_data = bytes(pkt)
                            if not self.send_packet(conn, timestamp, packet_data, packet_counter[0]):
                                # send_packet returned False - connection closed
                                self.capturing = False
                                return
                            packet_counter[0] += 1
                            if packet_counter[0] == 1:
                                LOGGER.info(f"First packet captured and sent via Scapy (packet_num={packet_counter[0]})")
                            elif packet_counter[0] % 100 == 0:
                                LOGGER.debug(f"Captured {packet_counter[0]} packets via Scapy so far")
                        except Exception as e:
                            LOGGER.debug(f"Packet send error: {e}")
                            self.capturing = False
                
                try:
                    # Suppress Scapy's pcap warning if Npcap not installed
                    # Scapy will still work but may show warnings
                    import warnings
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        warnings.filterwarnings("ignore", message=".*pcap.*")
                        warnings.filterwarnings("ignore", message=".*npcap.*")
                        warnings.filterwarnings("ignore", message=".*wincap.*")
                        
                        # Convert Windows device path to Scapy-compatible interface name
                        scapy_interface = None
                        if self.interface and self.interface != 'any':
                            # Handle loopback interface specially
                            is_loopback = 'loopback' in self.interface.lower() or self.interface.lower().endswith('loopback')
                            
                            # Try to find matching interface in Scapy's interface list
                            try:
                                scapy_interfaces = get_if_list()
                                LOGGER.info(f"Scapy available interfaces ({len(scapy_interfaces)}): {scapy_interfaces}")
                                
                                # Special handling for loopback
                                if is_loopback:
                                    # Look for loopback in Scapy's list (might be named differently)
                                    loopback_names = ['loopback', 'lo', 'lo0', '127.0.0.1', 'localhost']
                                    for iface in scapy_interfaces:
                                        iface_lower = iface.lower()
                                        if any(loopback_name in iface_lower for loopback_name in loopback_names):
                                            scapy_interface = iface
                                            LOGGER.info(f"Matched loopback interface: {self.interface} -> {scapy_interface}")
                                            break
                                    
                                    # If no loopback found, try using None (Scapy might handle it)
                                    if not scapy_interface:
                                        LOGGER.info("Loopback interface requested but not found in Scapy list, using None (Scapy default)")
                                        scapy_interface = None  # Scapy will use default/any interface
                                else:
                                    # Check if interface name matches directly
                                    if self.interface in scapy_interfaces:
                                        scapy_interface = self.interface
                                        LOGGER.info(f"Using interface directly: {scapy_interface}")
                                    else:
                                        # Try to match by GUID (extract GUID from device path)
                                        guid_match = re.search(r'\{([A-F0-9\-]+)\}', self.interface, re.IGNORECASE)
                                        if guid_match:
                                            guid = guid_match.group(1)
                                            # Look for interface containing this GUID
                                            for iface in scapy_interfaces:
                                                if guid.lower() in iface.lower() or self.interface.lower() in iface.lower():
                                                    scapy_interface = iface
                                                    LOGGER.info(f"Matched interface: {self.interface} -> {scapy_interface}")
                                                    break
                                        
                                        if not scapy_interface:
                                            # Use first available interface or the device path as fallback
                                            if scapy_interfaces:
                                                scapy_interface = scapy_interfaces[0]
                                                LOGGER.warning(f"Interface '{self.interface}' not found in Scapy list, using first available: {scapy_interface}")
                                            else:
                                                scapy_interface = self.interface
                                                LOGGER.warning(f"No Scapy interfaces found, using device path: {scapy_interface}")
                            except Exception as e:
                                LOGGER.warning(f"Error finding Scapy interface: {e}, using device path directly")
                                scapy_interface = self.interface
                        
                        LOGGER.info(f"Starting Scapy sniff on interface '{scapy_interface}' (original: '{self.interface}', capturing={self.capturing})")
                        
                        # Add timeout to detect if sniff is stuck
                        import threading
                        sniff_timeout = [False]
                        
                        def timeout_check():
                            time.sleep(5)  # Wait 5 seconds
                            if packet_counter[0] == 0 and self.capturing:
                                LOGGER.warning("No packets captured after 5 seconds - interface may be inactive or incorrect")
                                LOGGER.warning(f"Current interface: {scapy_interface}")
                                LOGGER.warning("Check if interface has network traffic or try a different interface")
                                # Check if connection is still alive
                                try:
                                    conn.getpeername()
                                    LOGGER.info("Connection still active, continuing capture...")
                                except (OSError, socket.error):
                                    LOGGER.warning("Connection closed - stopping capture")
                                    self.capturing = False
                        
                        timeout_thread = threading.Thread(target=timeout_check, daemon=True)
                        timeout_thread.start()
                        
                        sniff(iface=scapy_interface, 
                              prn=packet_handler, 
                              stop_filter=lambda x: not self.capturing,
                              store=False,
                              quiet=True)  # Suppress Scapy output
                        LOGGER.info(f"Scapy sniff ended: captured {packet_counter[0]} packets total")
                except OSError as e:
                    # Handle Npcap/WinPcap errors gracefully
                    error_msg = str(e)
                    if 'pcap' in error_msg.lower() or 'npcap' in error_msg.lower() or 'wincap' in error_msg.lower():
                        LOGGER.warning(f"Packet capture library issue: {e}")
                        LOGGER.warning("Npcap/WinPcap may not be installed or accessible")
                        LOGGER.warning("The service can still receive packets from remote clients")
                        LOGGER.warning("For local packet capture, install Npcap from: https://nmap.org/npcap/")
                        # Don't send error - service can still function for remote connections
                        return
                    else:
                        LOGGER.error(f"Failed to start Scapy capture on {self.interface}: {e}")
                        self.send_message(conn, RPCAP_MSG_ERROR, 1, f"Failed to start capture: {e}".encode('utf-8'))
                except Exception as e:
                    LOGGER.error(f"Failed to start Scapy capture on {self.interface}: {e}")
                    self.send_message(conn, RPCAP_MSG_ERROR, 1, f"Failed to start capture: {e}".encode('utf-8'))
            else:
                LOGGER.error("No pcap library available")
                self.send_message(conn, RPCAP_MSG_ERROR, 1, b"No capture library available")
        except Exception as e:
            LOGGER.error(f"Capture loop error: {e}")
        finally:
            # Clean up connection reference
            self.capture_conn = None
            
            # Get final packet count
            if PCAP_AVAILABLE:
                final_count = packet_num
            elif SCAPY_AVAILABLE:
                final_count = packet_counter[0]
            else:
                final_count = 0
            LOGGER.info(f"Capture loop ended (captured {final_count} packets)")
    
    def send_packet(self, conn, timestamp, packet_data, packet_num):
        """Send a captured packet to client"""
        try:
            # Check if connection is still valid before sending
            # This helps detect closed connections early
            try:
                # Use getpeername() to check if socket is still connected
                conn.getpeername()
            except (OSError, socket.error):
                # Connection is closed
                LOGGER.debug("Connection closed, stopping packet capture")
                self.capturing = False
                return False
            
            ts_sec = int(timestamp)
            ts_usec = int((timestamp - ts_sec) * 1000000)
            caplen = len(packet_data)
            orig_len = caplen
            
            # Packet header (20 bytes)
            pkt_header = struct.pack('!IIIII', ts_sec, ts_usec, caplen, orig_len, packet_num)
            
            # RPCAP message header + packet header + packet data
            msg_header = struct.pack('!BBHI', RPCAP_VERSION, RPCAP_MSG_PACKET, 0, 20 + caplen)
            conn.sendall(msg_header + pkt_header + packet_data)
            
            # Log first few packets for debugging
            if packet_num < 3:
                LOGGER.debug(f"Sent packet {packet_num}: {caplen} bytes to client")
            return True
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
            # Connection closed - stop capturing
            LOGGER.debug(f"Connection closed while sending packet {packet_num}: {e}")
            self.capturing = False
            return False
        except Exception as e:
            # Other errors - log but don't stop immediately
            if packet_num < 5:  # Log first few errors
                LOGGER.warning(f"Error sending packet {packet_num}: {e}")
            return False
    
    def handle_endcap(self, conn):
        """Handle ENDCAP request - stop packet capture"""
        self.capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        self.send_message(conn, RPCAP_MSG_ENDCAP_REPLY, 0, b'')
        LOGGER.info("Capture stopped")
    
    def handle_auth(self, conn, payload):
        """Handle authentication request"""
        try:
            if not self.password:
                # No password required
                self.authenticated = True
                self.send_message(conn, RPCAP_MSG_AUTH_REPLY, 0, b'')
                LOGGER.info("Authentication skipped (no password configured)")
                return True
            
            client_password = payload.rstrip(b'\x00').decode('utf-8', errors='ignore')
            if client_password == self.password:
                self.authenticated = True
                self.send_message(conn, RPCAP_MSG_AUTH_REPLY, 0, b'')
                LOGGER.info("Client authenticated successfully")
                return True
            else:
                self.send_message(conn, RPCAP_MSG_AUTH_REPLY, 1, b'Authentication failed')
                LOGGER.warning("Authentication failed - incorrect password")
                return False
        except Exception as e:
            LOGGER.error(f"Authentication error: {e}")
            self.send_message(conn, RPCAP_MSG_AUTH_REPLY, 1, str(e).encode('utf-8'))
            return False
    
    def handle_client(self, conn, addr):
        """Handle a client connection"""
        LOGGER.info(f"Client connected: {addr}")
        self.authenticated = False if self.password else True  # Auto-authenticated if no password
        
        try:
            # Set socket options for better connection handling
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Set keepalive parameters (Windows-specific)
            try:
                # TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT (may not be available on Windows)
                import platform
                if platform.system() != 'Windows':
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            except (AttributeError, OSError):
                # Keepalive options not available on this platform
                pass
            
            # Set initial timeout
            conn.settimeout(30.0)
            
            # Send server version (4 bytes: version + 3 reserved)
            try:
                conn.sendall(struct.pack('!I', RPCAP_VERSION))
            except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                LOGGER.debug(f"Connection closed before version sent: {e}")
                return
            
            # If password is required, wait for authentication before allowing any operations
            if self.password:
                LOGGER.info("Password required - waiting for authentication")
                auth_received = False
                auth_timeout = time.time() + 30  # 30 second timeout for authentication
                
                while not self.authenticated and time.time() < auth_timeout:
                    try:
                        conn.settimeout(5)  # 5 second timeout per recv
                        ver, msg_type, value, payload = self.recv_message(conn)
                        if msg_type is None:
                            LOGGER.warning("Connection closed before authentication")
                            break
                        
                        if msg_type == RPCAP_MSG_AUTH_REQ:
                            if self.handle_auth(conn, payload):
                                LOGGER.info("Authentication successful")
                                auth_received = True
                                break
                            else:
                                LOGGER.warning("Authentication failed - closing connection")
                                self.send_message(conn, RPCAP_MSG_ERROR, 1, b"Authentication failed")
                                return
                        else:
                            # Reject any non-auth messages before authentication
                            LOGGER.warning(f"Rejecting non-auth message (type={msg_type}) before authentication")
                            self.send_message(conn, RPCAP_MSG_ERROR, 1, b"Authentication required first")
                    except socket.timeout:
                        continue
                    except Exception as e:
                        LOGGER.error(f"Error during authentication: {e}")
                        break
                
                if not self.authenticated:
                    LOGGER.error("Authentication timeout or failed - closing connection")
                    self.send_message(conn, RPCAP_MSG_ERROR, 1, b"Authentication required")
                    return
            
            # Now handle normal operations (authentication complete or not required)
            LOGGER.info("Waiting for RPCAP commands from client...")
            # Timeout is set in recv_message, but we'll keep it here too
            conn.settimeout(30.0)  # 30 second timeout for waiting for commands
            while self.running:
                try:
                    ver, msg_type, value, payload = self.recv_message(conn)
                    if msg_type is None:
                        # Check if this is a timeout (normal) or actual connection close
                        try:
                            # Try to check if socket is still connected
                            conn.getpeername()
                            # Socket still connected, just timeout - continue waiting
                            continue
                        except (OSError, socket.error):
                            # Socket is closed
                            LOGGER.debug("Client connection closed (normal disconnect)")
                            break
                    
                    LOGGER.info(f"Received RPCAP message: type={msg_type}, value={value}, payload_len={len(payload) if payload else 0}")
                    
                    # Handle authentication if it comes later (shouldn't happen, but handle gracefully)
                    if msg_type == RPCAP_MSG_AUTH_REQ:
                        LOGGER.info("Received AUTH_REQ message")
                        if not self.handle_auth(conn, payload):
                            break  # Authentication failed, close connection
                        continue
                    
                    # Require authentication for other operations if password is set
                    if self.password and not self.authenticated:
                        LOGGER.warning("Unauthenticated request rejected")
                        self.send_message(conn, RPCAP_MSG_ERROR, 1, b"Authentication required")
                        break
                    
                    if msg_type == RPCAP_MSG_FINDALLIF_REQ:
                        LOGGER.info("Received FINDALLIF_REQ - listing interfaces")
                        self.handle_findallif(conn)
                        LOGGER.info("FINDALLIF_REPLY sent, waiting for next command...")
                    elif msg_type == RPCAP_MSG_OPEN_REQ:
                        LOGGER.info(f"Received OPEN_REQ - opening interface: {payload.decode('utf-8', errors='ignore').rstrip('\x00') if payload else 'unknown'}")
                        self.handle_open(conn, payload)
                        LOGGER.info("OPEN_REPLY sent, waiting for next command...")
                    elif msg_type == RPCAP_MSG_STARTCAP_REQ:
                        LOGGER.info("Received STARTCAP_REQ - starting capture")
                        self.handle_startcap(conn, payload)
                        LOGGER.info("STARTCAP_REPLY sent, capture should be starting...")
                    elif msg_type == RPCAP_MSG_ENDCAP_REQ:
                        LOGGER.info("Received ENDCAP_REQ - stopping capture")
                        self.handle_endcap(conn)
                        break
                    else:
                        LOGGER.warning(f"Unknown message type: {msg_type}")
                        self.send_message(conn, RPCAP_MSG_ERROR, 1, b"Unknown message type")
                except socket.timeout:
                    LOGGER.debug("Timeout waiting for RPCAP command (this is normal)")
                    # Check if connection is still alive
                    try:
                        conn.getpeername()
                        continue
                    except (OSError, socket.error):
                        LOGGER.debug("Connection closed during timeout check")
                        break
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
                    LOGGER.debug(f"Connection closed by client: {type(e).__name__} (normal disconnect)")
                    break
                except Exception as e:
                    # Only log unexpected errors
                    LOGGER.error(f"Unexpected error receiving RPCAP message: {e}", exc_info=True)
                    break
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            # Expected connection closure - log at debug level
            LOGGER.debug(f"Client connection closed: {type(e).__name__} (normal)")
        except Exception as e:
            # Unexpected errors - log at error level
            LOGGER.error(f"Client connection error: {e}", exc_info=True)
        finally:
            self.capturing = False
            self.authenticated = False
            try:
                conn.close()
            except:
                pass
            LOGGER.info(f"Client disconnected: {addr}")
    
    def run(self):
        """Main server loop"""
        while self.running:
            try:
                conn, addr = self.socket.accept()
                # Handle each client in a separate thread
                import threading
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr),
                    daemon=True
                )
                client_thread.start()
            except Exception as e:
                if self.running:
                    LOGGER.error(f"Server error: {e}")
    
    def stop(self):
        """Stop the server"""
        self.running = False
        self.capturing = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        LOGGER.info("Server stopped")

def main():
    """Main entry point"""
    import argparse
    import json
    
    # Log startup immediately
    LOGGER.info("=" * 70)
    LOGGER.info("NetHawk Remote Capture Service Starting")
    LOGGER.info("Service Version: 2025-11-20 (Connection Error Handling Improved)")
    LOGGER.info(f"Log file: {LOG_FILE}")
    LOGGER.info(f"Log directory: {LOG_DIR}")
    LOGGER.info("=" * 70)
    
    # Check for service install/uninstall BEFORE argparse (win32serviceutil needs raw sys.argv)
    if '--install' in sys.argv or 'install' in sys.argv or '--uninstall' in sys.argv or '--remove' in sys.argv or 'remove' in sys.argv:
        # Try to import pywin32 modules
        try:
            import win32serviceutil
            import win32service
            import servicemanager
        except ImportError as e:
            print("Error: pywin32 required for service installation")
            print(f"Import error: {e}")
            print("\nThis executable was built without pywin32 bundled.")
            print("Please rebuild the service using build_service.bat")
            sys.exit(1)
        
        # Define service class
        class NetHawkService(win32serviceutil.ServiceFramework):
            _svc_name_ = "NetHawkCaptureService"
            _svc_display_name_ = "NetHawk Remote Capture Service"
            _svc_description_ = "Provides remote packet capture for NetHawk"
            
            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self.server = None
                self.service_args = args
            
            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                if self.server:
                    self.server.stop()
            
            def SvcDoRun(self):
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, '')
                )
                # Load config for service
                password = self.service_args.password if hasattr(self.service_args, 'password') else None
                host = self.service_args.host if hasattr(self.service_args, 'host') else '0.0.0.0'
                port = self.service_args.port if hasattr(self.service_args, 'port') else DEFAULT_PORT
                interface = self.service_args.interface if hasattr(self.service_args, 'interface') else 'any'
                
                if self.service_args.config and os.path.exists(self.service_args.config):
                    try:
                        with open(self.service_args.config, 'r') as f:
                            config = json.load(f)
                            password = config.get('password', password)
                            host = config.get('host', host)
                            port = config.get('port', port)
                            interface = config.get('interface', interface)
                    except:
                        pass
                
                self.server = RPCAPServer(host, port, interface, password)
                if self.server.start():
                    self.server.run()
        
        # Convert --install/--uninstall to install/remove for win32serviceutil
        if '--install' in sys.argv:
            sys.argv[sys.argv.index('--install')] = 'install'
        elif '--uninstall' in sys.argv:
            sys.argv[sys.argv.index('--uninstall')] = 'remove'
        elif '--remove' in sys.argv:
            sys.argv[sys.argv.index('--remove')] = 'remove'
        # If already 'install' or 'remove', leave as-is
        
        # Handle service installation/uninstallation
        try:
            win32serviceutil.HandleCommandLine(NetHawkService)
        except Exception as e:
            print(f"Service installation error: {e}")
            print("\nMake sure you are running as Administrator.")
            import traceback
            traceback.print_exc()
            sys.exit(1)
        return
    
    # Regular argument parsing for non-service operations
    parser = argparse.ArgumentParser(description='NetHawk Remote Capture Service')
    parser.add_argument('--host', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help=f'Port (default: {DEFAULT_PORT})')
    parser.add_argument('--interface', default='any', help='Default interface (default: any)')
    parser.add_argument('--password', help='Password for authentication (optional)')
    parser.add_argument('--config', help='Path to configuration file (JSON)')
    
    args = parser.parse_args()
    
    # Load configuration from file if provided
    password = args.password
    if args.config and os.path.exists(args.config):
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
                password = config.get('password', password)
                if not args.host or args.host == '0.0.0.0':
                    args.host = config.get('host', args.host)
                if args.port == DEFAULT_PORT:
                    args.port = config.get('port', args.port)
                if args.interface == 'any':
                    args.interface = config.get('interface', args.interface)
        except Exception as e:
            LOGGER.error(f"Failed to load config file: {e}")
    
    # Normal server operation (not installing/uninstalling service)
    LOGGER.info(f"Starting RPCAP server: host={args.host}, port={args.port}, interface={args.interface}")
    server = RPCAPServer(args.host, args.port, args.interface, password)
    
    def signal_handler(sig, frame):
        LOGGER.info("Shutdown signal received")
        server.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if server.start():
        LOGGER.info("RPCAP server started successfully")
        LOGGER.info("Server is ready to accept connections")
        try:
            server.run()
        except KeyboardInterrupt:
            LOGGER.info("Interrupted by user")
        finally:
            LOGGER.info("Stopping server...")
            server.stop()
            LOGGER.info("Server stopped")
    else:
        LOGGER.error("Failed to start server")
        sys.exit(1)

if __name__ == '__main__':
    main()

