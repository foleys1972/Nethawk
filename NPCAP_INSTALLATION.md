# Npcap Installation Guide

## What is Npcap?

Npcap is a packet capture library for Windows that allows applications to capture network packets. It's required for **local packet capture** on Windows machines.

## Do You Need Npcap?

### For NetHawkService.exe (Remote Capture Service)

**You DON'T need Npcap if:**
- The service is only receiving connections from remote clients
- You're using the service as an RPCAP server (remote capture)
- The service is just forwarding packets it receives

**You DO need Npcap if:**
- You want the service to capture packets locally on the server
- You need to list network interfaces
- You want to capture from specific network interfaces

### For Nethawk.exe (Main Application)

**You DON'T need Npcap if:**
- You're only analyzing PCAP files (loading saved captures)
- You're only using remote capture (connecting to remote servers)
- You're not doing local packet capture

**You DO need Npcap if:**
- You want to capture packets locally on your machine
- You want to see available network interfaces
- You want real-time local packet capture

## Installation

### Step 1: Download Npcap

1. Go to: https://nmap.org/npcap/
2. Download the latest installer (Npcap-x.x.x.exe)
3. Or use direct link: https://npcap.com/dist/

### Step 2: Install Npcap

1. **Run the installer as Administrator**
   - Right-click the installer → "Run as administrator"

2. **Installation Options:**
   - ✅ **Install Npcap in WinPcap API-compatible Mode** (Recommended)
     - This ensures compatibility with older applications
   - ✅ **Support loopback traffic capture** (Optional but useful)
   - ✅ **Restrict Npcap driver's access to Administrators only** (Recommended for security)

3. **Complete the installation**
   - Follow the installer prompts
   - Restart if prompted

### Step 3: Verify Installation

After installation, you can verify it works:

```batch
# Check if Npcap is installed
sc query npcap

# Or check in Device Manager
# Look for "Npcap Loopback Adapter" under Network Adapters
```

## Troubleshooting

### Error: "could not start pcap service"

**Cause:** Npcap is not installed or not accessible

**Solutions:**

1. **Install Npcap** (see above)

2. **Run as Administrator:**
   - Right-click NetHawkService.exe → "Run as administrator"
   - Or install as a service (which runs with admin privileges)

3. **Check Npcap Service:**
   ```batch
   sc query npcap
   ```
   If not running, start it:
   ```batch
   net start npcap
   ```

4. **Reinstall Npcap:**
   - Uninstall from Control Panel
   - Download fresh installer
   - Install as Administrator

### Error: "Access denied" or "Permission denied"

**Cause:** Insufficient privileges

**Solutions:**

1. **Run as Administrator:**
   - Right-click the application → "Run as administrator"

2. **Install as Service:**
   - NetHawkService.exe runs with elevated privileges when installed as a service
   - Use: `install_service.bat` (run as Administrator)

3. **Check Windows Firewall:**
   - Ensure Npcap is allowed through firewall
   - Windows usually prompts during Npcap installation

### Warning: "Npcap may not be installed"

**This is OK if:**
- You're only using remote capture
- You're only analyzing PCAP files
- The service is just forwarding packets

**The service will still work** - it just can't capture packets locally.

## Alternative: Use Remote Capture Only

If you don't want to install Npcap, you can:

1. **Use Remote Capture:**
   - Install NetHawkService.exe on a remote server (with Npcap)
   - Connect from Nethawk.exe to the remote server
   - No Npcap needed on the client machine

2. **Analyze PCAP Files:**
   - Load saved PCAP files in Nethawk.exe
   - No packet capture needed

## For Remote Servers

If you're deploying NetHawkService.exe to remote servers:

1. **Install Npcap on the remote server** (where packets will be captured)
2. **Run NetHawkService.exe as Administrator** or install as a service
3. **No Npcap needed on the client machine** (Nethawk.exe)

## Summary

| Scenario | Npcap Required? |
|----------|----------------|
| Local packet capture | ✅ Yes |
| Remote capture (client) | ❌ No |
| Remote capture (server) | ✅ Yes |
| PCAP file analysis | ❌ No |
| RPCAP server only | ❌ No (but recommended) |

## Quick Check

To check if Npcap is installed and working:

```batch
# Check service status
sc query npcap

# Check if interfaces are available (in Python)
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

If you get interfaces listed, Npcap is working!

