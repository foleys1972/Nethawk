# NetHawk Installation Guide

## Overview

NetHawk supports remote packet capture from remote servers. This guide explains what software needs to be installed on each machine.

---

## Machine 1: NetHawk Client (Analysis Machine)

**This is where you run NetHawk to analyze captured packets.**

### Required Software

1. **NetHawk Application**
   - **Option A**: Use the pre-built executable
     - Copy `Nethawk.exe` (or `dist\Nethawk.exe` if you built it) to this machine
     - No additional installation needed - just run the .exe
   
   - **Option B**: Run from Python source
     - Install Python 3.8+ 
     - Install dependencies: `pip install -r requirements.txt`
     - Run: `python nethawk2_2.py`

2. **Network Access**
   - Must be able to reach the remote server over the network
   - Firewall should allow outbound connections to the remote server

### Optional Software

- **Npcap** (for local packet capture if you also want to capture locally)
  - Download from: https://nmap.org/npcap/
  - Only needed if you want to capture packets on THIS machine too

---

## Machine 2: Remote Capture Server

**This is the machine where packets will be captured from.**

### Option 1: NetHawk Service (Recommended for Windows)

**Best for**: Windows servers, easy setup, service-based

#### Required Software

1. **NetHawkService.exe**
   - Copy `dist\NetHawkService.exe` from the build machine to the remote server
   - This is a standalone executable - no Python or dependencies needed

2. **Installation Steps**
   ```batch
   # Copy NetHawkService.exe to the remote server
   # Then run as Administrator:
   
   # Install as Windows Service
   NetHawkService.exe --install
   
   # Start the service
   net start NetHawkCaptureService
   
   # Or use the automated installer
   install_service.bat  (run as Administrator)
   ```

3. **Configuration (Optional)**
   - Create `C:\ProgramData\NetHawk\service_config.json`:
   ```json
   {
       "host": "0.0.0.0",
       "port": 2002,
       "interface": "any",
       "password": "your_secure_password_here"
   }
   ```

4. **Firewall Configuration**
   - Allow inbound TCP connections on port 2002 (or your custom port)
   - Windows Firewall rule:
     ```batch
     netsh advfirewall firewall add rule name="NetHawk RPCAP" dir=in action=allow protocol=TCP localport=2002
     ```

#### What NetHawkService.exe Provides

- ✅ RPCAP protocol server (compatible with Wireshark)
- ✅ Windows Service support (auto-start on boot)
- ✅ Password authentication (optional)
- ✅ Automatic logging to `C:\ProgramData\NetHawk\nethawk_service.log`
- ✅ No Python or dependencies required (fully self-contained)

---

### Option 2: Standard RPCAP (Windows Alternative)

**Best for**: If you prefer using standard WinPcap/Npcap rpcapd

#### Required Software

1. **Npcap** (includes rpcapd)
   - Download from: https://nmap.org/npcap/
   - Install with "Install Npcap in WinPcap API-compatible Mode"

2. **Start rpcapd Service**
   ```batch
   # No authentication
   rpcapd.exe -n
   
   # With password
   rpcapd.exe -p your_password
   ```

3. **Firewall Configuration**
   - Same as Option 1 - allow port 2002

---

### Option 3: SSH + TShark (Linux/Unix or Windows)

**Best for**: Linux servers, encrypted connections, existing SSH infrastructure

#### Required Software

1. **SSH Server** (usually already installed)
   - Linux: `openssh-server`
   - Windows: OpenSSH Server (Windows 10+)

2. **TShark** (Wireshark command-line tool)
   - Linux: `sudo apt-get install tshark` (Debian/Ubuntu)
   - Linux: `sudo yum install wireshark-cli` (RHEL/CentOS)
   - Windows: Install Wireshark (includes TShark)

3. **SSH Access**
   - SSH key authentication (recommended) or password
   - User must have permissions to capture packets (usually requires sudo/root)

4. **Firewall Configuration**
   - Allow SSH (port 22) - usually already configured

#### Configuration in NetHawk

When adding remote agent in NetHawk:
- Enable "SSH" checkbox
- Enter SSH username
- Enter SSH password or use SSH key
- Select "TShark" as capture method

---

## Quick Setup Summary

### Scenario 1: Windows Remote Server (Easiest)

**Client Machine:**
- Install: `Nethawk.exe` (or run from Python)

**Remote Server:**
- Copy: `NetHawkService.exe`
- Run: `NetHawkService.exe --install` (as Administrator)
- Start: `net start NetHawkCaptureService`
- Configure firewall: Allow port 2002

**In NetHawk:**
- Add Remote Agent → Enter server IP → Port 2002 → Enable RPCAP → Connect

---

### Scenario 2: Linux Remote Server

**Client Machine:**
- Install: `Nethawk.exe` (or run from Python)

**Remote Server:**
- Install: `tshark` (via package manager)
- Ensure: SSH server running
- Configure: SSH access (key or password)

**In NetHawk:**
- Add Remote Agent → Enter server IP → Enable SSH → Enter username/password → Select TShark → Connect

---

### Scenario 3: Windows Server with Standard RPCAP

**Client Machine:**
- Install: `Nethawk.exe` (or run from Python)

**Remote Server:**
- Install: Npcap (includes rpcapd)
- Run: `rpcapd.exe -p password` (or as service)
- Configure firewall: Allow port 2002

**In NetHawk:**
- Add Remote Agent → Enter server IP → Port 2002 → Enable RPCAP → Enter password → Connect

---

## Network Requirements

### Ports

- **RPCAP**: TCP 2002 (default, configurable)
- **SSH**: TCP 22 (standard SSH port)
- **TShark over SSH**: Uses SSH port (22)

### Firewall Rules

**On Remote Server:**
```batch
# Windows Firewall - RPCAP
netsh advfirewall firewall add rule name="NetHawk RPCAP" dir=in action=allow protocol=TCP localport=2002

# Or for SSH (if using TShark)
netsh advfirewall firewall add rule name="SSH" dir=in action=allow protocol=TCP localport=22
```

**On Client Machine:**
- Usually no special rules needed (outbound connections are typically allowed)

---

## Security Recommendations

1. **Use Password Authentication**
   - Always set a password for RPCAP: `NetHawkService.exe --password "secure_password"`
   - Or use SSH with key authentication for TShark

2. **Restrict Network Access**
   - Use Windows Firewall to limit RPCAP access to specific client IPs
   - Or use VPN for secure connection

3. **SSH is More Secure**
   - SSH-based capture (TShark) is encrypted
   - RPCAP is unencrypted (use VPN if needed)

4. **Service Account**
   - NetHawkService runs as LocalSystem by default
   - Consider creating a dedicated service account with minimal privileges

---

## Troubleshooting

### Client Can't Connect

1. **Check Firewall**
   - Verify port 2002 (RPCAP) or 22 (SSH) is open on remote server
   - Test with: `telnet remote_server_ip 2002`

2. **Check Service Status**
   - Windows: `sc query NetHawkCaptureService`
   - Linux: `systemctl status sshd`

3. **Check Logs**
   - Windows: `C:\ProgramData\NetHawk\nethawk_service.log`
   - Linux: `/var/log/auth.log` (for SSH)

### No Packets Captured

1. **Check Permissions**
   - Windows: Service must run with Administrator privileges
   - Linux: User must have packet capture permissions (usually requires sudo)

2. **Check Interface**
   - Verify the correct network interface is selected
   - List interfaces: `ipconfig` (Windows) or `ip addr` (Linux)

3. **Check Network Traffic**
   - Ensure there is actual network traffic on the interface

---

## File Locations

### Client Machine (NetHawk)
- Application: `Nethawk.exe` (or `nethawk2_2.py`)
- Config: `C:\ProgramData\NetHawk\nethawk_config.json`
- Database: `C:\ProgramData\NetHawk\nethawk_packets.db`
- Logs: `C:\ProgramData\NetHawk\nethawk_YYYY-MM-DD.log`

### Remote Server (NetHawkService)
- Service: `NetHawkService.exe`
- Config: `C:\ProgramData\NetHawk\service_config.json`
- Logs: `C:\ProgramData\NetHawk\nethawk_service.log`

---

## Next Steps

1. **Choose your remote capture method** (NetHawkService, rpcapd, or SSH+TShark)
2. **Install software on remote server** (see options above)
3. **Configure firewall** (allow required ports)
4. **Start the service/daemon** on remote server
5. **Add remote agent in NetHawk** (Remote Capture tab → Add Agent)
6. **Connect and start capturing!**

For detailed service management, see `README_SERVICE.md`.

