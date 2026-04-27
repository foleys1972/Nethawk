# How Wireshark Does Remote Capture

## Overview
Wireshark supports remote packet capture through several mechanisms, allowing you to capture packets on a remote machine and analyze them locally.

## 1. SSH-Based Remote Capture (sshdump)

### How It Works
- **Extcap Interface**: Wireshark uses an "extcap" (external capture) interface called `sshdump`
- **SSH Connection**: Establishes an SSH connection to the remote host
- **Remote Execution**: Runs `dumpcap` or `tcpdump` on the remote machine
- **Packet Streaming**: Streams captured packets back over the SSH connection
- **Real-time Processing**: Processes packets in real-time as they arrive

### Technical Flow
```
Local Wireshark → SSH Connection → Remote Host
                                      ↓
                                  dumpcap/tcpdump
                                      ↓
                                  Packet Stream
                                      ↓
                                  SSH Tunnel
                                      ↓
                              Local Wireshark Display
```

### Requirements
- SSH access to remote host
- `dumpcap` or `tcpdump` installed on remote host
- Appropriate permissions on remote host (usually root/sudo)
- SSH key authentication or password access

### Usage Example
```bash
# Using sshdump extcap interface
wireshark -i sshdump --extcap-interfaces

# Or via GUI: Capture → Options → Manage Interfaces → SSH Remote Capture
```

### Configuration
- Remote host: IP address or hostname
- SSH port: Default 22
- Username: SSH username
- Interface: Network interface on remote host (e.g., eth0, wlan0)
- Capture filter: BPF filter (optional)

## 2. Remote Packet Capture Protocol (RPCAP) - Windows

### How It Works
- **RPCAP Daemon**: Uses `rpcapd.exe` from WinPcap/Npcap
- **TCP Connection**: Listens on TCP port 2002 (default)
- **Protocol**: Custom binary protocol for packet transmission
- **Authentication**: Optional password-based authentication
- **Interface Enumeration**: Client can list available interfaces on remote host

### Technical Flow
```
Local Wireshark → TCP Connection (port 2002) → Remote rpcapd
                                                      ↓
                                                  WinPcap/Npcap
                                                      ↓
                                                  Network Interface
                                                      ↓
                                                  Packet Stream
                                                      ↓
                                                  TCP Connection
                                                      ↓
                                              Local Wireshark Display
```

### RPCAP Protocol Details
- **Connection Phase**: Client connects, authenticates (if required)
- **Interface Discovery**: Client requests list of available interfaces
- **Capture Start**: Client sends capture request with interface and filter
- **Data Transfer**: Server sends packets in RPCAP format
- **Control Messages**: Heartbeats, error messages, stop commands

### RPCAP Packet Format
```
[Header: 16 bytes]
- Version (2 bytes)
- Message Type (2 bytes)
- Value Length (4 bytes)
- Reserved (8 bytes)

[Payload: Variable length]
- Interface list
- Packet data
- Error messages
```

### Requirements
- WinPcap or Npcap installed on remote Windows machine
- `rpcapd.exe` running as service or manually
- Firewall rules allowing TCP port 2002
- Network connectivity between client and server

### Usage
```bash
# Start rpcapd on remote Windows machine
rpcapd.exe -n  # No authentication
rpcapd.exe -p password  # With password

# In Wireshark GUI:
# Capture → Options → Manage Interfaces → Remote Interfaces
# Add: rpcap://remote_host:2002
```

## 3. Named Pipes (Unix/Linux)

### How It Works
- **Named Pipe (FIFO)**: Creates a named pipe on local machine
- **SSH Tunnel**: Uses SSH to execute remote capture command
- **Output Redirection**: Redirects remote capture output to pipe
- **Local Reading**: Wireshark reads from the named pipe

### Technical Flow
```
Local Machine:
  mkfifo /tmp/remote_capture.pcap
  
Remote Machine (via SSH):
  tcpdump -i eth0 -w - | ssh user@local "cat > /tmp/remote_capture.pcap"
  
Local Wireshark:
  wireshark -i /tmp/remote_capture.pcap
```

### Requirements
- SSH access
- Named pipe support (Unix/Linux)
- `tcpdump` or `dumpcap` on remote host

## 4. Network Device Streaming

### How It Works
Some network devices (e.g., Cisco WAPs) can stream captures directly to Wireshark:
- Device configured to capture packets
- Device sends packets over TCP to Wireshark
- Wireshark receives stream on specified port

## Comparison of Methods

| Method | Platform | Security | Performance | Complexity |
|--------|----------|----------|-------------|------------|
| SSH (sshdump) | All | High (encrypted) | Medium | Low |
| RPCAP | Windows | Medium (optional auth) | High | Medium |
| Named Pipes | Unix/Linux | High (SSH) | Medium | Medium |
| Device Streaming | Network devices | Low | High | High |

## Security Considerations

### SSH-Based (Recommended)
- ✅ Encrypted by default
- ✅ Uses existing SSH infrastructure
- ✅ Supports key-based authentication
- ✅ No additional ports needed

### RPCAP
- ⚠️ Unencrypted by default (unless using VPN)
- ⚠️ Requires firewall configuration
- ⚠️ Optional password authentication
- ⚠️ Additional service to maintain

## Performance Characteristics

### SSH-Based
- **Overhead**: SSH encryption/decryption
- **Latency**: Slight delay due to encryption
- **Bandwidth**: Efficient compression possible
- **CPU**: Higher CPU usage due to encryption

### RPCAP
- **Overhead**: Minimal protocol overhead
- **Latency**: Lower latency (no encryption by default)
- **Bandwidth**: Raw packet transmission
- **CPU**: Lower CPU usage

## Implementation Details

### SSH Dump Extcap
The `sshdump` extcap interface is typically located at:
- Linux: `/usr/lib/x86_64-linux-gnu/wireshark/extcap/sshdump`
- Windows: `C:\Program Files\Wireshark\extcap\sshdump.exe`

### RPCAP Daemon
- Location: `C:\Program Files\Npcap\rpcapd.exe` (or WinPcap)
- Service: Can run as Windows service
- Logging: Optional logging to file
- Configuration: Command-line arguments or config file

## Troubleshooting

### SSH-Based Issues
- **Permission denied**: Check SSH keys and permissions
- **Command not found**: Ensure dumpcap/tcpdump installed on remote
- **No packets**: Check interface name and permissions on remote host

### RPCAP Issues
- **Connection refused**: Check firewall and rpcapd status
- **Authentication failed**: Verify password or disable auth
- **No interfaces**: Check WinPcap/Npcap installation

## Best Practices

1. **Use SSH-based capture** for security and cross-platform compatibility
2. **Use RPCAP** only on trusted networks or with VPN
3. **Limit capture filters** to reduce bandwidth usage
4. **Monitor network usage** when capturing remotely
5. **Use appropriate permissions** on remote hosts
6. **Test connectivity** before starting long captures

## References

- Wireshark SSH Dump: https://www.wireshark.org/docs/man-pages/sshdump.html
- RPCAP Protocol: WinPcap/Npcap documentation
- Wireshark Remote Capture: https://wiki.wireshark.org/CaptureSetup/Remote

