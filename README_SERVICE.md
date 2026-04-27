# NetHawk Remote Capture Service

A lightweight service executable that runs on remote machines to provide packet capture capabilities for the main NetHawk application.

## Features

- **RPCAP Protocol**: Compatible with Wireshark's RPCAP protocol
- **Windows Service**: Can be installed as a Windows service
- **Authentication**: Optional password protection
- **Lightweight**: Minimal resource usage, no GUI
- **Automatic Logging**: Logs to `C:\ProgramData\NetHawk\nethawk_service.log`
- **Service Manager GUI**: Easy-to-use GUI for managing the service
- **Configuration File**: JSON-based configuration support

## Installation

### Build the Service

```batch
build_service.bat
```

This creates `dist\NetHawkService.exe`

### Install as Windows Service

```batch
# Install the service
NetHawkService.exe --install

# Start the service
net start NetHawkCaptureService

# Stop the service
net stop NetHawkCaptureService

# Uninstall the service
NetHawkService.exe --uninstall
```

### Run Manually (for testing)

```batch
# Run on default port 2002
NetHawkService.exe

# Run on custom port
NetHawkService.exe --port 2003

# Run with specific interface
NetHawkService.exe --interface eth0

# Run on specific host
NetHawkService.exe --host 192.168.1.100 --port 2002

# Run with password authentication
NetHawkService.exe --password "your_secure_password"

# Run with configuration file
NetHawkService.exe --config "C:\ProgramData\NetHawk\service_config.json"
```

### Configuration File

Create `service_config.json` in `C:\ProgramData\NetHawk\`:

```json
{
    "host": "0.0.0.0",
    "port": 2002,
    "interface": "any",
    "password": "your_secure_password_here"
}
```

Copy `service_config.json.example` and edit it.

## Usage in NetHawk

1. Deploy `NetHawkService.exe` to the remote machine
2. Install and start the service (or run manually)
3. In NetHawk, add remote agent:
   - Host: IP address of remote machine
   - Port: 2002 (or custom port)
   - Enable RPCAP checkbox
   - If password is set, enter it in the password field
   - Click "Connect"

## Service Manager GUI

A graphical interface for managing the service:

```batch
python service_manager_gui.py
```

Features:
- View service status (Running/Stopped)
- Start/Stop/Restart service
- Install/Uninstall service
- View service logs
- Configure service settings

## Quick Installation

Use the automated installer:

```batch
# Run as Administrator
install_service.bat
```

This will:
1. Check for existing service
2. Install the service
3. Configure auto-start
4. Start the service
5. Verify installation

## Requirements

- Windows (for service installation)
- Python pcap library OR Scapy (for packet capture)
- Network interface access

## Logging

Service logs are written to:
- `C:\ProgramData\NetHawk\nethawk_service.log`
- Console output (when run manually)

## Troubleshooting

1. **Service won't start**: Check Windows Event Viewer for errors
2. **Can't capture packets**: Ensure running with administrator privileges
3. **Connection refused**: Check firewall allows port 2002
4. **No interfaces found**: Install pcap library or Scapy

## Security Notes

- **Password Protection**: Use `--password` or configuration file to enable authentication
- **Firewall**: The service listens on all interfaces (0.0.0.0) by default
- **Restrict Access**: Consider restricting to specific IP with `--host` parameter
- **Firewall Rules**: Use Windows Firewall to limit access to specific IPs
- **Production**: Always use password authentication in production environments

## Authentication

If a password is configured:
1. The service requires authentication before allowing any operations
2. Clients must provide the correct password during connection
3. In NetHawk, enter the password when adding the remote agent
4. Authentication uses RPCAP protocol standard (compatible with Wireshark)

