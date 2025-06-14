# Enhanced Windows Firewall + Port Forwarding Management

A PowerShell script for managing Windows Firewall rules and port forwarding for WSL2 services.

## Features

- ✅ **CSV-based Configuration**: Easy port management through a simple CSV file
- ✅ **Port Range Support**: Configure multiple ports at once using ranges (e.g., 8000-8010)
- ✅ **Protocol Support**: Configure TCP, UDP, or both protocols
- ✅ **State Management**: Tracks and cleans up removed ports automatically
- ✅ **Port Forwarding**: Automatically configures port forwarding to specified address
- ✅ **WSL IP Detection**: Automatically detects WSL2 IP address when not specified
- ✅ **Rule Profiles**: Configures rules for all firewall profiles (Domain, Private, Public)
- ✅ **Rule Cleanup**: Option to remove all created rules
- ✅ **Detailed Logging**: Clear feedback on all operations

## Requirements

- Windows 10/11 with WSL2
- PowerShell 5.1 or later
- Administrator privileges

## Quick Start

1. Download the script and CSV file
2. Edit `ports.csv` to configure your ports
3. Run the script as administrator:
   ```powershell
   .\firewall-rules.ps1
   ```

## CSV Configuration

The `ports.csv` file uses the following format:

```csv
Port,Description,Protocol,Enabled,PortForwarding,ForwardAddress
80,Web Server,TCP,1,0,
443,HTTPS Server,TCP,1,0,
8000-8010,Development Server,TCP,1,1,192.168.1.100
3000,React Dev Server,TCP,1,1,
```

### CSV Fields

| Field | Description | Values | Required |
|-------|-------------|--------|----------|
| Port | Port number or range | `number` or `start-end` | ✅ |
| Description | Rule description | Any text | ✅ |
| Protocol | Network protocol | `TCP`, `UDP`, `BOTH` | ✅ |
| Enabled | Rule state | `1` (enabled), `0` (disabled) | ✅ |
| PortForwarding | Enable port forwarding | `1` (enabled), `0` (disabled) | ✅ |
| ForwardAddress | Target IP address | IP address or empty | ❌ |

### Port Options

- Single port: `80`
- Port range: `8000-8010`

### Protocol Options

- `TCP`: TCP protocol only
- `UDP`: UDP protocol only
- `BOTH`: Both TCP and UDP protocols

### PortForwarding Options

- `1`: Enable port forwarding to specified address
- `0`: Disable port forwarding

### ForwardAddress Options

- **IP Address**: Specific IP address to forward to (e.g., `192.168.1.100`)
- **Empty**: Auto-detect WSL2 IP address
- **Note**: Only the first non-empty ForwardAddress in the CSV will be used for all port forwarding

## Usage

### Basic Usage

```powershell
# Create/update firewall rules and port forwarding
.\firewall-rules.ps1
```

### Remove All Rules

```powershell
# Remove all firewall rules and port forwarding
.\firewall-rules.ps1 -RemoveRules
```

### Skip Auto-Cleanup

```powershell
# Skip automatic cleanup of obsolete rules
.\firewall-rules.ps1 -SkipAutoCleanup
```

## Examples

### Basic Web Server (No Port Forwarding)

```csv
Port,Description,Protocol,Enabled,PortForwarding,ForwardAddress
80,Web Server,TCP,1,0,
443,HTTPS Server,TCP,1,0,
```

### Development Environment (Auto-detect WSL IP)

```csv
Port,Description,Protocol,Enabled,PortForwarding,ForwardAddress
3000,React Dev Server,TCP,1,1,
8000,API Server,TCP,1,1,
9000,Database,TCP,1,1,
```

### Production Environment (Specific IP)

```csv
Port,Description,Protocol,Enabled,PortForwarding,ForwardAddress
80,Web Server,TCP,1,1,192.168.1.100
443,HTTPS Server,TCP,1,1,192.168.1.100
3306,MySQL,TCP,1,1,192.168.1.100
```

### Mixed Configuration

```csv
Port,Description,Protocol,Enabled,PortForwarding,ForwardAddress
80,Public Web,TCP,1,0,
443,Public HTTPS,TCP,1,0,
3000,Dev Server,TCP,1,1,192.168.1.100
8000-8010,API Range,TCP,1,1,192.168.1.100
```

## How It Works

1. **Address Detection**: The script first checks the CSV for a `ForwardAddress` value
2. **Auto-Detection**: If no address is specified, it automatically detects the WSL2 IP
3. **Port Forwarding**: Creates Windows port proxy rules for ports with `PortForwarding=1`
4. **Firewall Rules**: Creates Windows Firewall rules for all specified ports
5. **State Tracking**: Saves current configuration to enable cleanup of removed ports

## Troubleshooting

### Common Issues

1. **Script fails to run**
   - Ensure you're running as administrator
   - Check PowerShell execution policy: `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`

2. **Port forwarding not working**
   - Verify WSL2 is running
   - Check if the port is already in use
   - Ensure the service is running in WSL2
   - Verify the ForwardAddress is correct

3. **Rules not being created**
   - Check CSV file format
   - Verify port numbers are valid
   - Check for duplicate entries
   - Ensure CSV has all required columns

4. **WSL IP auto-detection fails**
   - Specify ForwardAddress manually in CSV
   - Check WSL2 network configuration
   - Verify WSL2 is running

### Logging

The script provides detailed logging:
- **Green**: Success messages
- **Yellow**: Information/warnings  
- **Red**: Errors
- **Cyan**: Status information

## State Management

The script maintains a state file (`firewall_state.json`) to track:
- Previously configured ports
- Port forwarding settings
- Rule descriptions

This enables automatic cleanup when ports are removed from the CSV.

## Contributing

Feel free to submit issues and enhancement requests!

## License

MIT License
