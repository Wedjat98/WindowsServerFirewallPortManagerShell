# FirewallPort Manager

A PowerShell script for batch management of Windows Firewall rules, supporting port rule configuration via CSV files and handling both TCP and UDP protocols. Includes WSL2 port forwarding support.

## 🚀 Features

- ✅ **Batch Management**: Create or delete firewall rules in bulk through CSV files
- ✅ **Protocol Support**: Support for TCP, UDP, or both protocols simultaneously
- ✅ **Port Ranges**: Support for single ports and port ranges (e.g., `2280-2290`)
- ✅ **Smart Detection**: Automatically detect existing rules to avoid duplicates
- ✅ **Detailed Logging**: Comprehensive operation logs and statistics
- ✅ **Safe Deletion**: Support for batch deletion of created rules
- ✅ **Error Handling**: Robust error handling and validation mechanisms
- ✅ **Rule Control**: Enable/disable individual rules
- ✅ **Performance Optimization**: Optimized rule processing logic for improved speed
- ✅ **WSL2 Integration**: Automatic port forwarding to WSL2 with smart cleanup
- ✅ **Location Awareness**: Support for Windows vs WSL service locations

## 📋 System Requirements

- **Operating System**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: PowerShell 5.1 or higher
- **Permissions**: Administrator privileges (required for modifying firewall rules)
- **Module**: NetSecurity module (built into Windows)
- **WSL2**: Windows Subsystem for Linux 2 (optional, for port forwarding)

## 📁 File Structure

```
firewall-manager/
├── firewall-rules.ps1    # Main script file
├── ports.csv            # Port configuration file
├── open-port-test.py    # Port testing tool
└── README.md            # Documentation
```

## 🔍 Port Testing Tool

The project includes a Python testing tool `open-port-test.py` for verifying firewall rule configurations. This tool can:

- Create temporary HTTP/HTTPS test servers
- Verify port accessibility
- Display server information and connection status
- Support SSL encrypted connection testing

### Usage

1. **Install Python Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Test Server**
   ```bash
   # Test HTTP port
   python open-port-test.py 80

   # Test HTTPS port (requires SSL certificate)
   python open-port-test.py 443 --ssl
   ```

3. **Access Test Page**
   - Local access: `http://localhost:port`
   - LAN access: `http://local-ip:port`

### Test Results

The test page displays:
- Server hostname
- Local IP address
- Listening port
- Protocol used (HTTP/HTTPS)
- Client IP address
- Connection status

### Notes

- Python 3.6+ required to run the test server
- SSL certificates (key.pem and cert.pem) needed for HTTPS mode
- Close the test server after use
- Recommended for testing environments only

## 🛠️ Installation and Setup

### 1. Download Files
Place `firewall-rules.ps1` and `ports.csv` in the same directory.

### 2. Configure CSV File
Edit the `ports.csv` file with the following format:

```csv
Port,Description,Protocol,Enabled,Location,PortForwarding
80,Web Server HTTP,TCP,True,WSL,1
443,Web Server HTTPS,TCP,True,WSL,1
3306,MySQL Database,TCP,True,WSL,1
27017,MongoDB Database,TCP,True,WSL,1
8080-8090,Application Server Range,TCP,True,WSL,1
53,DNS Server,UDP,True,Windows,0
1194,OpenVPN,BOTH,True,Windows,0
```

### 3. Run as Administrator
Right-click PowerShell and select "Run as Administrator".

## 🐚 PS1 Shell Usage Guide

### Basic Usage

1. **Open PowerShell**
   - Press `Win + X`, select "Windows PowerShell (Admin)" or "Windows Terminal (Admin)"
   - Or press `Win + R`, type `powershell`, press `Ctrl + Shift + Enter` to run as admin

2. **Navigate to Script Directory**
   ```powershell
   cd "C:\path\to\your\script"
   ```

3. **Set Execution Policy** (if needed)
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

4. **Run Script**
   ```powershell
   # Basic usage
   .\firewall-rules.ps1

   # With WSL port forwarding
   .\firewall-rules.ps1 -ConfigurePortForwarding

   # Remove all rules
   .\firewall-rules.ps1 -RemoveRules
   ```

### Common Commands

- **View Help**
  ```powershell
  Get-Help .\firewall-rules.ps1
  ```

- **View Detailed Help**
  ```powershell
  Get-Help .\firewall-rules.ps1 -Detailed
  ```

- **View Examples**
  ```powershell
  Get-Help .\firewall-rules.ps1 -Examples
  ```

### Debugging Tips

1. **Enable Verbose Output**
   ```powershell
   $VerbosePreference = "Continue"
   .\firewall-rules.ps1 -Verbose
   ```

2. **View Current Firewall Rules**
   ```powershell
   Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*Your Rule Name*"}
   ```

3. **Check Script Execution Policy**
   ```powershell
   Get-ExecutionPolicy
   ```

### Common Issues

1. **If "Cannot Load File" Error Occurs**
   - Check file path
   - Verify UTF-8 encoding
   - Check file permissions

2. **If "Execution Policy Restriction" Error Occurs**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

3. **To View Detailed Error Information**
   ```powershell
   $ErrorActionPreference = "Continue"
   .\firewall-rules.ps1
   ```

## 📊 CSV File Format

| Column | Description | Example | Required |
|--------|-------------|---------|----------|
| Port | Port number or range | `80`, `443`, `5140-5149` | ✅ |
| Description | Rule description | `Nginx HTTP Server` | ✅ |
| Protocol | Protocol type | `TCP`, `UDP`, `BOTH` | ✅ |
| Enabled | Rule status | `True` (enabled), `False` (disabled) | ❌ |
| Location | Service location | `WSL`, `Windows` | ❌ |
| PortForwarding | Enable forwarding | `1` (enabled), `0` (disabled) | ❌ |

### Protocol Options

- **TCP**: Create TCP protocol rules only
- **UDP**: Create UDP protocol rules only
- **BOTH**: Create both TCP and UDP protocol rules

### Port Format

- **Single Port**: `80`, `443`, `3000`
- **Port Range**: `5000-5050`

### Enable Status

- **True**: Enable rule (allow traffic)
- **False**: Disable rule (block traffic)
- **Empty**: Default to enabled

### Location Options

- **WSL**: Service runs in WSL2 (port forwarding enabled by default)
- **Windows**: Service runs on Windows host (no port forwarding)
- **Empty**: Defaults to WSL

### Port Forwarding

- **1**: Enable port forwarding to WSL
- **0**: Disable port forwarding
- **Empty**: Defaults to enabled for WSL services

## 📝 Usage Examples

### Example 1: Web Server Configuration

```csv
Port,Description,Protocol,Enabled,Location,PortForwarding
80,HTTP Server,TCP,True,WSL,1
443,HTTPS Server,TCP,True,WSL,1
8080,Alternative HTTP,TCP,False,WSL,0
```

### Example 2: Mixed Windows/WSL Services

```csv
Port,Description,Protocol,Enabled,Location,PortForwarding
80,Web Server,TCP,True,WSL,1
3306,MySQL,TCP,True,WSL,1
1433,SQL Server,TCP,True,Windows,0
53,DNS Server,UDP,True,Windows,0
```

### Example 3: Development Environment Configuration

```csv
Port,Description,Protocol,Enabled,Location,PortForwarding
3000,React Dev Server,TCP,True,WSL,1
5000,Flask Backend,TCP,True,WSL,1
8000-8010,Microservices Range,TCP,True,WSL,1
```

## 🔧 Command Line Parameters

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `-RemoveRules` | Switch | Delete rules mode | `.\firewall-rules.ps1 -RemoveRules` |
| `-ConfigurePortForwarding` | Switch | Enable WSL port forwarding | `.\firewall-rules.ps1 -ConfigurePortForwarding` |
| `-SkipAutoCleanup` | Switch | Skip automatic cleanup | `.\firewall-rules.ps1 -SkipAutoCleanup` |
| `-WSLAddress` | String | Specify WSL IP address | `.\firewall-rules.ps1 -WSLAddress "192.168.1.100"` |

## 📋 Output Log Description

The script displays detailed operation logs:

- **🔵 INFO**: General information
- **🟢 SUCCESS**: Operation successful
- **🟡 WARNING**: Warning messages
- **🔴 ERROR**: Error messages

### Run Results Summary

```
--- Summary ---
Rules Created: 15
Rules Skipped (already existed): 2
Port Forwards Configured: 8
Port Forwards Skipped (Windows services): 2
Errors Encountered: 0
--- Script Finished ---
```

## ⚠️ Important Notes

### Permission Requirements
- Must run PowerShell as **Administrator**
- Ensure you have permission to modify Windows Firewall
- WSL2 must be installed for port forwarding

### Security Recommendations
- Only open necessary ports
- Regularly review firewall rules
- Test in a test environment before production use
- Be cautious with port forwarding to WSL

### Network Configuration
- Rules created by the script apply to all network profiles (Domain, Private, Public)
- To modify scope, edit the `$ruleProfiles` variable in the script
- Port forwarding requires WSL2 to be running

## 🐛 Troubleshooting

### Common Errors

**Error 1: Insufficient Permissions**
```
ERROR: Failed to create firewall rule: Access is denied
```
**Solution**: Run PowerShell as Administrator

**Error 2: CSV File Format Error**
```
ERROR: Missing 'Protocol' column in CSV row
```
**Solution**: Check CSV file format, ensure all required columns are present

**Error 3: Invalid Port Range Format**
```
WARNING: Invalid port range '2280-' for description 'Test'
```
**Solution**: Check port range format, should be `startPort-endPort`

**Error 4: WSL Port Forwarding Issues**
```
WARNING: Could not auto-detect WSL address
```
**Solution**: Ensure WSL2 is running and try specifying WSL IP manually with `-WSLAddress`

### Debugging Tips

1. **Check CSV File**: Ensure UTF-8 encoding and correct format
2. **Verify Port Numbers**: Ensure ports are within valid range (1-65535)
3. **Check Existing Rules**: Use `Get-NetFirewallRule` to view current rules
4. **Check Port Forwards**: Use `netsh interface portproxy show all` to view forwards
5. **Verify WSL Status**: Use `wsl --status` to check WSL2 state

## 📞 Support

If you encounter issues or have suggestions for improvement:

1. Check this README document
2. Verify system requirements and permissions
3. Check script output error messages
4. Check Windows Event Logs
5. Verify WSL2 configuration if using port forwarding

## 📄 License

This script is for learning and personal use only. Please comply with relevant laws and enterprise security policies when using.

## 🔄 Version History

- **v4.0**:
  - Added WSL2 port forwarding support
  - Improved port forwarding cleanup
  - Added location awareness for Windows/WSL services
  - Enhanced error handling and logging
- **v3.0**:
  - Added rule enable/disable functionality
  - Optimized rule processing performance
  - Improved batch operation efficiency
  - Reduced memory usage
- **v2.0**: Added TCP/UDP protocol support, improved error handling
- **v1.0**: Basic version, TCP protocol only
