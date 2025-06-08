# FirewallPort Manager

一个用于批量管理Windows防火墙规则的PowerShell脚本，支持通过CSV文件配置端口规则，可同时处理TCP和UDP协议。

## 🚀 功能特性

- ✅ **批量管理**：通过CSV文件批量创建或删除防火墙规则
- ✅ **协议支持**：支持TCP、UDP或同时开放两种协议
- ✅ **端口范围**：支持单个端口和端口范围（如 `2280-2290`）
- ✅ **智能检测**：自动检测现有规则，避免重复创建
- ✅ **详细日志**：提供详细的操作日志和统计信息
- ✅ **安全删除**：支持批量删除已创建的规则
- ✅ **错误处理**：完善的错误处理和验证机制

## 📋 系统要求

- **操作系统**：Windows 10/11 或 Windows Server 2016+
- **PowerShell**：PowerShell 5.1 或更高版本
- **权限**：管理员权限（修改防火墙规则需要）
- **模块**：NetSecurity 模块（Windows内置）

## 📁 文件结构

```
firewall-manager/
├── firewall-rules.ps1    # 主脚本文件
├── ports.csv            # 端口配置文件
├── open-port-test.py    # 端口测试工具
└── README.md            # 说明文档
```

## 🔍 端口测试工具

项目包含一个Python测试工具 `open-port-test.py`，用于验证防火墙规则是否正确配置。这个工具可以：

- 创建临时的HTTP/HTTPS测试服务器
- 验证端口是否成功开放
- 显示服务器信息和连接状态
- 支持SSL加密连接测试

### 使用方法

1. **安装Python依赖**
   ```bash
   pip install -r requirements.txt
   ```

2. **运行测试服务器**
   ```bash
   # 测试HTTP端口
   python open-port-test.py 80

   # 测试HTTPS端口（需要SSL证书）
   python open-port-test.py 443 --ssl
   ```

3. **访问测试页面**
   - 本机访问：`http://localhost:端口号`
   - 局域网访问：`http://内网IP:端口号`

### 测试结果说明

测试页面会显示：
- 服务器主机名
- 内网IP地址
- 监听端口
- 使用的协议（HTTP/HTTPS）
- 客户端IP地址
- 连接状态

### 注意事项

- 运行测试服务器需要Python 3.6+
- 使用HTTPS模式需要准备SSL证书（key.pem和cert.pem）
- 测试完成后请及时关闭测试服务器
- 建议在测试环境中使用，不要在生产环境长期运行

## 🛠️ 安装与设置

### 1. 下载文件

将 `firewall-rules.ps1` 和 `ports.csv` 放在同一个目录中。

### 2. 配置CSV文件

编辑 `ports.csv` 文件，按照以下格式配置需要管理的端口：

```csv
Port,Description,Protocol
80,Web Server HTTP,TCP
443,Web Server HTTPS,TCP
3306,MySQL Database,TCP
27017,MongoDB Database,TCP
8080-8090,Application Server Range,TCP
53,DNS Server,UDP
1194,OpenVPN,BOTH
```

### 3. 以管理员身份运行

右键点击PowerShell，选择"以管理员身份运行"。

## 🐚 PS1 Shell 使用说明

### 基本使用

1. **打开 PowerShell**

   - 按 `Win + X`，选择 "Windows PowerShell (管理员)" 或 "Windows Terminal (管理员)"
   - 或按 `Win + R`，输入 `powershell`，按 `Ctrl + Shift + Enter` 以管理员身份运行
2. **导航到脚本目录**

   ```powershell
   cd "C:\path\to\your\script"
   ```
3. **设置执行策略**（如果需要）

   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
4. **运行脚本**

   ```powershell
   .\firewall-rules.ps1
   ```

### 常用命令

- **查看帮助信息**

  ```powershell
  Get-Help .\firewall-rules.ps1
  ```
- **查看详细帮助**

  ```powershell
  Get-Help .\firewall-rules.ps1 -Detailed
  ```
- **查看示例**

  ```powershell
  Get-Help .\firewall-rules.ps1 -Examples
  ```

### 调试技巧

1. **启用详细输出**

   ```powershell
   $VerbosePreference = "Continue"
   .\firewall-rules.ps1 -Verbose
   ```
2. **查看当前防火墙规则**

   ```powershell
   Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*Your Rule Name*"}
   ```
3. **检查脚本执行权限**

   ```powershell
   Get-ExecutionPolicy
   ```

### 常见问题解决

1. **如果遇到"无法加载文件"错误**

   - 检查文件路径是否正确
   - 确认文件编码为 UTF-8
   - 验证文件权限
2. **如果遇到"执行策略限制"错误**

   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
3. **如果需要查看详细错误信息**

   ```powershell
   $ErrorActionPreference = "Continue"
   .\firewall-rules.ps1
   ```

## 📖 使用方法

### 创建防火墙规则

```powershell
# 导航到脚本目录
cd "C:\path\to\your\script"

# 执行脚本创建规则
.\firewall-rules.ps1
```

### 删除防火墙规则

```powershell
# 删除所有由脚本创建的规则
.\firewall-rules.ps1 -RemoveRules
```

### 修改规则基础名称

如果需要修改防火墙规则的基础名称，编辑脚本中的 `$ruleBaseName` 变量：

```powershell
$ruleBaseName = "Your Custom Rule Name"
```

## 📊 CSV文件格式说明

| 列名        | 描述             | 示例                           | 必填 |
| ----------- | ---------------- | ------------------------------ | ---- |
| Port        | 端口号或端口范围 | `80`, `443`, `5140-5149` | ✅   |
| Description | 规则描述         | `Nginx HTTP Server`          | ✅   |
| Protocol    | 协议类型         | `TCP`, `UDP`, `BOTH`     | ✅   |

### 协议选项

- **TCP**：仅创建TCP协议规则
- **UDP**：仅创建UDP协议规则
- **BOTH**：同时创建TCP和UDP协议规则

### 端口格式

- **单个端口**：`80`, `443`, `3000`
- **端口范围**：`5000-5050`

## 📝 使用示例

### 示例1：Web服务器配置

```csv
Port,Description,Protocol
80,HTTP Server,TCP
443,HTTPS Server,TCP
8080,Alternative HTTP,TCP
```

### 示例2：游戏服务器配置

```csv
Port,Description,Protocol
25565,Minecraft Server,TCP
7777,Game Server,BOTH
19132,Bedrock Server,UDP
```

### 示例3：开发环境配置

```csv
Port,Description,Protocol
3000,React Dev Server,TCP
5000,Flask Backend,TCP
8000-8010,Microservices Range,TCP
```

## 🔧 命令行参数

| 参数             | 类型   | 描述         | 示例                                  |
| ---------------- | ------ | ------------ | ------------------------------------- |
| `-RemoveRules` | Switch | 删除规则模式 | `.\firewall-rules.ps1 -RemoveRules` |

## 📋 输出日志说明

脚本运行时会显示详细的操作日志：

- **🔵 INFO**：一般信息
- **🟢 SUCCESS**：操作成功
- **🟡 WARNING**：警告信息
- **🔴 ERROR**：错误信息

### 运行结果统计

```
--- Summary ---
Rules Created: 15
Rules Skipped (already existed): 2
Errors Encountered: 0
--- Script Finished ---
```

## ⚠️ 注意事项

### 权限要求

- 必须以**管理员身份**运行PowerShell
- 确保具有修改Windows防火墙的权限

### 安全建议

- 仅开放必要的端口
- 定期审查防火墙规则
- 在生产环境使用前先在测试环境验证

### 网络配置

- 脚本创建的规则适用于所有网络配置文件（Domain, Private, Public）
- 如需修改适用范围，可编辑脚本中的 `$ruleProfiles` 变量

## 🐛 故障排除

### 常见错误

**错误1：权限不足**

```
ERROR: Failed to create firewall rule: Access is denied
```

**解决方案**：以管理员身份运行PowerShell

**错误2：CSV文件格式错误**

```
ERROR: Missing 'Protocol' column in CSV row
```

**解决方案**：检查CSV文件格式，确保包含所有必需列

**错误3：端口范围格式错误**

```
WARNING: Invalid port range '2280-' for description 'Test'
```

**解决方案**：检查端口范围格式，应为 `startPort-endPort`

### 调试建议

1. **检查CSV文件**：确保文件编码为UTF-8，格式正确
2. **验证端口号**：确保端口号在有效范围内（1-65535）
3. **检查现有规则**：使用 `Get-NetFirewallRule` 查看现有规则

## 📞 支持

如果遇到问题或有改进建议，请：

1. 检查本README文档
2. 验证系统要求和权限
3. 查看脚本输出的错误信息
4. 检查Windows事件日志

## 📄 许可证

本脚本仅供学习和个人使用。使用时请遵守相关法律法规和企业安全政策。

## 🔄 版本历史

- **v2.0**：添加TCP/UDP协议支持，改进错误处理
- **v1.0**：基础版本，仅支持TCP协议
