# 增强型 Windows 防火墙 + 端口转发管理

一个用于管理 Windows 防火墙规则和 WSL2 服务端口转发的 PowerShell 脚本。

## 功能特点

- ✅ **CSV 配置**: 通过简单的 CSV 文件轻松管理端口
- ✅ **端口范围支持**: 使用范围配置多个端口（例如，8000-8010）
- ✅ **协议支持**: 配置 TCP、UDP 或两种协议
- ✅ **状态管理**: 自动跟踪和清理已删除的端口
- ✅ **端口转发**: 自动配置到指定地址的端口转发
- ✅ **WSL IP 检测**: 未指定地址时自动检测 WSL2 IP 地址
- ✅ **规则配置文件**: 为所有防火墙配置文件（域、专用、公用）配置规则
- ✅ **规则清理**: 可选择删除所有创建的规则
- ✅ **详细日志**: 所有操作的清晰反馈

## 系统要求

- Windows 10/11 带 WSL2
- PowerShell 5.1 或更高版本
- 管理员权限

## 快速开始

1. 下载脚本和 CSV 文件
2. 编辑 `ports.csv` 配置你的端口
3. 以管理员身份运行脚本：
   ```powershell
   .\firewall-rules.ps1
   ```

## CSV 配置

`ports.csv` 文件使用以下格式：

```csv
Port,Description,Protocol,Enabled,PortForwarding,ForwardAddress
80,Web 服务器,TCP,1,0,
443,HTTPS 服务器,TCP,1,0,
8000-8010,开发服务器,TCP,1,1,192.168.1.100
3000,React 开发服务器,TCP,1,1,
```

### CSV 字段

| 字段 | 描述 | 值 | 必填 |
|------|------|-----|------|
| Port | 端口号或范围 | `数字` 或 `起始-结束` | ✅ |
| Description | 规则描述 | 任意文本 | ✅ |
| Protocol | 网络协议 | `TCP`, `UDP`, `BOTH` | ✅ |
| Enabled | 规则状态 | `1` (启用), `0` (禁用) | ✅ |
| PortForwarding | 启用端口转发 | `1` (启用), `0` (禁用) | ✅ |
| ForwardAddress | 目标 IP 地址 | IP 地址或空白 | ❌ |

### 端口选项

- 单个端口：`80`
- 端口范围：`8000-8010`

### 协议选项

- `TCP`: 仅 TCP 协议
- `UDP`: 仅 UDP 协议
- `BOTH`: TCP 和 UDP 协议

### 端口转发选项

- `1`: 启用到指定地址的端口转发
- `0`: 禁用端口转发

### 转发地址选项

- **IP 地址**: 指定要转发到的 IP 地址（例如，`192.168.1.100`）
- **空白**: 自动检测 WSL2 IP 地址
- **注意**: CSV 中第一个非空的 ForwardAddress 将用于所有端口转发

## 使用方法

### 基本用法

```powershell
# 创建/更新防火墙规则和端口转发
.\firewall-rules.ps1
```

### 删除所有规则

```powershell
# 删除所有防火墙规则和端口转发
.\firewall-rules.ps1 -RemoveRules
```

### 跳过自动清理

```powershell
# 跳过过时规则的自动清理
.\firewall-rules.ps1 -SkipAutoCleanup
```

## 示例

### 基本 Web 服务器（无端口转发）

```csv
Port,Description,Protocol,Enabled,PortForwarding,ForwardAddress
80,Web 服务器,TCP,1,0,
443,HTTPS 服务器,TCP,1,0,
```

### 开发环境（自动检测 WSL IP）

```csv
Port,Description,Protocol,Enabled,PortForwarding,ForwardAddress
3000,React 开发服务器,TCP,1,1,
8000,API 服务器,TCP,1,1,
9000,数据库,TCP,1,1,
```

### 生产环境（指定 IP）

```csv
Port,Description,Protocol,Enabled,PortForwarding,ForwardAddress
80,Web 服务器,TCP,1,1,192.168.1.100
443,HTTPS 服务器,TCP,1,1,192.168.1.100
3306,MySQL,TCP,1,1,192.168.1.100
```

### 混合配置

```csv
Port,Description,Protocol,Enabled,PortForwarding,ForwardAddress
80,公共 Web,TCP,1,0,
443,公共 HTTPS,TCP,1,0,
3000,开发服务器,TCP,1,1,192.168.1.100
8000-8010,API 范围,TCP,1,1,192.168.1.100
```

## 工作原理

1. **地址检测**: 脚本首先检查 CSV 中的 `ForwardAddress` 值
2. **自动检测**: 如果未指定地址，则自动检测 WSL2 IP
3. **端口转发**: 为 `PortForwarding=1` 的端口创建 Windows 端口代理规则
4. **防火墙规则**: 为所有指定端口创建 Windows 防火墙规则
5. **状态跟踪**: 保存当前配置以启用已删除端口的清理

## 故障排除

### 常见问题

1. **脚本无法运行**
   - 确保以管理员身份运行
   - 检查 PowerShell 执行策略：`Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`

2. **端口转发不工作**
   - 验证 WSL2 是否正在运行
   - 检查端口是否已被占用
   - 确保服务在 WSL2 中运行
   - 验证 ForwardAddress 是否正确

3. **规则未创建**
   - 检查 CSV 文件格式
   - 验证端口号是否有效
   - 检查是否有重复条目
   - 确保 CSV 包含所有必需列

4. **WSL IP 自动检测失败**
   - 在 CSV 中手动指定 ForwardAddress
   - 检查 WSL2 网络配置
   - 验证 WSL2 是否正在运行

### 日志记录

脚本提供详细的日志记录：
- **绿色**: 成功消息
- **黄色**: 信息/警告
- **红色**: 错误
- **青色**: 状态信息

## 状态管理

脚本维护一个状态文件（`firewall_state.json`）来跟踪：
- 之前配置的端口
- 端口转发设置
- 规则描述

这使得在从 CSV 中删除端口时能够自动清理。

## 贡献

欢迎提交问题和改进建议！

## 许可证

MIT 许可证 