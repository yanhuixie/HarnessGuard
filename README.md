# HarnessGuard

监控 AI 编程 Harness 软件（Claude Code、Codex、Cursor 等）行为的终端安全防护工具：侦测并阻止其打包上传用户源代码等资产的行为。

## 它解决什么问题

AI 编程工具在本地拥有极高的权限——读写整个代码仓库、执行任意命令、访问网络。一旦其行为失范（或被恶意指令诱导），用户源代码、密钥等资产可能被静默打包外传。HarnessGuard 以独立防护进程的形态运行，对这些工具的文件、进程、网络行为做持续监控与实时阻断。

## 核心能力

- **文件系统监控（第一道防线）**：侦测对源代码目录的大规模读取/打包行为
- **网络监控（兜底防线）**：感知 Harness 进程访问的远程端点，识别并阻断敏感数据外传
- **进程树监控**：自动识别主流 Harness 软件及其全部可执行程序，覆盖经由 nodejs、npm、git、python 等启动的任意子进程，以及计划任务/crontab 触发的执行
- **豁免机制**：基于身份矩阵（签名、路径、哈希），避免误伤正常操作
- **响应动作**：告警（OS 通知）+ 阻断（拦截网络/文件操作）
- **Web UI**：后台服务 + 浏览器访问的管理界面

## 架构

Rust workspace，多 crate 分层（依赖方向自上而下，无环）：

```
hg-app                  # 主程序装配（特权服务）
├─ hg-plat-win / linux / macos   # 平台适配层（ETW / eBPF / EndpointSecurity）
├─ hg-web               # Web UI 与 API（axum）
├─ hg-store             # 存储层（SQLite）
└─ hg-notify            # OS 通知会话桥
   └─ hg-core           # 规则引擎（快慢双路径）、进程身份表
      └─ hg-model       # 统一事件模型
         hg-platform    # 平台抽象 trait
```

约束：整体 RSS ≤ 100MB，CPU 低开销；需运行时提权（访问内核态事件源）。

## 当前状态

- [x] 需求与技术设计评审定稿
- [x] M0：Windows 技术验证（ETW 事件源可行性 spike）
- [x] M1：Windows 端到端链路（检测 → 归因 → 阻断）
- [x] M4：Windows 加固（安装器 / 自保护 / 复验闭环；[第一批报告](docs/20260919-M4第一批报告.md)、[复验报告](docs/20260920-M4第一批复验报告.md)、[第二批报告](docs/20260920-M4第二批报告.md)）
- [ ] M2：Linux 首次编译校准（eBPF 平台代码已编写，未编译验证）
- [ ] M3：macOS 编译校准（EndpointSecurity，同上）

## 安装与卸载（Windows）

需管理员 PowerShell（UAC 提权）：

```powershell
cargo build --release
# 一键安装：前置检查（提权/端口/BFE）→ 配置生成 → 自保护 ACL → 服务安装
# （已装则版本化升级，配置与数据库保留）→ 启动至防护生效
.\target\release\harnessguard.exe install

# Web UI（token 在安装目录 web-token.txt，仅 SYSTEM/Administrators 可读）
start "http://127.0.0.1:8377/?token=<web-token.txt 内容>"

# 卸载：停服（轮询）→ 删服务 → 清 web-token.txt；config/db/logs 保留（审计数据）
.\target\release\harnessguard.exe uninstall
```

- 服务：LocalSystem 自启动，失败三级重启（`sc qfailure HarnessGuard`）
- 日志：安装目录 `logs/`（按日轮转，保留 14 天；`sc stop` 停机序列可观测）
- 日常调试：`harnessguard.exe`（无参控制台模式，Ctrl+C 走完整停机序列）

### 配置（config.toml）

安装目录 `config.toml`（TOML，可经 Web UI 设置页编辑，热生效）：监控树
（`processes.harness`）、网络阈值（`network.upload_threshold_mb`）、端点白名单
（`endpoints.allow`）、文件规则（`files.*`）、存储与 Web 端口等。字段说明见
[技术设计 §6](docs/20260919-HarnessGuard技术设计.md)。

### 可选：文件审计通道（场景 A 加强）

内核文件事件在 burst 下约 99% 等不到文件名（复验定案），`.git` 读取判定可用
Security 审计通道（Event ID 4663）加强——**opt-in**，因启用需改系统级审计策略
（auditpol + SACL）：

```powershell
.\target\release\harnessguard.exe enable-file-audit D:\work\repo\.git   # 需提权
# 回退（对称撤销 auditpol/SACL）：
.\target\release\harnessguard.exe disable-file-audit D:\work\repo\.git
```

### Linux / macOS

`installer/install.sh`（systemd）与 `installer/macos/build-pkg.sh` 为 M2/M3
预写占位（**未编译、未实机验证**），里程碑到位后校准启用。

## 实机复验

复验脚本（管理员 PowerShell，构造方式参考）见 `demos/`：`m1-demo.ps1`（场景
B/D 端到端）、`m4-verify.ps1`（M4 主轮）、`m4-verify3.ps1`（修复验证）、
`m4-sse-final.ps1`（SSE 收口，非提权可跑）。M4 第二批复验清单见
[第二批报告](docs/20260920-M4第二批报告.md)。

## 文档

| 文档 | 说明 |
| --- | --- |
| [需求设计](docs/20260919-HarnessGuard需求设计.md) | 威胁模型、检测规则、能力边界（开发基准文档） |
| [技术设计](docs/20260919-HarnessGuard技术设计.md) | 架构、模块、接口与数据设计 |
| [M0 报告](docs/20260919-M0-Windows-spike报告.md) | Windows 平台技术验证结论 |
| [M1 报告](docs/20260919-M1-Windows-端到端报告.md) | Windows 端到端验收报告 |
| [M4 第一批报告](docs/20260919-M4第一批报告.md) | Windows 加固（SSE/WFP/estats/TaskScheduler/服务宿主） |
| [M4 第一批复验报告](docs/20260920-M4第一批复验报告.md) | 管理员实机复验（6 项，4 轮） |
| [M4 第二批报告](docs/20260920-M4第二批报告.md) | Windows 收尾（estats 降级/归因竞态/4663/ACL/日志/安装器） |
| [intro](docs/intro.md) | 最初的原始需求记录（历史文档） |
