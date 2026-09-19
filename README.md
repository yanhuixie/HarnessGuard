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
- [ ] M2：Linux 首次编译校准（eBPF 平台代码已编写，未编译验证）
- [ ] M3：macOS 编译校准（EndpointSecurity，同上）
- [ ] M4：自保护加固

## 文档

| 文档 | 说明 |
| --- | --- |
| [需求设计](docs/20260919-HarnessGuard需求设计.md) | 威胁模型、检测规则、能力边界（开发基准文档） |
| [技术设计](docs/20260919-HarnessGuard技术设计.md) | 架构、模块、接口与数据设计 |
| [M0 报告](docs/20260919-M0-Windows-spike报告.md) | Windows 平台技术验证结论 |
| [M1 报告](docs/20260919-M1-Windows-端到端报告.md) | Windows 端到端验收报告 |
| [intro](docs/intro.md) | 最初的原始需求记录（历史文档） |
