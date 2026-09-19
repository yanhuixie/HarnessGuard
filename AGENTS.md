# AGENTS.md

面向在本仓库工作的 AI 编程 agent 的操作约定。项目定位见 [README.md](README.md)。

## 基准文档（改代码前必读）

- [需求设计](docs/20260919-HarnessGuard需求设计.md) — 威胁模型与检测规则的唯一基准，含能力边界与非目标
- [技术设计](docs/20260919-HarnessGuard技术设计.md) — 架构、模块、接口与数据设计，含里程碑与风险清单

任何与两份文档字面冲突的实现，先在文档中走"差异修正记录"或"设计拍板记录"流程，不要静默偏离。

## 常用命令

```bash
cargo build                # workspace 全量构建（Windows 上全绿）
cargo test                 # 单测（hg-core / hg-store / hg-web 等含 #[test]）
cargo check                # 快速校验
cargo clippy --workspace   # 静态检查
```

端到端演示（需管理员 PowerShell，实机验证用）：

```powershell
powershell -ExecutionPolicy Bypass -File demos\m1-demo.ps1
```

## 架构与依赖纪律

Rust workspace，10 个 crate，依赖方向**必须无环**（技术设计 §2）：

```
hg-app → {hg-plat-win/linux/macos, hg-web, hg-store, hg-notify} → hg-core → hg-model ← hg-platform
```

- `hg-platform`：平台抽象 trait（只依赖 hg-model）
- `hg-core`：规则引擎（快慢双路径）、进程身份表。**引擎无 IO**——所有副作用经 `EngineOutput` 通道由 hg-app 的执行器落地
- `hg-model`：统一事件模型（`Envelope` / `RawEvent` / `Verdict`）
- `hg-store`：SQLite 存储；`hg-web`：axum Web UI；`hg-notify`：OS 通知会话桥
- `hg-plat-*`：平台适配层，互不依赖，仅被 hg-app 装配

## 平台验证状态（关键）

| 平台 | 状态 |
| --- | --- |
| Windows | 已编译 + 管理员实机验证（M0/M1 报告） |
| Linux | 代码已编写，**从未编译**（eBPF/aya，cfg 门控） |
| macOS | 代码已编写，**从未编译**（EndpointSecurity，cfg 门控） |

由此派生的纪律：

- 改动 `hg-plat-linux` / `hg-plat-macos` 后，在 Windows 上只能验证 `cargo check` 通过的 cfg 门控部分，**不得宣称平台功能已验证**；相关提交与报告须标注"未编译验证"
- 平台专属依赖的门控放在各平台 crate 的 Cargo.toml（workspace 级不放 `[target]` 段）

## 硬约束

- 整体 RSS ≤ 100MB（技术设计 §10 有预算核算表），新依赖/缓存引入前先评估内存
- 无内核驱动：只用用户态特权 API（ETW / eBPF / EndpointSecurity），"提权"= 管理员/root 系统服务
- 运行需管理员权限（ETW 实时会话、WFP 处置）

## 代码与文档约定

- 注释、doc comment、tracing 消息一律中文；代码注释引用设计依据时标注章节（如 `// 技术设计 §3.3`）
- 错误处理：跨层错误用 `thiserror`，应用层用 `anyhow` 上下文链（`{e:#}`）；日志用 `tracing`，禁止 `println!` 调试残留
- 文档文件名：8 位日期前缀（如 `20260919-xxx报告.md`），放 `docs/`
- 提交信息中文；一次提交只含本次工作相关文件
