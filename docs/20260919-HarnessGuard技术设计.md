# HarnessGuard 技术设计

> 依据：[20260919-HarnessGuard需求设计.md](./20260919-HarnessGuard需求设计.md)（下称"需求文档"）。本文档负责落地架构、模块、接口与数据设计。
> 日期：2026-09-19（v2，已按独立评审意见修订：修复 fanotify API 错误、循环依赖、敏感文件/DNS/持久化落点缺失、通知会话边界、背压与停机序列等 10 项 P1）

---

## 1. 设计总览

### 1.1 架构与数据流

```
┌──────────────────────────── 单特权服务进程（Rust，一个二进制） ────────────────────────────────┐
│                                                                                              │
│  平台事件源（平台线程 × N）             核心引擎（hg-core）              出口                  │
│  ┌───────────────┐   RawEvent   ┌─────────────────────┐                                    │
│  │ ETW (Win)      │──┐           │ 进程身份表 ProcTable │──┐                                 │
│  │ eBPF (Linux)   │  │           │ （dashmap 分片锁）   │  │                                 │
│  │ auditpipe (Mac)│  ├─ mpsc ──▶ │ ConnRegistry 连接表  │  ├─▶ Enforcer（处置动作）          │
│  └───────────────┘  │           │                     │  │    kill / drop_tcp / block_ip   │
│  ┌───────────────┐  │           │ 慢路径分析流水线     │  ├─▶ Notifier（OS 通知，经会话桥） │
│  │ fanotify PERM  │──┘           │ （审计/累计/阈值）   │  ├─▶ Store（SQLite 追加写）        │
│  │ (Linux,同步)   │── 快路径规则快照（arc-swap）▶ FAN_ALLOW/DENY 同步写回                  │
│  └───────────────┘                      ▲规则快照原子替换                                   │
│  健康监控：事件源心跳/自动重建/失效告警 ──┘                                                    │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

三平台统一为 **"事件流（检测）+ 处置动作（响应）"** 模型（需求 §5）：平台差异被压缩在"事件源"与"Enforcer"两个边缘，核心引擎、规则、存储、UI 三平台共享。

### 1.2 设计原则

1. **快慢双路径**：唯一有同步判定预算的是 Linux fanotify `FAN_OPEN_PERM/FAN_ACCESS_PERM`（进程在等 open/access 返回，判定必须微秒级完成）。一切 IO（SQLite、通知、网络处置）只允许发生在异步路径；PERM 线程投递审计事件只许 `try_send`（通道满则丢弃并计数，绝不阻塞，否则全系统 open 卡死）。
2. **平台代码隔离**：领域模型在 `hg-model`（纯数据）；`hg-core` 只含逻辑，无平台 API、无 IO，可全量单测；平台 crate 只做"系统 API → 统一事件模型"的翻译。
3. **规则即数据**：规则全部配置化（TOML），快照原子替换，热更新不停服务。
4. **诚实降级**：平台能力差异（需求 §1.2）在事件模型层显式表达；检测能力失效必须"大声告警"，禁止静默失效（见 §9 健康监控）。

---

## 2. Workspace 结构

```
harnessguard/
├── Cargo.toml                  # workspace
├── crates/
│   ├── hg-model/               # 纯领域类型：RawEvent / Identity / Verdict / Pid / TcpQuad …
│   ├── hg-core/                # 规则引擎 + ProcTable + ConnRegistry + 分析流水线（纯逻辑）
│   ├── hg-platform/            # EventSource / Enforcer trait 定义（依赖 hg-model）
│   ├── hg-plat-win/            # ETW 事件源、WFP/杀进程/断连接处置、服务封装、通知代理拉起
│   ├── hg-plat-linux/          # eBPF(aya)、fanotify、sock_diag、nft 处置
│   ├── hg-plat-macos/          # auditpipe FFI、libpcap、tcpdrop/pf 处置、通知 LaunchAgent
│   ├── hg-store/               # rusqlite（bundled）：schema、追加写、滚动清理、查询
│   ├── hg-notify/              # 通知封装 + 三平台会话桥（见 §8）
│   ├── hg-web/                 # axum：REST + SSE、token 鉴权、静态资源嵌入
│   └── hg-app/                 # main：配置加载、平台选择、健康监控、组装装配
└── ui/                         # 前端静态资源（无构建，rust-embed 嵌入 hg-web）
```

依赖方向（无环）：`hg-app → {hg-plat-*, hg-web, hg-store, hg-notify} → hg-core → hg-model ← hg-platform`。平台 crate 之间互不依赖。

### 2.1 关键 trait（定义于 hg-platform，类型来自 hg-model）

```rust
/// 平台事件源：在专属线程内阻塞读系统 API，翻译为 RawEvent 推入通道。
/// trait 本身不 async —— fanotify/auditpipe/eBPF ringbuf 均以平台线程阻塞/轮询驱动。
pub trait EventSource: Send {
    fn name(&self) -> &'static str;
    fn run(self, tx: mpsc::Sender<RawEvent>) -> std::convert::Infallible;
}

/// 处置动作（全部在异步路径调用，无同步预算约束）。
pub trait Enforcer: Send + Sync {
    fn kill_process(&self, pid: Pid, start_time: StartTime) -> Result<()>;
    fn drop_tcp(&self, quad: TcpQuad) -> Result<()>;                        // 重置单条 TCP 连接
    fn block_endpoint_temporary(&self, ip: IpAddr, ttl: Duration) -> Result<()>; // 防火墙层封 IP
}
```

---

## 3. 核心领域模型

### 3.1 统一事件模型（hg-model）

```rust
pub struct Envelope { pub ts: Timestamp }   // 统一时基：单调时钟（防回拨），落库换算 UTC 毫秒；各平台源事件时基对齐见 §5

pub enum RawEvent {
    Exec      { pid, ppid, start_time, exe: PathBuf, cmdline: Vec<OsString>, cwd: PathBuf },
    Exit      { pid, start_time },
    FileOpen  { pid, start_time, path: PathBuf, access: Read | Write },
    FileCreate{ pid, start_time, path: PathBuf },   // 归档产物判定信号（三平台均为事后处置，无同步拒绝语义）
    ConnOpen  { pid, start_time, conn_id: ConnId, proto, local, remote },
    ConnTx    { conn_id, bytes_out_delta: u64 },    // 上行字节量增量；归因靠 ConnRegistry 内存映射
    ConnClose { conn_id },
    DnsQuery  { pid, qname: String, answers: Vec<IpAddr> },  // 域名→IP 关联（需求 §3.2）
    Persistence { pid, kind: SchedTask | Cron | LaunchAgent | RunKey, detail: String },
}
```

- `start_time` 全程随 pid 携带：防 pid 复用错判（身份表/处置校验 pid + start_time 双匹配）。
- `FileCreate` 与 `FileOpen(Write)` 分开建模：归档产物判定靠"创建压缩后缀文件"信号，语义与"写已有文件"不同；其处置是**事后杀进程/告警**（平台无同步拒绝点，含 Linux——`FAN_CREATE` 是通知类事件）。
- **ConnRegistry**（hg-core，dashmap）：`ConnId → (pid, harness_root, remote, bytes_out 累计)`。`ConnTx` 只带 conn_id，归因、阈值累计全部在此内存表完成（不可能依赖 SQLite），连接关闭后汇总落库。

### 3.2 进程身份表（ProcTable）

```rust
pub struct Identity {
    pub pid: Pid, pub start_time: StartTime,
    pub exe: PathBuf, pub cmdline: Vec<OsString>,
    pub harness_root: Option<HarnessId>,   // None = 非监控进程
    pub tool_exempt: Option<&'static str>, // 命中 tool_exempt 表的版本控制工具（身份矩阵豁免，需求 §3.3）
}
// ProcTable = DashMap<Pid, Identity>
```

**身份判定（Exec 事件时执行）**：
1. 可执行路径（或 sha256，见 §6 特征库）命中 harness 特征库 → `harness_root = Some(new_id)`（监控根）；
2. 父进程 `harness_root` 非 None → 继承父的 `harness_root`（跨 shell 链传播，覆盖计划任务/shell/任意第三方拉起）；
3. 命中 `tool_exempt` 表（git 等版本控制工具 × 豁免路径模式）→ 标记豁免身份。注意：**仍继承 harness_root**——豁免靠"工具 × 路径"矩阵分支，而非脱离进程树；归档工具（tar/zip/7z）**不进豁免表**，它们在树内一律走封堵规则。

**启动补扫描**：服务可能晚于 harness 启动。启动时全量枚举存活进程（Linux `/proc`、Windows 进程快照、macOS `sysctl KERN_PROC_ALL`），按 exe/哈希命中特征库补建根身份；未观察到的中间父链无法精确重建，按 exe 特征直接判定，宁标勿漏。

### 3.3 快慢双路径规则引擎（本设计最重要的性能结构）

```rust
/// 快路径：纯函数、无 IO、无系统调用。仅 Linux fanotify PERM 事件同步调用（微秒预算）。
pub fn judge_perm_sync(rules: &RulesSnapshot, id: &Identity, path: &Path, access: Access) -> Verdict {
    // 0. 白名单短路：path/进程在用户白名单 → Allow（需求 §4.3）
    // 1. id.harness_root.is_none() → Allow（非监控进程不干预；审计走 try_send 异步落库）
    // 2. tool_exempt 且路径匹配其豁免模式（如 git × .git/**）→ Allow（需求 §3.3 身份矩阵）
    // 3. harness 进程（非豁免工具）触碰 .git/** 分面（需求 §3.1，拍板记录 12）：
    //    注入面（hooks/** 读写、config/config.lock 写）→ Deny；
    //    工作流面（objects/refs/HEAD/锁文件等本职读写）→ Allow
    //    （引擎按监控根首见补一条 Audit 取证线索，防高频读写刷库）
    // 4. 敏感文件模式命中 → Allow 放行 + Audit 标记（不阻断，异步落 Verdict(Audit) 供取证）
    // 5. 默认 Allow + try_send 审计事件（满则丢弃计数）
}

/// 慢路径：异步分析线程执行，预算宽松。所有判定统一 action 命名 Block | Audit | Allow。
/// - 敏感文件读取命中 → Verdict(Audit) 落库（需求 §3.1 第一条规则）
/// - 归档产物创建（FileCreate × 压缩后缀）→ Verdict(Block) + kill_process（事后处置）
/// - Exec 命令行匹配 [commands].blocked（git archive/bundle/format-patch、tar/zip…）
///     → Verdict(Block) + kill_process（需求 §3.3 导出封堵）
/// - 网络阈值：ConnRegistry 按 (harness_root, remote) 累计上行字节——
///     累计 > upload_threshold_mb 且端点（域名→IP 映射或 IP）不在白名单
///     → Verdict(Block) + drop_tcp + block_endpoint_temporary
/// - 两级评分联动（最小模型，需求 §3.1"取证与评分联动"落点）：
///     该 harness_root 已有敏感文件 Audit 记录 且 累计 > 阈值/10 → 同样 Block
/// - Persistence 事件 → Verdict(Audit) + 高优先告警（需求 §3.5）
}
```

**规则热更新**：`RulesSnapshot`（Arc 包裹、构建时预编译：路径通配符编译为 glob、命令行编译为模式、白名单编译为哈希集）经 `arc-swap` 原子替换；快/慢路径读快照全程无锁。UI 修改白名单/配置 → 构建新快照 → 原子替换 + 写回 TOML（同一事务语义）。

**Verdict 与证据链**：

```rust
pub struct Verdict {
    pub rule_id: RuleId, pub action: Block | Audit | Allow,
    pub evidence: Evidence,   // 命中规则、路径、连接、累计字节数、关联 Audit 记录等，JSON 落库
}
```

每个 Block 落库 + 通知（附证据摘要），UI 可跳转证据——满足"审计取证"要求。

---

## 4. 存储层（hg-store，SQLite）

rusqlite（`bundled` feature，静态编译 sqlite3.c，免系统依赖）。WAL 模式。

```sql
CREATE TABLE processes(   -- 身份表镜像（历史查询用）
  pid INTEGER, start_ts INTEGER, exe TEXT, cmdline TEXT,
  harness_root TEXT, exit_ts INTEGER);
CREATE INDEX idx_proc_root ON processes(harness_root, start_ts);

CREATE TABLE events(      -- 异步路径全量审计流
  id INTEGER PRIMARY KEY, ts INTEGER, pid INTEGER, start_ts INTEGER,
  kind TEXT, detail_json TEXT);
CREATE INDEX idx_events_ts ON events(ts);

CREATE TABLE conns(       -- ConnRegistry 关闭时汇总落库
  conn_id TEXT PRIMARY KEY, pid INTEGER, harness_root TEXT,
  remote_ip TEXT, remote_port INTEGER, proto TEXT,
  bytes_out INTEGER, opened_ts INTEGER, closed_ts INTEGER);
CREATE INDEX idx_conns_root ON conns(harness_root, remote_ip);

CREATE TABLE verdicts(    -- 判定记录（UI 主视图）
  id INTEGER PRIMARY KEY, ts INTEGER, rule_id TEXT, action TEXT,
  pid INTEGER, exe TEXT, evidence_json TEXT, notified INTEGER);
CREATE INDEX idx_verdicts_ts ON verdicts(ts);

CREATE TABLE dns_map(     -- 域名→IP 关联缓存（供端点白名单判定）
  qname TEXT, ip TEXT, pid INTEGER, ts INTEGER);
CREATE INDEX idx_dns_ip ON dns_map(ip);

CREATE TABLE whitelist(
  id INTEGER PRIMARY KEY, kind TEXT,  -- endpoint | path | proc
  value TEXT, note TEXT, created_ts INTEGER, UNIQUE(kind, value));
```

- **时间戳**：统一 UTC 毫秒整数存储；各平台源时基（ETW QPC、eBPF ktime、BSM 时间戳、fanotify 事件时钟）在事件源层用 `(boot_time, monotonic)` 对齐换算，UI 按本地时区渲染。
- **写入策略**：异步路径批量 flush（每 200ms 或 500 条）；审计流与判定解耦，SQLite 慢不拖累检测。
- **追加写与滚动清理的矛盾拍板**：运行期只追加——SQLite 触发器拦截对 `events/conns/verdicts/processes` 的 `UPDATE/DELETE`；唯一删除路径是每日清理任务（清理连接持有内部标记，临时禁用触发器执行 `DELETE`）。满足需求"审计日志只能追加"，同时保留保留期清理能力。Web UI"清空审计数据"（`POST /api/data/clear`，2026-09-20 补）复用同一路径：`StoreOp::Purge` 经写入通道转入写入线程执行，不看保留期，白名单与运行中进程身份不在清理范围。
- **滚动清理范围**：`events`、`conns`、`verdicts`、`processes`（已退出进程）、`dns_map` 全部纳入，按 `min(保留天数, 磁盘上限)` 双条件（默认 30 天 / 500MB）。conns 表无 `ts` 列，按 `opened_ts` 判期（实现首版误按 `ts` 删致恒失败，已修正）。
- **防篡改**：库文件 ACL 仅管理员可写；不做链式哈希（威胁模型为被动外传，需求 §1.1）。

---

## 5. 平台适配层

### 5.1 Windows（hg-plat-win）

| 能力 | 选型 | 说明 |
|------|------|------|
| 进程事件 | ETW Kernel-Process provider（ferrisetw；备选 windows-rs 手写消费者） | Image/ProcessStart/Stop，异步流 |
| 文件事件 | ETW Kernel-File | **FileObject→路径需经 Kernel-File Name 事件关联**（经典坑：Name 事件丢失则路径 unknown，需维护 FileObject 缓存 + 容忍 unknown）；事件量大，解析层按 harness 身份早过滤（即读即弃非监控进程事件），spike 实测速率 |
| 网络事件/字节量 | ETW Microsoft-Windows-Kernel-Network | connect + per-send bytes，按连接累计 |
| **DNS** | ETW Microsoft-Windows-Dns-Client | 查询与应答 IP → `DnsQuery` 事件 |
| **持久化检测** | Task Scheduler 操作日志（ETW `Microsoft-Windows-TaskScheduler/Operational`）+ RunKey/RunOnce 注册表（Kernel-Registry provider 过滤该键路径，或低频轮询对比快照） | 归因发起进程 |
| 处置：杀进程 | `OpenProcess`+`TerminateProcess`（SYSTEM 有 SeDebugPrivilege，校验 start_time） | |
| 处置：断连接 | `SetTcpEntry`/`SetTcp6Entry`（`MIB_TCP_STATE_DELETE_TCB`） | IPv4/IPv6 双栈 |
| 处置：封 IP | 用户态 WFP（`FwpmFilterAdd0` 子层 BLOCK + TTL 过期）| 无需驱动 |
| 服务宿主 | `windows-service` crate，恢复策略自动重启 | |
| 通知 | 会话桥：`WTSQueryUserToken` + `CreateProcessAsUser` 拉起一次性通知代理（活跃会话枚举，每会话投递），见 §8 | 服务在会话 0，不可直接 Toast |

### 5.2 Linux（hg-plat-linux）

| 能力 | 选型 | 说明 |
|------|------|------|
| 进程事件 | **eBPF（aya）：tracepoint `sched_process_exec`/`sched_process_exit`/`sched_process_fork`** | 直接携带 exe/filename 与 pid 上下文，短命进程不丢（需求 §3.4）；需 root（已具备）+ 内核 BTF（5.10+ 主流发行版默认），M0 验证。**备选**（无 BTF/容器精简内核降级）：proc connector（`CN_PROC`），但其事件仅 pid，exe/cmdline 需补读 `/proc`，短命进程常读不到——降级模式显式告警"短命子进程可见性受限" |
| 文件事件 + **同步阻断** | fanotify：`fanotify_init(FAN_CLASS_CONTENT \| FAN_CLOEXEC \| FAN_NONBLOCK, O_RDONLY \| O_LARGEFILE)`；`fanotify_mark(fd, FAN_MARK_ADD \| FAN_MARK_FILESYSTEM, FAN_OPEN_PERM \| FAN_ACCESS_PERM \| FAN_CREATE \| FAN_CLOSE_WRITE, ...)` | PERM 位在 **mark mask**（不在 init 第二参）。`FAN_OPEN/ACCESS_PERM` → `judge_perm_sync` → 同步写回 `FAN_ALLOW/FAN_DENY`；`FAN_CREATE/FAN_CLOSE_WRITE` 仅产生通知事件（`FileCreate` 信号源，事后处置）。内核 ≥ 5.10 |
| 网络事件/字节量 | 首选 eBPF：`tcp_sendmsg`/udp 等挂点按 **socket cookie** 计数上行字节，cookie↔五元组↔pid 在 ConnRegistry 关联 | 备选链（BPF 不可用时降级并告警）：inet_diag(sock_diag) 周期采样（pid 归因弱）→ nftables accounting（按 IP 不按进程，判定粒度降为端点级） |
| **DNS** | eBPF 挂 UDP:53（或 libpcap 抓 53 端口）解析 query/answer | 明文 DNS 场景；DoH 下退化按 IP（需求 §1.2 已声明） |
| 持久化检测 | inotify 监控 `/etc/cron*`、`~/.cron`、systemd unit 目录变更 | 归因触发进程 |
| 处置：断连接/封 IP | `nft` CLI 子进程（备选 libnftables FFI） | |
| 服务宿主 | systemd unit | |
| 通知 | 会话桥：遍历 `loginctl` 活跃会话，以各 `DBUS_SESSION_BUS_ADDRESS=/run/user/<uid>/bus` 投递 notify-send，见 §8 | root 服务无会话 bus，不可直接投递 |

**Linux 双风险（M0 必测）**：全盘 filesystem mark + PERM 位使**全系统每次 open/access 同步往返用户态**——需实测对系统吞吐的影响（缓解预案：mark 收缩到用户工作区目录 + 已知 harness 目录，牺牲全盘覆盖换吞吐）；eBPF 加载失败（无 BTF）的降级链自检。

### 5.3 macOS（hg-plat-macos）

| 能力 | 选型 | 说明 |
|------|------|------|
| 进程/文件事件 | **手写** `/dev/auditpipe`（open + `AUDITPIPE_SET_PRESELECT_MODE` ioctl 预选 EX/FC 类 + BSM token 解析）；参考 SUpraudit（`praudit` 实时替代品） | 无现成 Rust crate，**全项目最大自研点**，M0 必出最小原型。降级：FSEvents（文件，粗粒度）+ `sysctl kinfo_proc` 轮询（进程，漏短命进程），降级时显式告警 |
| 网络事件/字节量 | libpcap（BPF 设备，root）按五元组累计上行；pid 归因 `proc_pidinfo`/fd 扫描 | |
| **DNS** | libpcap BPF 过滤 `port 53` | |
| 持久化检测 | FSEvents 监控 `~/Library/LaunchAgents`、`/Library/Launch{Agents,Daemons}` | |
| 处置 | `tcpdrop`（四元组掐连接）、`pfctl` 封 IP、`kill` | 事后秒级（需求 §5 能力阶梯） |
| 服务宿主 | LaunchDaemon plist | |
| 通知 | 会话桥：安装 per-user LaunchAgent 轻量代理（unix domain socket 收请求→用户会话发通知），见 §8 | LaunchDaemon 无用户上下文 |

---

## 6. 配置与规则（TOML，双通道：文件 + Web UI）

```toml
# /etc/harnessguard/config.toml（Win: ProgramData\HarnessGuard\config.toml）

[network]
upload_threshold_mb = 100            # 上行阻断阈值（需求 §3.2，可自设）
sensitive_escalation_divisor = 10    # 已读敏感文件时阈值降档除数（两级评分联动）

[endpoints]
allow = [                            # 端点白名单：域名优先（经 dns_map 解析匹配），DoH 下退化按 IP
  "api.anthropic.com", "api.openai.com",
  "*.github.com", "*.googleapis.com",
]

[files]
git_dir_action     = "block"         # block | audit（需求 §3.1，默认 block 可改；仅作用于 .git 注入面：hooks/** 与 config 写，拍板记录 12）
git_dir_kill       = false           # 注入面 block 命中是否升级杀进程（拍板记录 13，缺省不杀：判定+通知即止）
archive_action     = "block"
sensitive_patterns = [".env", ".env.*", "*_rsa", "*.pem", "*credentials*"]
archive_patterns   = ["*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.7z", "*.gz", "*.zst"]

[commands]                           # Exec 命令行封堵（慢路径判定 + kill_process）
blocked = [
  "git archive*", "git bundle*", "git format-patch*",
  "tar *", "zip *", "7z *", "gzip *", "zstd *",
]

[[processes.harness]]                # 特征库：内置默认 + 用户 UI 增补；支持路径 glob 与可选哈希
name = "claude-code"
paths = ["**/node_modules/.bin/claude*", "**/claude*"]
# sha256 = ["..."]                   # 可选：哈希特征（需求 §3.4）

[[tool_exempt]]                      # 身份矩阵豁免：版本控制工具 × 豁免路径模式（需求 §3.3）
exe = "git"
allow_paths = [".git/**"]            # git 的 .git 内读写豁免；工作区写操作不受豁免

[storage]
retention_days = 30
max_disk_mb = 500

[web]
bind = "127.0.0.1:8377"
```

内置默认配置编译进二进制（`include_str!` + 版本号），用户配置覆盖式合并；UI 修改写回文件（仅管理员可写）。归档工具（tar/zip/7z）不进 `tool_exempt`——它们在 harness 树内的执行由 `[commands].blocked` 封堵，用户终端中手动使用不在树内、不受影响。

---

## 7. Web UI 与 API（hg-web）

- **技术栈**：axum + tokio（工作线程压至 2–4）；前端无构建静态资源（原生 JS + fetch + SSE，`rust-embed` 嵌入二进制）。
- **鉴权**（需求 §6.2）：仅 `127.0.0.1`；启动生成随机 token；普通 API 仅接受 `Authorization: Bearer`（前端存 localStorage）；**query token 仅放行 `/api/stream`（SSE）**——EventSource API 无法带 header，同时避免 token 大面积落入浏览器历史/服务器日志；中间件校验 `Host` 必须为配置的 `127.0.0.1:port`（防 DNS rebinding）。

| 端点 | 方法 | 用途 |
|------|------|------|
| `/api/status` | GET | 服务状态、事件源健康度、当前监控 harness 列表、资源占用 |
| `/api/events?since&kind&pid` | GET | 审计流分页查询 |
| `/api/verdicts` | GET | 判定记录（Dashboard 主数据） |
| `/api/whitelist` | GET/POST/DELETE | 白名单管理（热替换快照 + 落库） |
| `/api/config` | GET/PUT | 阈值/规则动作配置（写 TOML + 热替换） |
| `/api/processes` | GET | 进程身份表快照 |
| `/api/stream` | SSE（query token） | 实时事件 + 判定推送 |
| `/` | GET | 静态 UI |

**页面**：Dashboard（状态 + 最近阻断 + 证据详情）、事件流（过滤/搜索）、白名单、设置。

---

## 8. 通知与自保护

### 8.1 OS 通知的会话桥（特权服务 → 用户桌面）

特权服务不在用户会话内，三平台均无法直接投递桌面通知，统一经会话桥：

| 平台 | 桥接机制 | 多会话策略 |
|------|----------|-----------|
| Windows | 服务内 `WTSEnumerateSessions` 找活跃会话 → `WTSQueryUserToken` + `CreateProcessAsUser` 拉起一次性代理进程（自带 AUMID 注册）发 Toast | 每个活跃会话各投递一份 |
| Linux | 遍历 `/run/user/<uid>/`（loginctl 活跃会话），设置各会话 `DBUS_SESSION_BUS_ADDRESS` 调 dbus 通知接口 | 每个活跃会话各投递 |
| macOS | 安装 per-user LaunchAgent 轻量代理（常驻用户会话，监听 unix domain socket；服务发请求→代理调用户通知 API）。代理仅此一职，非 UI 网关 | 每 UID 一个代理，按活跃 UID 分发 |

节流：同类规则 1 分钟内聚合，防通知风暴。所有 Block 类 Verdict 触发通知，正文含进程名 + 规则摘要 + UI 证据指引。

### 8.2 自保护（需求 §6.3 落地）

- 配置/规则/SQLite 文件 ACL：仅 SYSTEM/root/admin 可写；
- 服务恢复策略（Service recovery / `Restart=always` / KeepAlive）；
- 事件流中出现针对自身二进制/配置目录的可疑访问 → 高优先告警（不做内核级防杀，威胁模型 §1.1）。

---

## 9. 错误处理、健康监控与生命周期

### 9.1 事件源健康监控

- 每个事件源维护心跳计数器，健康线程每 10s 检查：计数持续为 0 且自检探测失败（如 ETW session 状态、netlink/auditpipe fd 可读性、BPF map 计数）→ **失效告警（OS 通知 + UI 红色状态）+ 自动重建**（指数退避重建 session/fd/程序）。
- 禁止静默失效：检测能力降级必须让用户知道（fail-open 但大声喊，威胁模型决定不 fail-fast——监控挂了不该挂掉用户系统）。
- 事件源线程 panic 被 `catch_unwind` 捕获，按上表重建。

### 9.2 背压策略

- mpsc 通道容量 65536；慢路径消费速率按 M0 实测校准。
- **PERM 同步线程（Linux）投递审计事件只 `try_send`**：满则丢弃并计数（UI 显示丢弃数），判定永不被审计拖累。
- 丢弃持续增长（持续 >10%）→ 健康告警，提示降低审计粒度。

### 9.3 停机序列（防停机瞬间挂起/误拒）

1. 对所有未决 `FAN_OPEN_PERM/ACCESS_PERM` 统一回 `FAN_ALLOW`（放行，宁放勿卡）；
2. 停止事件源：停 ETW controller session、关 auditpipe/BPF link、删 nft 临时规则与 WFP 过滤器（不留残留阻断）；
3. flush SQLite（含 ConnRegistry 未关闭连接的汇总）；
4. 退出。SIGTERM/SIGINT/服务控制统一走此序列，超时兜底强制退出。

---

## 10. 内存预算核算（约束：RSS ≤ 100MB，需求 §6.4）

| 组成 | 预估 RSS |
|------|----------|
| Rust 基础 + tokio（2–4 线程）+ axum | 15–25MB |
| rusqlite（WAL 缓冲） | 3–8MB |
| ProcTable（~5k 进程）+ ConnRegistry + 通道缓冲 | 3–6MB |
| 平台事件源缓冲（ETW/auditpipe/eBPF ringbuf） | 3–5MB |
| FileObject→Name LRU 缓存（Windows，200k 条 × ~130–145B；拍板记录 10） | 26–29MB |
| estats 差分表与降级门控（Windows，逐轮按 monitored_quads 收敛，≤ 262k 条 × ~30B） | ≤ 8MB |
| 规则快照 + 杂项 | < 2MB |
| **合计** | **~54–83MB**（余量 ≥ 17MB，未超硬约束；下限为约数，实机 RSS 待复验收口） |

> 修订记录（2026-09-20，M4 第二批）：原表"平台事件源 5–15MB"含 FileObject 缓存，
> 实测构成（200k 条 LRU 全量 26–29MB）超出该档。按拍板记录第 10 条拆列单计并
> 维持 200k 容量（探测路径对短命句柄无效，缓存命中是文件路径解析主路径）；
> estats 表随 M4 第二批逐轮收敛机制成立硬封顶（原表述"封顶 262k×16B"未含
> 门控与哈希开销，且收敛前实际无界——评审修正）；合计与余量相应修正。

M0 spike 以实测 RSS 为验收项；超支预案：axum 降级 tiny_http、FileObject 缓存加 LRU 上限。

---

## 11. 里程碑（顺序与验收，不含工期估算）

| 阶段 | 内容 | 验收标准 |
|------|------|----------|
| **M0 spike** | 三平台关键 API 验证：Win=ETW 三 provider 事件速率/RSS、FileObject→Name 关联成功率；Linux=eBPF(aya) 加载（BTF 依赖）与 exec 上下文完整性、fanotify 全盘 PERM mark 的系统吞吐影响、socket cookie 归因可行性；Mac=auditpipe BSM 解析最小原型 | 每平台 spike 报告；§10 内存模型校准；Linux 网络归因与 fanotify mark 范围（全盘 vs 收缩）定稿 |
| **M1 Windows** | 端到端：ETW → 身份表 → 规则（含敏感文件 Audit、持久化告警、DNS 关联）→ 处置 → SQLite → UI + 通知（含会话桥） | 需求 §3 全部规则在 Windows 生效；演示：模拟 harness 外传被阻断且 UI 可查证据 |
| **M2 Linux** | eBPF + fanotify 同步快路径接入（`judge_perm_sync` 首个真实调用方）+ 网络处置 | `.git` 读取/敏感访问被同步拒绝（以实测 errno 为验收，FAN_DENY 通常表现为 EPERM）；网络阈值阻断；停机序列无残留 |
| **M3 macOS** | auditpipe 事件源 + 事后处置链 + 通知 LaunchAgent 桥 | 检测全可见；外传被秒级掐断；文件层仅告警（能力边界内） |
| **M4 加固** | 安装器（Win 安装 exe / install.sh / pkg 含通知代理）、自保护 ACL/恢复策略、文档 | 全新机器一键安装到防护生效 ≤ 5 分钟人工步骤 |

---

## 12. 技术风险清单

| 风险 | 影响 | 缓解 |
|------|------|------|
| fanotify 全盘 PERM mark 拖累全系统 open 吞吐 | 系统性能劣化 | M0 实测；预案：mark 收缩至工作区+harness 目录 |
| ETW 文件事件 FileObject→Name 关联丢失 | 文件规则漏检 | Name 缓存 + unknown 容忍 + 速率监控；M0 统计丢失率 |
| eBPF 加载失败（无 BTF/容器） | Linux 进程/网络检测降级 | proc connector/inet_diag 降级链 + 显式告警短命进程可见性受限 |
| ferrisetw 维护停滞 | Win 事件源返工 | 备选 windows-rs 手写 ETW 消费者 |
| auditpipe BSM 解析自研 | Mac 进度最大不确定项 | M0 原型先行；降级 FSEvents+kinfo_proc |
| 通知会话桥的平台差异 | 通知不可达（保护仍在） | M1 各平台首验；失败兜底=UI 红色横幅 |
| UDP/QUIC 流量归因 | HTTP/3 外传漏检 | 当前 harness 主流 TCP；标注已知盲区，M4 后调研 |
| DoH 下域名关联失效 | 白名单失准 | 域名+IP 双写白名单；UI 提示能力边界 |
| 100MB 预算 | 整体 | §10 核算 + M0 实测 + 降级预案 |

---

## 13. 与需求文档的映射核对表

| 需求条目 | 设计落点 |
|----------|----------|
| §3.1 敏感文件→审计 | 快路径规则 4 + 慢路径 Audit Verdict（§3.3）+ 两级评分联动（§3.3/§6） |
| §3.1 .git 注入面 / 打包→阻断 | 快路径规则 3（Linux 同步 Deny；工作流面 Allow + 引擎 root 首见 Audit，拍板记录 12）/ 慢路径 FileCreate+kill_process（§3.3，含平台阻断实时性差异说明） |
| §3.2 网络兜底阈值 | ConnRegistry 累计 + 白名单（§3.3）+ `conns`/`dns_map` 表（§4）+ 三平台 DNS 观测点（§5） |
| §3.3 身份矩阵/导出封堵 | `tool_exempt`（exe × 路径）+ `[commands].blocked`（§3.2/§3.3/§6） |
| §3.4 进程身份表/补扫描/短命进程 | ProcTable + 启动补扫描（§3.2）；eBPF 保短命进程可见（§5.2） |
| §3.5 持久化告警 | `RawEvent::Persistence` + 三平台持久化监控（§5.1–5.3） |
| §4 响应动作 | Enforcer（§2.1）+ 通知会话桥（§8.1）+ 白名单短路（§3.3） |
| §5 平台能力阶梯 | §5 平台适配层（Linux 同步 / Win 近实时 / Mac 事后） |
| §6.1 进程模型 | 单特权服务 + 系统服务宿主（§2、§5 各平台行） |
| §6.2 UI 安全 | §7 鉴权设计 |
| §6.3 自保护 | §8.2 + §9 健康监控 |
| §6.4 资源约束 | §10 预算核算 |
| §7 存储/配置 | §4（含追加写拍板）、§6 |

---

## 附：设计拍板记录（需求未定或与需求字面有偏差处）

1. Linux 进程事件采用 **eBPF（aya）首选 + proc connector 备选降级**（与需求 §5"eBPF"一致；降级模式显式告警可见性受限）。
2. 规则引擎**快慢双路径**：同步拒绝仅存在于 Linux fanotify PERM；`FAN_CREATE`（产物创建）与三平台其余检测均为**事后处置**语义。
3. 豁免矩阵显式配置化（`tool_exempt`：exe × 路径模式），归档工具不入豁免表。
4. 前端**无构建静态资源**（无 node 工具链依赖）。
5. 里程碑 **Windows 优先**（M1 主平台先获防护），Linux M2 引入同步快路径，macOS M3。
6. **追加写 vs 滚动清理**的矛盾拍板：运行期触发器禁改、唯一 DELETE 来自每日清理任务（§4；2026-09-20 补：Web UI 手动清空经写入线程同路径执行，仍满足"唯一删除路径"）。
7. 通知经**会话桥**投递（Win 一次性代理 / Linux 会话 bus 遍历 / Mac per-user LaunchAgent）。
8. token 经 query 传递仅限 SSE 端点（EventSource 无 header 能力），其余 API 仅 Bearer header。
9. **IPv6 断连接降级**（M4 实测，2026-09-19）：§5.1 原文的 `SetTcp6Entry` 为**文档幻影**——Windows SDK 头文件（iphlpapi.h/netioapi.h 及整个 um/）无声明、iphlpapi.lib 无符号、iphlpapi.dll 导出表无此名（Win10 26100 全量导出枚举核对，仅 `SetTcpEntry`/`SetPerTcp(6)ConnectionEStats` 存在），用户态文档化 API 无法实现 v6 连接级断开。拍板：v6 连接处置由引擎侧 Kill（socket 随进程关闭）+ 封 IP（netsh/WFP 均支持 v6）兜底；`MIB_TCP6ROW` 行构造纯函数与单测保留（锚定 MIB 布局），供平台补齐或 NSI 未公开接口评估——后者超出"文档化用户态 API"设计边界，暂不采用。
10. **FileObject 缓存容量 200k 维持 + §10 预算表修订**（M4 第二批，2026-09-20）：M1 沿袭的 200k 全量约 26–29MB（条目 48B slab + ~16B 索引 + NT 路径字符串均值 ~80B），超原 §10"平台事件源 5–15MB"档。拍板**不核减容量、修订预算表拆列单计**，依据：① M4 复验定案——句柄探测对短命句柄无效（ETW 投递延迟 > 句柄存活期），Name 缓存命中是文件路径解析的唯一现实主路径，容量直接决定 burst（tar 解包/大仓 git）下的 unknown 率；② 核减至 64k 在 monorepo 规模 burst 下将重演 M1"整表清空后 Read/Write 全 unknown"教训，且当前无实测 unknown 率数据支撑核减的安全性；③ 100MB 硬约束仍满足（修订后合计 ~54–83MB，余量 ≥ 17MB；estats 表经 M4 第二批逐轮收敛机制成立硬封顶）。实机 RSS 复验列入 M4 第二批复验清单。
11. **场景 A 备选通道落地 Security 4663（opt-in）**（M4 第二批，2026-09-20）：复验定案句柄探测对短命句柄无效后评估两条消费路径——① ETW 直连 Security-Auditing provider（{54849625-5478-4994-A5BA-3E3B0328C30D}）为 undocumented 技巧（仅 SYSTEM 身份、搭 OS 的 EventLog-Security 会话，krabsetw 示例实证；MS Learn 无消费文档），不作产品主路径；② 采用文档化的 **EvtSubscribe push 订阅**（winevt）：Security 通道 + XPath 过滤 EventID=4663，管理员/Event Log Readers 权限即可，实时回调。启用端（auditpol 开 File System 成功审计 + 目标目录 Everyone 审计 ACE，SACL 写入需 SeSecurityPrivilege）侵入系统级审计策略且 SACL 命中产生 Security 日志增长——拍板**默认关闭、显式 opt-in**：`enable-file-audit <目录>` / `disable-file-audit <目录>` 子命令管理生命周期（auditpol 子类别用 GUID 形式免本地化差异），事件经 FileOpen 复用引擎判定链（含监控树早过滤与 watch_paths 分量边界前缀过滤）。不进"一键安装"默认路径，M4 验收"≤5 分钟人工步骤"不受累。
12. **git-dir 规则分面：注入面阻断、工作流面放行**（2026-09-20，实机误杀定案）：原实现按需求 §3.1 旧文"读 .git 阻断"扩展为读写一律拒，其依据是"harness 无正当直写 .git 场景、写 .git 走 git.exe 豁免分支"的假设——ZCode 实机打破该假设：ETW 观测到 ZCode.exe 名下进程创建 `.git/objects/**` 与 `HEAD.lock`，正常 git 工作流被反复 Kill（**2026-09-20 后续调查修正**：ZCode 的 git 层静态证据为 spawn 外部 git.exe 形态（`ZCODE_GIT_BINARY`/dugite 风格调用，无进程内 git 库组件）；当日同时存在豁免失效（见拍板 13 前置防线）与 pid 复用冒名（M4 待修 ①）两个混杂因素，"进程内直写"未定谳——但分面结论不受影响：无论 IO 来自 git.exe 冒名还是进程内路径，按路径分面都是正确对策）。拍板（项目所有者）：`.git` 按**路径 × 读写方向**分面——**注入面**（`hooks/**` 读写；`config`/`config.lock` 写）维持 `git_dir_action` 默认 Block，依据 hook 注入与配置篡改（`core.fsmonitor`/`pager` 等执行注入点）是持久化/凭据劫持向量、正常工作流不触碰（已知 tradeoff：harness 内 `git init`/`clone` 写 `hooks/*.sample`、husky 类工具装 hook 会被拦，低频且方向保守，可配置解除）；**工作流面**（objects/refs/logs/HEAD/index/各类锁文件等读写）放行——进程内 git 库与 harness 任意代码同址不可身份区分，窃取面（读 .git 后外传）与"读工作区源码"同风险层级，由网络层阈值 + 导出命令封堵 + 归档产物三道兜底。引擎对工作流面按监控根首见补一条 Audit 取证线索（防 status/diff 高频读写刷库）。需求 §3.1/§2 已同步修订。
13. **git 注入面处置去杀化（配置化，缺省不杀）+ git 豁免编译期兜底**（2026-09-20，项目所有者拍板）：注入面命中 Block 判定时**默认不再杀进程**，新增 `[files] git_dir_kill`（缺省 false）交给用户决定是否升级——依据：Windows ETW 事后语义下杀仅止损（实测被"阻断"的 objects 文件实际已落盘），且打包封堵与网络阈值两重兜底仍在，杀进程对正常工作流的误伤代价（实机：ZCode 被杀重启）高于其止损收益。同批落地**豁免兜底**：`RulesSnapshot::compile` 在 tool_exempt 配置缺失 git 条目时注入内置 `.git/**` 豁免并告警（依据当日实测教训——运行实例豁免表为空而配置文件有段，文件与内存软状态可能分裂，git 豁免是需求 §3.3 明文行为、空表必属异常，不允许静默失去；用户自定义 git 条目存在时以用户为准）。附带修复：`allow_paths` 多段目录模式（如 `.git/objects/**`）旧实现在组件级 eq 匹配下静默失效，改为段序列滑窗匹配。测试补齐三层盲区：单测（旧版配置缺字段/缺豁免段的解析与兜底回归）、engine 门控测试、m1-demo 实机正向豁免场景（树内真 git.exe status/commit、绝对路径 git.exe、进程内 IO 形态模拟）。
