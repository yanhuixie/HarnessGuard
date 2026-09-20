//! HarnessGuard 领域模型（技术设计 §3）。
//!
//! 纯数据 crate：无平台 API、无 IO、无业务逻辑。
//! 三平台事件源把系统事件翻译为此处的 [`RawEvent`]，核心引擎据此判定。

use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use serde::Serialize;

/// 进程 ID。Windows PID 为 u32；Linux/macOS pid_t 恒为正值，均可容纳于 u32。
pub type Pid = u32;

/// 统一时基：单调毫秒（自服务启动，防系统时钟回拨），落库时换算 UTC 毫秒。
/// 各平台源事件时基（ETW QPC / eBPF ktime / BSM 时间戳）在事件源层完成对齐（技术设计 §4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Timestamp(pub u64);

/// 进程启动时刻（平台时基：Windows=进程创建 FILETIME；Linux=/proc stat 第 22 字段；
/// macOS=kinfo_proc p_starttime）。全程随 pid 携带，pid + start_time 双匹配防 pid 复用错判。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StartTime(pub u64);

/// 连接标识（平台 64 位标识：Windows=ETW 连接上下文；Linux=socket cookie）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct ConnId(pub u64);

/// 特征库命中的 harness 名（如 "claude-code"），作为该进程树的监控根标识。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct HarnessId(pub String);

/// 事件信封：统一时基包裹平台事件，经 mpsc 通道进入核心引擎。
#[derive(Debug, Clone, Serialize)]
pub struct Envelope {
    pub ts: Timestamp,
    pub event: RawEvent,
}

impl Envelope {
    pub fn new(ts: Timestamp, event: RawEvent) -> Self {
        Self { ts, event }
    }
}

/// 统一事件模型（技术设计 §3.1）。
#[derive(Debug, Clone, Serialize)]
pub enum RawEvent {
    /// 进程启动（携带完整身份判定所需字段）。
    Exec {
        pid: Pid,
        ppid: Pid,
        start_time: StartTime,
        exe: PathBuf,
        cmdline: Vec<OsString>,
        cwd: PathBuf,
    },
    /// 进程退出（身份表据此清理；pid + start_time 双匹配防误删复用 pid 的新进程）。
    Exit { pid: Pid, start_time: StartTime },
    /// 文件打开。Linux fanotify PERM 事件的同步判定对象；其余平台为事后观测。
    FileOpen {
        pid: Pid,
        start_time: StartTime,
        path: PathBuf,
        access: Access,
    },
    /// 文件创建（归档产物判定信号；三平台均为事后处置，无同步拒绝语义，技术设计 §3.1）。
    FileCreate {
        pid: Pid,
        start_time: StartTime,
        path: PathBuf,
    },
    /// 连接建立。
    ConnOpen {
        pid: Pid,
        start_time: StartTime,
        conn_id: ConnId,
        proto: Proto,
        local: SocketAddr,
        remote: SocketAddr,
    },
    /// 上行字节增量；归因靠核心引擎 ConnRegistry 内存映射（不可能依赖 SQLite）。
    ConnTx {
        conn_id: ConnId,
        bytes_out_delta: u64,
    },
    /// 连接关闭（ConnRegistry 汇总落库）。
    ConnClose { conn_id: ConnId },
    /// DNS 查询与应答（域名→IP 关联，需求 §3.2）。
    DnsQuery {
        pid: Pid,
        qname: String,
        answers: Vec<IpAddr>,
    },
    /// 持久化行为（高可疑告警，审计不阻断，需求 §3.5）。
    Persistence {
        pid: Pid,
        kind: PersistenceKind,
        detail: String,
    },
}

/// 文件访问方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Access {
    Read,
    Write,
}

/// 传输层协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Proto {
    Tcp,
    Udp,
}

/// 持久化手段分类（需求 §3.5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PersistenceKind {
    /// Windows 计划任务（Task Scheduler）。
    SchedTask,
    Cron,
    /// macOS LaunchAgent / LaunchDaemon。
    LaunchAgent,
    /// Windows 注册表 Run/RunOnce 自启动键。
    RunKey,
}

/// 进程身份（技术设计 §3.2；ProcTable 的表项）。
#[derive(Debug, Clone, Serialize)]
pub struct Identity {
    pub pid: Pid,
    pub start_time: StartTime,
    pub exe: PathBuf,
    pub cmdline: Vec<OsString>,
    /// 所属 harness 监控根；None = 非监控进程（不干预，技术设计 §3.3 快路径规则 1）。
    pub harness_root: Option<HarnessId>,
    /// 命中 tool_exempt 表的版本控制工具名（需求 §3.3 身份矩阵豁免）。
    /// 豁免靠"工具 × 路径"矩阵分支，不脱离进程树：harness_root 仍保留。
    pub tool_exempt: Option<String>,
}

/// TCP 连接四元组（处置 [`hg_platform::Enforcer::drop_tcp`] 用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TcpQuad {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// 判定动作（技术设计 §3.3：快慢路径统一 action 命名）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Action {
    Block,
    /// 放行但落审计记录（如敏感文件读取，需求 §3.1）。
    Audit,
    Allow,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Block => "block",
            Action::Audit => "audit",
            Action::Allow => "allow",
        }
    }
}

/// 内置规则标识（配置只改动作，规则枚举固定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RuleId(pub &'static str);

/// 证据链（JSON 落库，UI 可跳转展示——满足"审计取证"要求，技术设计 §3.3）。
#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub summary: String,
    pub detail: serde_json::Value,
}

/// 判定结果：规则 + 动作 + 证据。
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub rule_id: RuleId,
    pub action: Action,
    pub evidence: Evidence,
}
