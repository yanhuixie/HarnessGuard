//! 平台抽象（技术设计 §2.1）：事件源与处置动作 trait。
//!
//! 平台 crate（hg-plat-win / hg-plat-linux / hg-plat-macos）实现这两个 trait，
//! 把系统 API 翻译为 hg-model 的统一事件模型；核心引擎只面向 trait 编程。
//! 本 crate 是依赖方向的叶子：仅依赖 hg-model，被各平台 crate 引用（技术设计 §2）。

use std::net::IpAddr;
use std::time::Duration;

use anyhow::Result;
use hg_model::{Envelope, Pid, StartTime, TcpQuad};
use tokio::sync::mpsc;

/// 平台事件源：在专属线程内阻塞读系统 API，翻译为 Envelope 推入通道。
///
/// trait 本身不 async——fanotify/auditpipe/eBPF ringbuf 均以平台线程阻塞/轮询驱动
/// （技术设计 §2.1）。通道满时的投递策略由实现方按快慢路径约束决定：
/// Linux PERM 同步线程只许 `try_send`（满则丢弃并计数，绝不阻塞，技术设计 §9.2）。
pub trait EventSource: Send {
    /// 事件源名称（健康监控、日志、UI 状态展示用）。
    fn name(&self) -> &'static str;

    /// 运行至进程结束；正常情况下永不返回（Infallible）。
    /// 实现内部 panic 由健康监控 `catch_unwind` 捕获并按退避策略重建（技术设计 §9.1）。
    fn run(self, tx: mpsc::Sender<Envelope>) -> std::convert::Infallible;
}

/// 处置动作（全部在异步路径调用，无同步预算约束，技术设计 §2.1）。
pub trait Enforcer: Send + Sync {
    /// 杀进程；实现必须校验 start_time 防 pid 复用误杀。
    fn kill_process(&self, pid: Pid, start_time: StartTime) -> Result<()>;

    /// 重置单条 TCP 连接。
    fn drop_tcp(&self, quad: TcpQuad) -> Result<()>;

    /// 防火墙层临时封禁目标 IP（TTL 过期自动解封）。
    fn block_endpoint_temporary(&self, ip: IpAddr, ttl: Duration) -> Result<()>;
}
