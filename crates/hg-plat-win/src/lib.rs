//! Windows 平台适配（技术设计 §5.1，选型按 M0 spike 报告校准）。
//!
//! 模块：
//! - [`etw_source`]：ETW 事件源（进程/文件/网络 kernel flags + Dns-Client GUID）
//! - [`enforcer`]：杀进程 / 断连接 / 临时封 IP
//! - [`notify`]：OS 通知会话桥（WTS + CreateProcessAsUser 一次性 Toast 代理）
//! - [`runkey`]：注册表 RunKey/RunOnce 持久化轮询（M1 范围）
//! - [`bootstrap`]：启动补扫描（Toolhelp32 快照）
//! - [`ntpath`]：NT 设备路径转盘符路径
//! - [`peb`]：PEB 命令行读取（内核 ETW 无命令行的降级链）
//! - [`lru`]：FileObject 缓存的 O(1) LRU 封顶（M4 场景 A 缓解）
//! - [`probe`]：unknown Create 事件的同对象句柄探测补名（M4 场景 A 缓解）
//! - [`estats`]：GetPerTcpConnectionEStats 轮询补连接字节计数（M4 场景 C 替代路径）
//! - [`wfp`]：用户态 WFP 临时封禁（M4 偏差归位，netsh 为降级兜底）

pub mod bootstrap;
pub mod enforcer;
pub mod estats;
pub mod etw_source;
pub mod lru;
pub mod ntpath;
pub mod notify;
pub mod peb;
pub mod probe;
pub mod runkey;
pub mod wfp;

pub use enforcer::WinEnforcer;
pub use etw_source::{EtwInner, EtwSource, SourceStats};
pub use notify::WinNotifier;

pub fn describe() -> &'static str {
    "hg-plat-win：ETW 事件源 + 杀进程/断连接/封 IP 处置（M1）"
}
