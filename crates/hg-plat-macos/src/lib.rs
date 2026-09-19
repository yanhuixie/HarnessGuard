//! macOS 平台适配（技术设计 §5.3 + 需求 §5 能力阶梯：检测全可见 + 事后秒级处置，
//! 无实时文件阻断）。实现随 M3 落入，全部 `#[cfg(target_os = "macos")]` 门控；
//! Windows 上 `cargo check --workspace` 只编译下方跨平台占位。
//!
//! 双架构注意（技术任务硬约束 4）：Intel（x86_64）与 Apple Silicon（aarch64）
//! 发布各自原生二进制；auditpipe/BSM 与 libpcap 的 FFI 均为指针宽度无关的
//! C ABI（结构体偏移不随架构漂移处已在注释标注），BPF 设备名 bpf* 两架构一致。
//!
//! 模块（均仅在 macOS 目标编译）：
//! - [`auditpipe`]：/dev/auditpipe FFI（preselect ioctl + BSM 记录/token 解析）
//! - [`pcap`]：libpcap FFI（BPF 设备）网络五元组累计 + UDP:53 DNS
//! - [`enforcer`]：kill / tcpdrop 四元组掐连接 / pfctl 封 IP
//! - [`notify_agent`]：per-user LaunchAgent 通知桥（unix domain socket 客户端）
//! - [`persist`]：LaunchAgents/Daemons 目录监控（M3 首版为快照轮询，FSEvents FFI
//!   为升级项——偏差显式登记，见文件头）

#[cfg(target_os = "macos")]
pub mod auditpipe;
#[cfg(target_os = "macos")]
pub mod enforcer;
#[cfg(target_os = "macos")]
pub mod notify_agent;
#[cfg(target_os = "macos")]
pub mod pcap;
#[cfg(target_os = "macos")]
pub mod persist;

pub fn describe() -> &'static str {
    "hg-plat-macos：auditpipe + libpcap + tcpdrop/pf 处置（M3，仅编写未编译）"
}
