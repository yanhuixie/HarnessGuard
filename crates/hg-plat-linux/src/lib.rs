//! Linux 平台适配（技术设计 §5.2 + §9.3）。实现随 M2 落入，全部
//! `#[cfg(target_os = "linux")]` 门控；Windows 上 `cargo check --workspace`
//! 只编译下方跨平台占位。
//!
//! 模块（均仅在 Linux 目标编译）：
//! - [`fanotify`]：同步快路径——FAN_OPEN_PERM/FAN_ACCESS_PERM → judge_perm_sync →
//!   同步写回 FAN_ALLOW/FAN_DENY；FAN_CREATE/FAN_CLOSE_WRITE → FileCreate（事后）
//! - [`ebpf`]：aya 加载 sched_process_exec/fork/exit tracepoint（短命进程不丢）+
//!   tcp_sendmsg socket cookie 上行计数（备选降级链见文件头）
//! - [`dns`]：AF_PACKET 抓 UDP:53（明文 DNS；DoH 退化按 IP，需求 §1.2）
//! - [`persist`]：inotify 监控 cron/systemd unit 目录
//! - [`enforcer`]：kill（/proc start_time 双校验）/ ss -K 掐连接 / nft set 封 IP
//! - [`shutdown`]：停机序列（未决 PERM 全部 FAN_ALLOW，不留残留阻断，§9.3）
//!
//! BPF 内核侧源码：`bpf/harnessguard.bpf.c`（Linux 环境经 clang -target bpfel
//! 编译为 .o 后由 aya 加载；见该文件头）。

#[cfg(target_os = "linux")]
pub mod dns;
#[cfg(target_os = "linux")]
pub mod ebpf;
#[cfg(target_os = "linux")]
pub mod enforcer;
#[cfg(target_os = "linux")]
pub mod fanotify;
#[cfg(target_os = "linux")]
pub mod persist;
#[cfg(target_os = "linux")]
pub mod shutdown;

pub fn describe() -> &'static str {
    "hg-plat-linux：eBPF + fanotify 同步阻断 + ss/nft 处置（M2，仅编写未编译）"
}
