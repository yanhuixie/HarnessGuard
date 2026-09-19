//! Linux 平台适配（技术设计 §5.2）。
//!
//! 计划落地的能力（实际代码随第四步/M2 预写进入，全部
//! `#[cfg(target_os = "linux")]` 门控）：
//! - 进程事件：aya eBPF 挂 tracepoint sched_process_exec/exit/fork；
//!   降级链 proc connector（短命进程可见性受限，显式告警）；
//! - 文件事件 + 同步阻断：fanotify FAN_OPEN_PERM/FAN_ACCESS_PERM →
//!   judge_perm_sync → 同步写回 FAN_ALLOW/FAN_DENY（PERM 位在 mark mask）；
//!   FAN_CREATE/FAN_CLOSE_WRITE 为通知类事件（FileCreate 信号）；
//! - 网络归因：eBPF 挂 tcp_sendmsg/udp 按 socket cookie 计数；降级链
//!   inet_diag 周期采样 → nftables accounting；
//! - DNS：eBPF/libpcap 抓 UDP:53；
//! - 持久化：inotify 监控 /etc/cron*、systemd unit 目录；
//! - 处置：nft CLI 子进程（断连接/封 IP）；
//! - 停机序列：未决 PERM 全部回 FAN_ALLOW（技术设计 §9.3）。
//!
// 未编译验证：本 crate 实际 Linux 实现待 Linux 环境确认；当前为骨架占位，
// Windows 构建只编译下方跨平台占位内容。

pub fn describe() -> &'static str {
    "hg-plat-linux：eBPF + fanotify 同步阻断 + nft 处置（M2，仅编写不编译）"
}
