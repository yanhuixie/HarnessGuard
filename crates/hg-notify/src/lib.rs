//! OS 通知封装 + 三平台会话桥（技术设计 §8.1）。
//!
//! 特权服务不在用户会话内，三平台均无法直接投递桌面通知，统一经会话桥：
//! - Windows：WTSEnumerateSessions 找活跃会话 → WTSQueryUserToken +
//!   CreateProcessAsUser 拉起一次性 Toast 代理，每会话各投一份（M1 接入）；
//! - Linux：遍历 /run/user/<uid>/ 活跃会话，以各会话 DBUS_SESSION_BUS_ADDRESS
//!   投递 notify-send；
//! - macOS：per-user LaunchAgent 轻量代理（unix domain socket 收请求 → 用户会话
//!   发通知），每 UID 一个代理。
//!
//! 节流：同类规则 1 分钟内聚合，防通知风暴。所有 Block 类 Verdict 触发通知，
//! 正文含进程名 + 规则摘要 + UI 证据指引。失败兜底 = UI 红色横幅（保护仍在）。

pub fn describe() -> &'static str {
    "hg-notify：OS 通知会话桥（M1 接入 Windows WTS + CreateProcessAsUser）"
}
