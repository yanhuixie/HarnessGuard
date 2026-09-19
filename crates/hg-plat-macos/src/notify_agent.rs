// 未编译验证：待 macOS 环境确认（技术任务硬约束 3/4）。
//! 通知会话桥（技术设计 §8.1）：per-user LaunchAgent 轻量代理监听 unix domain
//! socket，特权 LaunchDaemon（本服务）发请求 → 代理在用户会话调 osascript 通知。
//! 代理仅此一职，非 UI 网关。每个活跃 UID 一个代理。
//!
//! 服务侧（本文件）：/var/tmp/harnessguard-notify-<uid>.sock 客户端，
//! 协议 = 一行 JSON（{"title":..,"body":..}），代理回 ACK 后关闭。
//! 代理本体与 LaunchAgent plist 由安装器落盘（M4 install.pkg），模板见文件尾注释。

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

pub const NOTIFY_TITLE_PREFIX: &str = "[HarnessGuard]";

/// 向指定 uid 的通知代理投递（失败返回 Err——由调用方计数，UI 红色横幅兜底）。
pub fn notify_user(uid: u32, title: &str, body: &str) -> anyhow::Result<()> {
    let path = format!("/var/tmp/harnessguard-notify-{uid}.sock");
    let mut stream = UnixStream::connect(&path)?;
    let payload = serde_json_lite::escape(title, body);
    stream.write_all(payload.as_bytes())?;
    stream.write_all(b"\n")?;
    let ack = BufReader::new(&mut stream).lines().next().transpose()?;
    match ack.as_deref() {
        Some("ACK") => Ok(()),
        other => anyhow::bail!("通知代理未确认（{other:?}）"),
    }
}

// 极简 JSON 转义（macOS 侧不引 serde_json，减少依赖面；M3 可换）
mod serde_json_lite {
    pub fn escape(title: &str, body: &str) -> String {
        format!("{{\"title\":\"{}\",\"body\":\"{}\"}}", esc(title), esc(body))
    }
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
    }
}

// ---- 安装器物料模板（M4 落盘）----
//
// /Library/LaunchAgents/com.harnessguard.notify.plist（per-user，LaunchAgents）：
//   Label: com.harnessguard.notify
//   ProgramArguments: [/usr/local/libexec/harnessguard-notify-agent]
//   RunAtLoad: true; KeepAlive: true
//
// 代理逻辑（独立小二进制，M4）：
//   bind /var/tmp/harnessguard-notify-$UID.sock（0600）
//   loop { accept; 读一行 JSON; osascript -e 'display notification BODY with title TITLE'; ACK }
//
// 活跃 UID 发现：`stat -f %u /dev/console` + `who` 解析（每 UID 一个代理按需拉起）。
