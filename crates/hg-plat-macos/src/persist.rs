// 未编译验证：待 macOS 环境确认（技术任务硬约束 3/4）。
//! 持久化检测（技术设计 §5.3）：监控 LaunchAgents / LaunchDaemons 目录。
//! 设计原文为 FSEvents；M3 首版用快照轮询（与 Linux 降级链同构），FSEvents FFI
//! （FSEventStreamCreate + CFRunLoop）为 M3 验证期升级项——偏差显式登记。
//! 归因发起进程：目录变更无 pid，审计 pid=0（与 Linux inotify 同口径）。

use std::time::Duration;

use hg_model::{Envelope, PersistenceKind, RawEvent, Timestamp};
use tokio::sync::mpsc;

const WATCH_DIRS: &[&str] = &["/Library/LaunchAgents", "/Library/LaunchDaemons"];

const POLL: Duration = Duration::from_secs(10);

pub fn spawn_persist_watch(tx: mpsc::Sender<Envelope>, base: std::time::Instant) {
    std::thread::spawn(move || {
        let snap = |dirs: &[&str]| -> Vec<(String, u64)> {
            let mut out = Vec::new();
            for d in dirs {
                if let Ok(rd) = std::fs::read_dir(d) {
                    for e in rd.flatten() {
                        let mtime = e
                            .metadata()
                            .and_then(|m| m.modified())
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        out.push((format!("{d}/{}", e.file_name().to_string_lossy()), mtime));
                    }
                }
            }
            out
        };
        let mut prev = snap(WATCH_DIRS);
        loop {
            std::thread::sleep(POLL);
            let cur = snap(WATCH_DIRS);
            for (path, mtime) in &cur {
                let is_new = !prev.iter().any(|(p, _)| p == path);
                let is_modified = prev.iter().any(|(p, m)| p == path && m != mtime);
                if is_new || is_modified {
                    let what = if is_new { "新增" } else { "修改" };
                    tracing::warn!("[持久化] LaunchAgent/Daemon {what}：{path}");
                    let _ = tx.try_send(Envelope::new(
                        Timestamp(base.elapsed().as_millis() as u64),
                        RawEvent::Persistence {
                            pid: 0,
                            kind: PersistenceKind::LaunchAgent,
                            detail: format!("{what} {path}"),
                        },
                    ));
                }
            }
            prev = cur;
        }
    });
}
