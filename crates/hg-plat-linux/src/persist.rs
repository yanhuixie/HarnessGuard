// 未编译验证：待 Linux 环境确认（技术任务硬约束 3）。
//! 持久化检测（技术设计 §5.2）：inotify 监控 cron 与 systemd unit 目录。
//! 归因发起进程：inotify 事件无 pid——审计记录 pid=0，M2 校准项（可配合
//! fanotify 已见的进程活动做启发式关联，或 auditd TASK_ORDER 通道）。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use hg_model::{Envelope, PersistenceKind, RawEvent, Timestamp};
use tokio::sync::mpsc;

const WATCH_DIRS: &[&str] = &[
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
    "/etc/systemd/system",
    "/root/.config/systemd/user",
];

const POLL: Duration = Duration::from_secs(2);

pub fn spawn_persist_watch(tx: mpsc::Sender<Envelope>, base: std::time::Instant) {
    std::thread::spawn(move || {
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            tracing::error!("inotify_init1 失败——持久化检测降级为轮询快照对比");
            run_poll_fallback(tx, base);
            return;
        }
        let mut wd_map: HashMap<i32, &str> = HashMap::new();
        for dir in WATCH_DIRS {
            let wd = unsafe {
                libc::inotify_add_watch(
                    fd,
                    format!("{dir}\0").as_ptr().cast(),
                    libc::IN_CREATE
                        | libc::IN_MOVED_TO
                        | libc::IN_CLOSE_WRITE
                        | libc::IN_DELETE
                        | libc::IN_MODIFY,
                )
            };
            if wd >= 0 {
                wd_map.insert(wd, dir);
            }
        }
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                std::thread::sleep(POLL);
                continue;
            }
            let mut off = 0usize;
            while off + std::mem::size_of::<libc::inotify_event>() <= n as usize {
                let ev = unsafe { &*(buf.as_ptr().add(off).cast::<libc::inotify_event>()) };
                off += std::mem::size_of::<libc::inotify_event>() + ev.len as usize;
                let name = String::from_utf8_lossy(unsafe {
                    std::slice::from_raw_parts(
                        (ev as *const libc::inotify_event as *const u8)
                            .add(std::mem::size_of::<libc::inotify_event>()),
                        ev.len as usize,
                    )
                })
                .trim_end_matches('\0')
                .to_string();
                let Some(dir) = wd_map.get(&ev.wd) else {
                    continue;
                };
                let kind = if dir.contains("cron") {
                    PersistenceKind::Cron
                } else {
                    PersistenceKind::LaunchAgent
                };
                tracing::warn!(
                    "[持久化] {} 变更：{dir}/{name}",
                    if kind == PersistenceKind::Cron {
                        "cron"
                    } else {
                        "systemd unit"
                    }
                );
                let _ = tx.try_send(Envelope::new(
                    Timestamp(base.elapsed().as_millis() as u64),
                    RawEvent::Persistence {
                        pid: 0,
                        kind,
                        detail: format!("{dir}/{name} mask={:#x}", ev.mask),
                    },
                ));
            }
        }
    });
}

/// inotify 不可用时的降级：目录快照对比（粗粒度，显式告警已打印）。
fn run_poll_fallback(tx: mpsc::Sender<Envelope>, base: std::time::Instant) {
    let snap = |dirs: &[&str]| -> Vec<String> {
        let mut out = Vec::new();
        for d in dirs {
            if let Ok(rd) = std::fs::read_dir(d) {
                for e in rd.flatten() {
                    out.push(format!("{d}/{}", e.file_name().to_string_lossy()));
                }
            }
        }
        out
    };
    let mut prev = snap(WATCH_DIRS);
    loop {
        std::thread::sleep(Duration::from_secs(30));
        let cur = snap(WATCH_DIRS);
        for c in &cur {
            if !prev.contains(c) {
                let kind = if c.contains("cron") {
                    PersistenceKind::Cron
                } else {
                    PersistenceKind::LaunchAgent
                };
                let _ = tx.try_send(Envelope::new(
                    Timestamp(base.elapsed().as_millis() as u64),
                    RawEvent::Persistence {
                        pid: 0,
                        kind,
                        detail: format!("新增 {c}"),
                    },
                ));
            }
        }
        prev = cur;
    }
}

/// 供停机序列持有（inotify fd 由线程独占，进程退出即回收；§9.3 无未决状态）。
pub struct PersistWatchHandle;

impl PersistWatchHandle {
    pub fn spawn(tx: mpsc::Sender<Envelope>, base: std::time::Instant) -> Arc<Self> {
        spawn_persist_watch(tx, base);
        Arc::new(Self)
    }
}
