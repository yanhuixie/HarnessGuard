// 未编译验证：待 Linux 环境确认（技术任务硬约束 3）。
//! fanotify 同步快路径（技术设计 §1.2 原则 1 + §5.2）：
//! - `fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY|O_LARGEFILE)`；
//! - PERM 位（`FAN_OPEN_PERM | FAN_ACCESS_PERM`）在 **mark mask**（不在 init 第二参）；
//! - 权限事件在专属线程同步判定：`judge_perm_sync`（微秒预算，纯函数无 IO）→
//!   写回 `fanotify_response{ FAN_ALLOW | FAN_DENY }`；
//! - 审计投递只 `try_send`（通道满丢弃计数，绝不阻塞——否则全系统 open 卡死，§9.2）；
//! - `FAN_CREATE | FAN_CLOSE_WRITE` 为通知类事件 → FileCreate（归档产物信号，事后处置）。
//!
//! 路径获取：legacy fd 模式（事件携带 fd）→ `readlink /proc/self/fd/<n>`。
//! 停机：drain 未决权限事件统一 FAN_ALLOW（§9.3，宁放勿卡）。

use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;

use hg_core::proc_table::ProcTable;
use hg_core::rules::{judge_perm_sync, RulesSnapshot};
use hg_model::{Access, Envelope, Pid, RawEvent, StartTime, Timestamp};
use tokio::sync::mpsc;

use arc_swap::ArcSwap;

// libc 常量（glibc 头文件值；libc crate 未全量导出 fanotify 常量）
const FAN_CLASS_CONTENT: libc::c_int = 0x0000_0004;
// 阻塞读（评审修正：非阻塞+2ms 轮询与同步判定微秒预算矛盾；停机经 close(fd) 解除阻塞）
const FAN_CLOEXEC: libc::c_int = 0x0000_0001;
const FAN_MARK_ADD: libc::c_uint = 0x0000_0001;
const FAN_MARK_FILESYSTEM: libc::c_uint = 0x0000_0100;
const FAN_OPEN_PERM: u64 = 0x0001_0000;
const FAN_ACCESS_PERM: u64 = 0x0002_0000;
const FAN_CREATE: u64 = 0x0000_0100;
const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
const FAN_ALLOW: libc::c_int = 0x01;
const FAN_DENY: libc::c_int = 0x02;
const O_RDONLY_LARGEFILE: libc::c_int = libc::O_RDONLY | libc::O_LARGEFILE;

#[repr(C)]
#[derive(Default)]
struct FanotifyEventMetadata {
    event_len: libc::c_uint,
    vers: libc::c_uchar,
    reserved: libc::c_uchar,
    metadata_len: libc::c_ushort,
    mask: u64,
    fd: libc::c_int,
    pid: libc::c_int,
}

#[repr(C)]
struct FanotifyResponse {
    fd: libc::c_int,
    response: libc::c_int,
}

/// fanotify 事件源（含同步判定线程）。持有者负责停机序列（见 [`ShutdownHandle`]）。
pub struct FanotifySource {
    fd: libc::c_int,
    procs: Arc<ProcTable>,
    rules: Arc<ArcSwap<RulesSnapshot>>,
    tx: mpsc::Sender<Envelope>,
    base: std::time::Instant,
    pub stats: Arc<FanotifyStats>,
}

#[derive(Default)]
pub struct FanotifyStats {
    pub perm_events: AtomicU64,
    pub denied: AtomicU64,
    pub audit_dropped: AtomicU64,
}

impl FanotifySource {
    /// 初始化并打全盘 filesystem mark。需要 root（CAP_SYS_ADMIN）。
    pub fn new(
        procs: Arc<ProcTable>,
        rules: Arc<ArcSwap<RulesSnapshot>>,
        tx: mpsc::Sender<Envelope>,
    ) -> anyhow::Result<Self> {
        let fd =
            unsafe { libc::fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDONLY_LARGEFILE) };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "fanotify_init 失败 errno={}（需 root）",
                errno()
            ));
        }
        // 全盘 mark；M0/Linux 校准项：吞吐不可接受时收缩到工作区+harness 目录（§5.2 风险表）
        let mask = FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_CREATE | FAN_CLOSE_WRITE;
        let rc = unsafe {
            libc::fanotify_mark(
                fd,
                FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                mask,
                libc::AT_FDCWD,
                b"/\0".as_ptr().cast(),
            )
        };
        if rc != 0 {
            unsafe { libc::close(fd) };
            return Err(anyhow::anyhow!(
                "fanotify_mark(filesystem, /) 失败 errno={}",
                errno()
            ));
        }
        Ok(Self {
            fd,
            procs,
            rules,
            tx,
            base: std::time::Instant::now(),
            stats: Arc::new(FanotifyStats::default()),
        })
    }

    fn now(&self) -> Timestamp {
        Timestamp(self.base.elapsed().as_millis() as u64)
    }

    /// 同步事件循环（专属线程，微秒级预算；阻塞点只有 read 与 response 写回）。
    /// 正常不返回；停机由 [`ShutdownHandle::shutdown`] 置标志 + drain。
    pub fn run(&self, stop: Arc<std::sync::atomic::AtomicBool>) {
        let mut buf = [0u8; 4096];
        loop {
            if stop.load(Relaxed) {
                self.allow_all_pending();
                return;
            }
            let n = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let e = errno();
                if e == libc::EINTR {
                    continue;
                }
                // 停机 close(fd) 后返回 EBADF：检查停止标志退出
                if stop.load(Relaxed) {
                    self.allow_all_pending();
                    return;
                }
                tracing::error!("fanotify read errno={e}，事件源失效（大声告警，§9.1）");
                // 失效重建由健康监控负责（M2 接入指数退避重建）
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
            let mut off = 0usize;
            while off + std::mem::size_of::<FanotifyEventMetadata>() <= n as usize {
                let ev = unsafe { &*(buf.as_ptr().add(off).cast::<FanotifyEventMetadata>()) };
                off += ev.event_len as usize;
                if ev.metadata_len as usize >= std::mem::size_of::<FanotifyEventMetadata>() {
                    self.handle_event(ev);
                }
            }
        }
    }

    fn handle_event(&self, ev: &FanotifyEventMetadata) {
        let path = fd_path(ev.fd);
        let pid = ev.pid as Pid;
        let is_perm = ev.mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM) != 0;

        // 早过滤 + 通知类事件转 FileCreate（归档产物信号，§3.1）
        if !is_perm {
            if ev.mask & (FAN_CREATE | FAN_CLOSE_WRITE) != 0 {
                if let Some(path) = &path {
                    if self.is_monitored(pid) {
                        let st = self
                            .procs
                            .get(&pid)
                            .map(|i| i.start_time)
                            .unwrap_or(StartTime(0));
                        self.try_send(RawEvent::FileCreate {
                            pid,
                            start_time: st,
                            path: path.clone(),
                        });
                    }
                }
            }
            close_fd(ev.fd);
            return;
        }

        self.stats.perm_events.fetch_add(1, Relaxed);
        let verdict = {
            let rules = self.rules.load();
            match self.procs.get(&pid) {
                Some(id) => {
                    judge_perm_sync(&rules, &id, &path.clone().unwrap_or_default(), Access::Read)
                }
                None => {
                    // 非监控进程：放行（不干预，§3.3 规则 1）
                    hg_model::Verdict {
                        rule_id: hg_model::RuleId("non-harness"),
                        action: hg_model::Action::Allow,
                        evidence: hg_model::Evidence {
                            summary: String::new(),
                            detail: serde_json::Value::Null,
                        },
                    }
                }
            }
        };
        let resp = if verdict.action == hg_model::Action::Block {
            self.stats.denied.fetch_add(1, Relaxed);
            FAN_DENY
        } else {
            FAN_ALLOW
        };
        let r = FanotifyResponse {
            fd: ev.fd,
            response: resp,
        };
        let _ = unsafe {
            libc::write(
                self.fd,
                &r as *const _ as *const libc::c_void,
                std::mem::size_of::<FanotifyResponse>(),
            )
        };

        // 审计（Block/Audit 才值得落库；try_send 满则丢——判定永不被审计拖累，§9.2）
        if verdict.action != hg_model::Action::Allow {
            self.try_send(RawEvent::FileOpen {
                pid,
                start_time: self
                    .procs
                    .get(&pid)
                    .map(|i| i.start_time)
                    .unwrap_or(StartTime(0)),
                path: path.clone().unwrap_or_default(),
                access: Access::Read,
            });
        }
        close_fd(ev.fd);
    }

    fn is_monitored(&self, pid: Pid) -> bool {
        self.procs
            .get(&pid)
            .is_some_and(|i| i.harness_root.is_some())
    }

    fn try_send(&self, event: RawEvent) {
        if self.tx.try_send(Envelope::new(self.now(), event)).is_err() {
            self.stats.audit_dropped.fetch_add(1, Relaxed);
        }
    }

    /// 停机序列第 1 步（§9.3）：未决权限事件统一 FAN_ALLOW（宁放勿卡）。
    pub fn allow_all_pending(&self) {
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            let mut off = 0usize;
            while off + std::mem::size_of::<FanotifyEventMetadata>() <= n as usize {
                let ev = unsafe { &*(buf.as_ptr().add(off).cast::<FanotifyEventMetadata>()) };
                off += ev.event_len as usize;
                if ev.mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM) != 0 {
                    let r = FanotifyResponse {
                        fd: ev.fd,
                        response: FAN_ALLOW,
                    };
                    let _ = unsafe {
                        libc::write(
                            self.fd,
                            &r as *const _ as *const libc::c_void,
                            std::mem::size_of::<FanotifyResponse>(),
                        )
                    };
                }
                close_fd(ev.fd);
            }
        }
    }
}

impl Drop for FanotifySource {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn fd_path(fd: libc::c_int) -> Option<PathBuf> {
    let mut buf = [0u8; libc::PATH_MAX as usize];
    let n = unsafe {
        libc::readlink(
            format!("/proc/self/fd/{fd}").as_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len() - 1,
        )
    };
    if n <= 0 {
        return None;
    }
    buf[n as usize] = 0;
    Some(PathBuf::from(
        String::from_utf8_lossy(&buf[..n as usize]).into_owned(),
    ))
}

fn close_fd(fd: libc::c_int) {
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
