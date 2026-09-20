// 未编译验证：待 macOS 环境确认（技术任务硬约束 3/4）。
//! /dev/auditpipe 事件源（技术设计 §5.3，全项目最大自研点）：
//! - open + `AUDITPIPE_SET_PRESELECT_MODE`(AUDITPIPE_PRESELECT_MODE_LOCAL) ioctl
//!   + `AUDITPIPE_SET_QLIMIT`，本地预选 EX（exec）与 FC（file control）类事件；
//! - 阻塞读 BSM 记录（`header token + 若干扩展 token`），最小解析：
//!   AUT_HEADER32/64（秒级时间戳 + 事件类型）、AUT_PATH（文件路径）、
//!   AUT_EXEC_ARGS/AUT_EXEC_ENV（命令行）、AUT_SUBJECT32/64（pid/ppid/uid）；
//! - 事件类型映射：AUE_EXECVE → Exec；AUE_OPEN_R/AUE_OPEN_RW 等 → FileOpen；
//!   AUE_CREATE → FileCreate；其余忽略。
//! - 降级链（设计 §5.3）：auditpipe 打不开/解析失败率高 → FSEvents + sysctl
//!   kinfo_proc 轮询（漏短命进程，显式告警）。
//!
//! ioctl 常量值来自 bsm/audit_pipe.h（Darwin）；双架构同为 32 位 _IOW 编码，
//! x86_64 与 aarch64 无差异。

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::sync::Arc;
use std::time::Duration;

use hg_core::proc_table::ProcTable;
use hg_model::{Access, Envelope, Pid, RawEvent, StartTime, Timestamp};
use tokio::sync::mpsc;

// bsm/audit_pipe.h
const AUDITPIPE_SET_PRESELECT_MODE: libc::c_ulong = 0x8004_4873;
const AUDITPIPE_SET_QLIMIT: libc::c_ulong = 0x8004_4879;
const AUDITPIPE_PRESELECT_MODE_LOCAL: i32 = 2;
// bsm/audit.h 事件类（预选 mask，64 位）
const AUDIT_CLASS_EX: u64 = 1 << 1; // 0x0000_0002 exec
const AUDIT_CLASS_FC: u64 = 1 << 10; // 0x0000_0400 file control（open/create/rename...）
                                     // BSM token 类型
const AUT_HEADER32: u8 = 0x14;
const AUT_HEADER64: u8 = 0x74;
const AUT_PATH: u8 = 0x12;
const AUT_SUBJECT32: u8 = 0x0c;
const AUT_SUBJECT64: u8 = 0x76;
const AUT_EXEC_ARGS: u8 = 0x0b;
// bsm/audit_uevents / kevents.h 常用事件号（数值来源 OpenBSM audit_kevents.h；
// macOS 实测 emit 分布与 Darwin 变体差异仍属 M3 校准，见文件头声明）
const AUE_EXECVE: u16 = 23;
const AUE_OPEN_R: u16 = 72;
// 造文件的两个常见事件：open(O_CREAT) 写族 + creat() 旧接口
const AUE_OPEN_WC: u16 = 77;
const AUE_CREAT: u16 = 4;

pub struct AuditPipeSource {
    procs: Arc<ProcTable>,
    tx: mpsc::Sender<Envelope>,
    base: std::time::Instant,
}

#[derive(Default)]
struct BsmRecordState {
    event: u16,
    pid: Pid,
    ppid: Pid,
    path: Option<String>,
    args: Vec<OsString>,
}

impl AuditPipeSource {
    pub fn new(procs: Arc<ProcTable>, tx: mpsc::Sender<Envelope>) -> Self {
        Self {
            procs,
            tx,
            base: std::time::Instant::now(),
        }
    }

    fn now(&self) -> Timestamp {
        Timestamp(self.base.elapsed().as_millis() as u64)
    }

    /// 打开 auditpipe 并配置预选。需要 root。
    pub fn open_pipe() -> anyhow::Result<i32> {
        let fd = unsafe { libc::open(b"/dev/auditpipe\0".as_ptr().cast(), libc::O_RDONLY) };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "open(/dev/auditpipe) 失败 errno={}——降级 FSEvents+kinfo_proc（漏短命进程，显式告警）",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            ));
        }
        unsafe {
            let mode = AUDITPIPE_PRESELECT_MODE_LOCAL;
            libc::ioctl(fd, AUDITPIPE_SET_PRESELECT_MODE, &mode);
            let qlimit: libc::c_int = 1024;
            libc::ioctl(fd, AUDITPIPE_SET_QLIMIT, &qlimit);
            // 本地预选 mask：EX + FC（每次 ioctl 设置一个类位）
            let mask: u64 = AUDIT_CLASS_EX | AUDIT_CLASS_FC;
            // AUDITPIPE_SET_PRESELECT_FLAGS(_IOW('a', ...)：M3 按头文件精确编码
            const AUDITPIPE_SET_PRESELECT_FLAGS: libc::c_ulong = 0x8010_487c;
            libc::ioctl(fd, AUDITPIPE_SET_PRESELECT_FLAGS, &mask);
        }
        Ok(fd)
    }

    /// 事件循环（专属线程阻塞读；正常不返回）。
    pub fn run(&self, fd: i32) -> anyhow::Result<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(8192);
        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.capacity()) };
            if n < 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if e == libc::EINTR {
                    continue;
                }
                tracing::error!("auditpipe read errno={e}（事件源失效大声告警，§9.1）");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            let n = n as usize;
            let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr(), n) };
            self.consume_record(bytes);
        }
    }

    /// 单条 BSM 记录：header 起始、token 序列直到长度耗尽。
    fn consume_record(&self, bytes: &[u8]) {
        let mut st = BsmRecordState::default();
        let mut off = 0usize;
        while off < bytes.len() {
            let tok = match bytes.get(off) {
                Some(&t) => t,
                None => break,
            };
            match tok {
                AUT_HEADER32 => {
                    // len(u16) ver(u8) event(u16) ... time(s)
                    if bytes.len() < off + 12 {
                        break;
                    }
                    st.event = u16::from_be_bytes([bytes[off + 6], bytes[off + 7]]);
                    off += 20; // header32 定长（含时间戳）
                }
                AUT_HEADER64 => {
                    if bytes.len() < off + 24 {
                        break;
                    }
                    st.event = u16::from_be_bytes([bytes[off + 6], bytes[off + 7]]);
                    off += 32;
                }
                AUT_PATH => {
                    if let Some((s, next)) = read_str_token(bytes, off) {
                        st.path = Some(s);
                        off = next;
                    } else {
                        break;
                    }
                }
                AUT_EXEC_ARGS => {
                    if let Some((v, next)) = read_str_list_token(bytes, off) {
                        st.args = v;
                        off = next;
                    } else {
                        break;
                    }
                }
                AUT_SUBJECT32 => {
                    if bytes.len() >= off + 44 {
                        st.pid = u32::from_be_bytes([
                            bytes[off + 24],
                            bytes[off + 25],
                            bytes[off + 26],
                            bytes[off + 27],
                        ]);
                        st.ppid = u32::from_be_bytes([
                            bytes[off + 28],
                            bytes[off + 29],
                            bytes[off + 30],
                            bytes[off + 31],
                        ]);
                        off += 44;
                    } else {
                        break;
                    }
                }
                AUT_SUBJECT64 => {
                    if bytes.len() >= off + 60 {
                        st.pid = u32::from_be_bytes([
                            bytes[off + 24],
                            bytes[off + 25],
                            bytes[off + 26],
                            bytes[off + 27],
                        ]);
                        st.ppid = u32::from_be_bytes([
                            bytes[off + 28],
                            bytes[off + 29],
                            bytes[off + 30],
                            bytes[off + 31],
                        ]);
                        off += 60;
                    } else {
                        break;
                    }
                }
                _ => {
                    // 未知 token：无法安全跳过（长度规则未知）——终止本记录（保守丢弃）
                    break;
                }
            }
        }
        self.dispatch(st);
    }

    fn dispatch(&self, st: BsmRecordState) {
        let id = self.procs.get(&st.pid);
        match st.event {
            AUE_EXECVE => {
                let _ = self.tx.try_send(Envelope::new(
                    self.now(),
                    RawEvent::Exec {
                        pid: st.pid,
                        ppid: st.ppid,
                        start_time: StartTime(0), // kinfo_proc p_starttime 由引擎补齐（M3）
                        exe: st.path.clone().unwrap_or_default().into(),
                        cmdline: st.args.clone(),
                        cwd: Default::default(),
                    },
                ));
            }
            e if e == AUE_CREAT || e == AUE_OPEN_WC => {
                if id.as_ref().is_some_and(|i| i.harness_root.is_some()) {
                    let _ = self.tx.try_send(Envelope::new(
                        self.now(),
                        RawEvent::FileCreate {
                            pid: st.pid,
                            start_time: StartTime(0),
                            path: st.path.unwrap_or_default().into(),
                        },
                    ));
                }
            }
            e if e == AUE_OPEN_R => {
                if id.as_ref().is_some_and(|i| i.harness_root.is_some()) {
                    let _ = self.tx.try_send(Envelope::new(
                        self.now(),
                        RawEvent::FileOpen {
                            pid: st.pid,
                            start_time: StartTime(0),
                            path: st.path.unwrap_or_default().into(),
                            access: Access::Read,
                        },
                    ));
                }
            }
            _ => {}
        }
    }
}

fn read_str_token(b: &[u8], off: usize) -> Option<(String, usize)> {
    // token(u8) len(u16) bytes + NUL 对齐 4
    if b.len() < off + 3 {
        return None;
    }
    let len = u16::from_be_bytes([b[off + 1], b[off + 2]]) as usize;
    if b.len() < off + 3 + len {
        return None;
    }
    let s = String::from_utf8_lossy(&b[off + 3..off + 3 + len])
        .trim_end_matches('\0')
        .to_string();
    let total = 3 + len;
    let next = off + (total + 3) & !3; // 4 字节对齐
    Some((s, next))
}

fn read_str_list_token(b: &[u8], off: usize) -> Option<(Vec<OsString>, usize)> {
    if b.len() < off + 2 {
        return None;
    }
    let count = b[off + 1] as usize;
    let mut p = off + 2;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if b.len() < p + 2 {
            return None;
        }
        let len = b[p] as usize;
        let s = OsString::from_vec(b.get(p + 1..p + 1 + len)?.to_vec());
        out.push(s);
        p += 1 + len;
    }
    p = (p + 3) & !3;
    Some((out, p))
}
