// 未编译验证：待 Linux 环境确认（技术任务硬约束 3）。
//! eBPF 事件源（技术设计 §5.2，aya）：
//! - 进程事件：tracepoint `sched_process_exec` / `sched_process_fork` / `sched_process_exit`
//!   （直接携带 exe/filename 与 pid 上下文，短命进程不丢，需求 §3.4）；
//!   cmdline 补读 `/proc/<pid>/cmdline`（exec 后立即读，短命竞态容忍）；
//!   start_time 取 `/proc/<pid>/stat` 第 22 字段（jiffies，防 pid 复用）。
//! - 网络上行：kprobe `tcp_sendmsg` 按 **socket cookie** 累计字节（BPF map）；
//!   cookie↔五元组↔pid 归因由用户态周期采样 `ss -te`（sk 列含 cookie）；
//!   降级链（§5.2）：BPF 不可用 → inet_diag 周期采样（pid 归因弱，显式告警）。
//! - DNS：见 [`crate::dns`]（AF_PACKET，独立于 BPF）。
//!
//! BPF 对象编译：`bpf/harnessguard.bpf.c` → `clang -target bpfel -O2 -g -c`
//! （M2 Linux 环境执行；产物路径经 `HG_BPF_OBJ` 环境变量或默认
//! `/usr/lib/harnessguard/harnessguard.bpf.o` 加载）。

use std::sync::Arc;
use std::time::Duration;

use hg_core::proc_table::ProcTable;
use hg_model::{ConnId, Envelope, Pid, RawEvent, StartTime, Timestamp};
use tokio::sync::mpsc;

/// BPF 用户态事件（与 `bpf/harnessguard.bpf.c` 中结构体布局一致，#[repr(C)]）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfEvent {
    pub kind: u32, // 0=exec 1=exit 2=fork 3=tcp_send
    pub pid: u32,
    pub ppid: u32,
    pub cookie: u64,
    pub bytes: u64,
    pub filename: [u8; 256],
}

pub struct EbpfSource {
    procs: Arc<ProcTable>,
    tx: mpsc::Sender<Envelope>,
    base: std::time::Instant,
}

impl EbpfSource {
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

    /// 加载 BPF 对象并消费事件。对象文件缺失/BTF 不可用时按设计降级链
    /// 显式告警（proc connector / inet_diag），不 fail-fast（§1.2 原则 4）。
    pub fn run(&self) -> anyhow::Result<()> {
        let obj_path = std::env::var("HG_BPF_OBJ")
            .unwrap_or_else(|_| "/usr/lib/harnessguard/harnessguard.bpf.o".into());
        let mut bpf = match aya::Ebpf::load_file(&obj_path) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(
                    "BPF 加载失败（{e}）——降级链：proc connector + inet_diag 采样，\
                     短命子进程可见性受限（显式告警，技术设计 §5.2）"
                );
                return Err(anyhow::anyhow!("bpf load failed: {e}"));
            }
        };
        // tracepoint 挂载
        for tp in [
            "sched_process_exec",
            "sched_process_exit",
            "sched_process_fork",
        ] {
            let prog: &mut aya::programs::TracePoint = bpf
                .program_mut(tp)
                .ok_or_else(|| anyhow::anyhow!("BPF 程序缺失：{tp}"))?
                .try_into()?;
            prog.load()?;
            prog.attach("sched", tp)?;
        }
        // kprobe：tcp_sendmsg（cookie 计数在内核侧 map 完成）
        let kp: &mut aya::programs::KProbe = bpf
            .program_mut("tcp_sendmsg_count")
            .ok_or_else(|| anyhow::anyhow!("BPF 程序缺失：tcp_sendmsg_count"))?
            .try_into()?;
        kp.load()?;
        kp.attach("tcp_sendmsg", 0)?;

        // RingBuf 事件消费（aya 0.13：map_mut 取 &mut Map 后 try_into 为 RingBuf）
        let map = bpf
            .map_mut("events")
            .ok_or_else(|| anyhow::anyhow!("BPF map 缺失：events"))?;
        let mut ring: aya::maps::RingBuf<_> = map.try_into()?;
        loop {
            while let Some(item) = ring.next() {
                let buf: &[u8] = &item;
                if buf.len() >= std::mem::size_of::<BpfEvent>() {
                    let ev = unsafe { &*(buf.as_ptr() as *const BpfEvent) };
                    self.dispatch(ev);
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn dispatch(&self, ev: &BpfEvent) {
        match ev.kind {
            0 => {
                // exec：filename（NT 无关，直接是绝对路径）+ cmdline 补读 + start_time
                let len = ev
                    .filename
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(ev.filename.len());
                let exe = String::from_utf8_lossy(&ev.filename[..len]).into_owned();
                let cmdline = read_cmdline(ev.pid);
                let st = StartTime(proc_starttime(ev.pid));
                let _ = self.tx.try_send(Envelope::new(
                    self.now(),
                    RawEvent::Exec {
                        pid: ev.pid,
                        ppid: ev.ppid,
                        start_time: st,
                        exe: exe.into(),
                        cmdline,
                        cwd: read_cwd(ev.pid),
                    },
                ));
            }
            1 => {
                let _ = self.tx.try_send(Envelope::new(
                    self.now(),
                    RawEvent::Exit {
                        pid: ev.pid,
                        start_time: StartTime(0),
                    },
                ));
            }
            2 => { /* fork：ppid 关联在 exec 事件流内完成（ProcTable 按表查询父身份） */
            }
            3 => {
                // tcp_send：按 cookie 累计；conn_id 直接用 cookie（稳定且天然防复用）
                let _ = self.tx.try_send(Envelope::new(
                    self.now(),
                    RawEvent::ConnTx {
                        conn_id: ConnId(ev.cookie),
                        bytes_out_delta: ev.bytes,
                    },
                ));
            }
            _ => {}
        }
    }
}

/// cookie 归因采样：`ss -te` 输出含 sk（cookie）与 pid/四元组。
/// 周期调用，结果交引擎 ConnRegistry 关联（M2 校准项：采样间隔 vs 短连接寿命）。
pub fn sample_socket_cookies() -> Vec<(
    u64, /*cookie*/
    Pid,
    String, /*local*/
    String, /*remote*/
)> {
    let out = std::process::Command::new("ss")
        .args(["-tne", "state", "established"])
        .output();
    let mut rows = Vec::new();
    if let Ok(o) = out {
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines() {
            // ss 行形如：... local peer ... pid=123 sk=abcd12 ...（字段顺序按版本校准）
            let cookie = line
                .split("sk=")
                .nth(1)
                .and_then(|s| s.split_whitespace().next());
            let pid = line.split("pid=").nth(1).and_then(|s| s.split(',').next());
            let mut cols = line.split_whitespace().filter(|c| c.contains(':'));
            let local = cols.next().unwrap_or_default().to_string();
            let remote = cols.next().unwrap_or_default().to_string();
            if let (Some(c), Some(p)) = (cookie, pid) {
                if let (Ok(c), Ok(p)) = (u64::from_str_radix(c, 16), p.parse::<u32>()) {
                    rows.push((c, p, local, remote));
                }
            }
        }
    }
    rows
}

fn read_cmdline(pid: Pid) -> Vec<std::ffi::OsString> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| {
            b.split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| std::ffi::OsString::from(String::from_utf8_lossy(s).into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

fn read_cwd(pid: Pid) -> std::path::PathBuf {
    std::fs::read_link(format!("/proc/{pid}/cwd")).unwrap_or_default()
}

/// /proc/<pid>/stat 第 22 字段（starttime，jiffies since boot）
pub fn proc_starttime(pid: Pid) -> u64 {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return 0;
    };
    // 字段 2 (comm) 可能含空格——从最后 ')' 之后切
    let tail = match stat.rfind(')') {
        Some(i) => &stat[i + 2..],
        None => return 0,
    };
    tail.split_whitespace()
        .nth(19) // 第 3 字段(state)起数 19 → 第 22 字段
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}
