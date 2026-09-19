//! ETW 事件源（技术设计 §5.1，选型按 M0 spike 校准）：
//! - 进程：经典 kernel logger `EVENT_TRACE_FLAG_PROCESS`（start/stop + pid/ppid）
//!   + `EVENT_TRACE_FLAG_IMAGE_LOAD`（Load 事件携带完整 exe NT 路径）；
//! - 文件：`EVENT_TRACE_FLAG_FILE_IO(_INIT)`，FileObject→Name 缓存，按 harness 身份早过滤；
//! - 网络：`EVENT_TRACE_FLAG_NETWORK_TCPIP`（connect/send/disconnect）；
//! - DNS：Dns-Client 按 GUID 挂独立 UserTrace（by_name 本机 NotFound，M0 轮 1）。
//! manifest 版 Kernel-Process 在本机不出事件（M0 轮 2–4），弃用。

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use dashmap::DashMap;
use ferrisetw::parser::{Parser, Pointer};
use ferrisetw::provider::{kernel_providers, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{KernelTrace, UserTrace};
use ferrisetw::EventRecord;
use hg_core::ProcTable;
use hg_model::{
    Access, ConnId, Envelope, Pid, Proto, RawEvent, StartTime, Timestamp,
};
use tokio::sync::mpsc;

use crate::lru;
use crate::ntpath::nt_to_win32;
use crate::peb;
use crate::probe;

/// 事件源健康统计（定义于 hg-core::health，供 Web 状态页共享；技术设计 §9.1/§9.2）。
pub use hg_core::health::SourceStats;

/// 文件 opcode（M0 实测）：64=Create 67=Read 68=Write
const FILE_OP_CREATE: u8 = 64;
const FILE_OP_READ: u8 = 67;
const FILE_OP_WRITE: u8 = 68;
/// 网络 opcode：16=connect 10=send 18=disconnect（M0 实测分布）
const NET_OP_CONNECT: u8 = 16;
const NET_OP_SEND: u8 = 10;
const NET_OP_DISCONNECT: u8 = 18;
/// FileObject 缓存容量（LRU 封顶，M1 为超限整表清空——burst 会误清热点；
/// §10 预算表超支预案原文"FileObject 缓存加 LRU 上限"）
const FILEOBJ_CAP: usize = 200_000;
/// 探测失败表容量（FileObject → 已失败不重试；burst 中 Create→Close 极快，
/// 句柄已关为主要 miss 原因，重试无意义）
const PROBE_FAIL_CAP: usize = 4096;
/// 计划任务注册工具 cmdline 特征（小写包含匹配；schtasks / PowerShell
/// Register-ScheduledTask / COM RegisterTask 定义）
const SCHED_MARKERS: [&str; 3] = ["schtasks", "register-scheduledtask", "registertask"];
/// 注册候选缓存容量（Exec 时快照；106 事件常晚于发起 cmd 退出——归因竞态修复）
const SCHED_CAND_CAP: usize = 64;
/// 注册候选有效期（106 相对 cmd 退出的延迟为数十 ms～数 s，窗口取宽防误归因旧进程）
const SCHED_CAND_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(120);

/// Exec 时缓存的计划任务注册候选（cmdline 含 [`SCHED_MARKERS`] 特征）。
struct SchedCandidate {
    pid: Pid,
    cmdline: String,
    at: Instant,
}

struct PidCtx {
    ppid: Pid,
    start_time: StartTime,
    exe: Option<PathBuf>,
    exec_sent: bool,
    /// ProcessStart 事件是否已到（Exec 需 start+exe 双就绪再发：
    /// ImageLoad 可能先于 ProcessStart 到达，此时 ppid 未知，提前发会丢继承）
    start_seen: bool,
    /// 进程 cwd（PEB 读取）：ETW 文件名常为相对形式，需 cwd 拼接（实测教训）
    cwd: PathBuf,
}

/// ETW 回调线程与装配方共享的状态。
pub struct EtwInner {
    pub procs: Arc<ProcTable>,
    pub stats: Arc<SourceStats>,
    tx: OnceLock<mpsc::Sender<Envelope>>,
    base: Instant,
    pid_ctx: DashMap<Pid, PidCtx>,
    /// FileObject → 文件名（LRU 封顶：M1 整表清空在 burst 下会误清热点条目）
    fileobj: Mutex<lru::LruCache>,
    /// Name 事件迟到时的挂起重试表：obj → (pid, opcode)。Name 到达即补发（上限控制内存）。
    pending_files: Mutex<HashMap<u64, (Pid, u8)>>,
    /// unknown Create 探测失败表（同对象不重试；LRU 封顶防涨）
    probe_failed: Mutex<lru::LruCache>,
    /// 探测限流：上次探测时刻（全系统句柄快照数 ms 级，burst 必须降频）
    probe_last: Mutex<Instant>,
    /// TCP owner 表（GetExtendedTcpTable）：四元组 → 归属 pid。
    /// 实测教训：本机 TCP-IP 经典事件 PID 字段恒为 -1，归因只能走 owner 表。
    tcp_owner: Mutex<(std::time::Instant, HashMap<(std::net::SocketAddr, std::net::SocketAddr), Pid>)>,
    /// 已发 ConnOpen 的连接（send/connect 任一先到都确保登记——实测 connect 事件
    /// 在部分路径缺失，send 带有效 pid 时补登记，防孤儿 send）
    emitted_conns: dashmap::DashSet<u64>,
    /// 已发 ConnOpen 的四元组（conn_id → (local, remote)）：estats 轮询线程按此
    /// 补计字节（场景 C 替代路径）；disconnect 时移除（同四元组复用可重登记）
    pub(crate) monitored_quads: dashmap::DashMap<u64, (SocketAddr, SocketAddr)>,
    /// 计划任务注册候选（Exec 时快照）：106 事件到达时发起 cmd 常已退出，
    /// 实时进程扫描必 miss——按此缓存归因（容量/时效封顶，见 prune 函数）
    sched_candidates: Mutex<VecDeque<SchedCandidate>>,
}

impl EtwInner {
    pub fn new(procs: Arc<ProcTable>, stats: Arc<SourceStats>) -> Arc<Self> {
        Arc::new(Self {
            procs,
            stats,
            tx: OnceLock::new(),
            base: Instant::now(),
            pid_ctx: DashMap::new(),
            fileobj: Mutex::new(lru::LruCache::new(FILEOBJ_CAP)),
            pending_files: Mutex::new(HashMap::new()),
            probe_failed: Mutex::new(lru::LruCache::new(PROBE_FAIL_CAP)),
            probe_last: Mutex::new(Instant::now() - probe::PROBE_MIN_INTERVAL),
            tcp_owner: Mutex::new((std::time::Instant::now() - std::time::Duration::from_secs(10), HashMap::new())),
            emitted_conns: dashmap::DashSet::new(),
            monitored_quads: dashmap::DashMap::new(),
            sched_candidates: Mutex::new(VecDeque::new()),
        })
    }

    fn now(&self) -> Timestamp {
        Timestamp(self.base.elapsed().as_millis() as u64)
    }

    /// 通道满即丢弃并计数（技术设计 §9.2：判定永不被审计拖累）。
    pub fn emit(&self, event: RawEvent) {
        if let Some(tx) = self.tx.get() {
            match tx.try_send(Envelope::new(self.now(), event)) {
                Ok(()) => {
                    self.stats.events_sent.fetch_add(1, Relaxed);
                }
                Err(_) => {
                    self.stats.events_dropped_full.fetch_add(1, Relaxed);
                }
            }
        }
    }

    fn parse_u32(p: &Parser, names: &[&str]) -> Option<u32> {
        for n in names {
            if let Ok(v) = p.try_parse(n) {
                return Some(v);
            }
        }
        None
    }

    fn on_process(&self, record: &EventRecord, loc: &SchemaLocator) {
        match record.opcode() {
            1 => {
                let Ok(schema) = loc.event_schema(record) else { return };
                let p = Parser::create(record, &schema);
                let pid = Self::parse_u32(&p, &["ProcessId", "ProcessID"]).unwrap_or(0);
                let ppid = Self::parse_u32(&p, &["ParentId", "ParentID"]).unwrap_or(0);
                if pid == 0 {
                    return;
                }
                // start_time 与 cwd：经典事件不带，立即读 PEB（竞态容忍缺省值）
                let (_, st, cwd) = peb::query_process(pid);
                if let Some(mut ctx) = self.pid_ctx.get_mut(&pid) {
                    ctx.ppid = ppid;
                    ctx.start_time = StartTime(st);
                    ctx.start_seen = true;
                    if ctx.cwd.as_os_str().is_empty() {
                        ctx.cwd = cwd;
                    }
                } else {
                    self.pid_ctx.insert(
                        pid,
                        PidCtx { ppid, start_time: StartTime(st), exe: None, exec_sent: false, start_seen: true, cwd },
                    );
                }
                self.try_emit_exec(pid);
            }
            2 => {
                let Ok(schema) = loc.event_schema(record) else { return };
                let p = Parser::create(record, &schema);
                let pid = Self::parse_u32(&p, &["ProcessId", "ProcessID"]).unwrap_or(0);
                if pid == 0 {
                    return;
                }
                if let Some((_, ctx)) = self.pid_ctx.remove(&pid) {
                    self.emit(RawEvent::Exit { pid, start_time: ctx.start_time });
                }
            }
            _ => {}
        }
    }

    /// exe 路径就绪（首个 ImageLoad）且 start 已到 → 发 Exec（含 PEB 命令行降级链）。
    fn try_emit_exec(&self, pid: Pid) {
        let Some(ctx) = self.pid_ctx.get(&pid) else { return };
        if ctx.exec_sent || !ctx.start_seen || ctx.exe.is_none() {
            return;
        }
        let exe = ctx.exe.clone().unwrap();
        let ppid = ctx.ppid;
        let st = ctx.start_time;
        let cwd = ctx.cwd.clone();
        drop(ctx);
        let (cmdline, _, _) = peb::query_process(pid);
        // 归因竞态修复：计划任务注册工具进程在 Exec 时快照 cmdline 候选
        //（106 事件到达时常已退出，届时实时扫描已无对象）
        self.remember_task_registrar(pid, &cmdline);
        if let Some(mut ctx) = self.pid_ctx.get_mut(&pid) {
            ctx.exec_sent = true;
        }
        self.emit(RawEvent::Exec {
            pid,
            ppid,
            start_time: st,
            exe,
            cmdline,
            cwd,
        });
    }

    fn on_image_load(&self, record: &EventRecord, loc: &SchemaLocator) {
        if record.opcode() != 10 {
            return;
        }
        let Ok(schema) = loc.event_schema(record) else { return };
        let p = Parser::create(record, &schema);
        let pid = Self::parse_u32(&p, &["ProcessId", "ProcessID"]).unwrap_or(0);
        let file: Option<String> = p.try_parse::<String>("FileName").ok();
        if pid == 0 {
            return;
        }
        let Some(file) = file else { return };
        if let Some(mut ctx) = self.pid_ctx.get_mut(&pid) {
            if ctx.exe.is_none() {
                ctx.exe = Some(nt_to_win32(&file));
            }
        } else {
            // start 事件尚未到达（或本进程早于服务启动）：先暂存，start 到达再发
            let (_, _, cwd) = peb::query_process(pid);
            self.pid_ctx.insert(
                pid,
                PidCtx { ppid: 0, start_time: StartTime(peb::process_start_time(pid)), exe: Some(nt_to_win32(&file)), exec_sent: false, start_seen: false, cwd },
            );
            return;
        }
        self.try_emit_exec(pid);
    }

    fn on_file(&self, record: &EventRecord, loc: &SchemaLocator) {
        self.stats.kernel_events_seen.fetch_add(1, Relaxed);
        let op = record.opcode();
        let Ok(schema) = loc.event_schema(record) else { return };
        let p = Parser::create(record, &schema);

        // Name 事件：建缓存（与 opcode 无关，按字段成功与否识别）
        let name: Option<String> = p.try_parse::<String>("FileName").ok().filter(|s| !s.is_empty());
        let obj: Option<u64> = p
            .try_parse::<Pointer>("FileObject")
            .ok()
            .map(|ptr| *ptr as u64);
        if let (Some(n), Some(fo)) = (&name, obj) {
            let mut g = self.fileobj.lock().unwrap();
            g.insert(fo, n.clone());
            self.stats.file_cache_entries.store(g.len() as u64, Relaxed);
            drop(g);
            // Name 迟到重试：此前 unknown 的同 FileObject 事件现在补发。
            // 先 remove 释放锁再 emit——emit 链含路径解析与通道发送，锁内执行
            // 放大临界区（M4 待修清单 2）
            let pending = self.pending_files.lock().unwrap().remove(&fo);
            if let Some((pid2, op2)) = pending {
                self.emit_file_event(pid2, op2, n);
            }
        }

        if !matches!(op, FILE_OP_CREATE | FILE_OP_READ | FILE_OP_WRITE) {
            return;
        }
        // 经典内核 FileIo 事件的 PID 在事件头（schema 无此字段）——实测教训
        let pid = {
            let hp = record.process_id();
            if hp != 0 { hp } else { Self::parse_u32(&p, &["ProcessId", "ProcessID"]).unwrap_or(0) }
        };
        // 早过滤：非监控树进程即读即弃（M0 实测 26k/s，此为硬要求）
        let Some(id) = self.procs.get(&pid) else { return };
        if id.harness_root.is_none() {
            return;
        }
        // 解析路径：事件自带 FileName 或 FileObject→Name 缓存
        let path = match name {
            Some(n) => {
                self.stats.file_resolved.fetch_add(1, Relaxed);
                Some(n)
            }
            None => match obj.and_then(|fo| {
                    let mut g = self.fileobj.lock().unwrap();
                    g.get(fo).map(|s| s.to_string())
                }) {
                Some(n) => {
                    self.stats.file_resolved.fetch_add(1, Relaxed);
                    Some(n)
                }
                None => {
                    self.stats.file_unknown.fetch_add(1, Relaxed);
                    tracing::debug!("[file-unknown] pid={pid} op={op} obj={:x}", obj.unwrap_or(0));
                    None
                }
            },
        };
        match path {
            Some(path) => self.emit_file_event(pid, op, &path),
            None => {
                // 场景 A 缓解（M1 缺口 1）：unknown 的 Create 事件做同对象句柄探测
                // 补名（限流 + 失败不重试，见 probe 模块头注释）；成功则回填缓存
                // 并补发事件，后续同 FileObject 的 Read/Write 直接走缓存命中
                if let Some(fo) = obj {
                    let allowed = {
                        let failed = self.probe_failed.lock().unwrap().contains(fo);
                        let mut last = self.probe_last.lock().unwrap();
                        let elapsed_ok = last.elapsed() >= probe::PROBE_MIN_INTERVAL;
                        if elapsed_ok {
                            *last = Instant::now();
                        }
                        drop(last);
                        // 实机复验修正：Read（cmd type 等读路径）也探测——
                        // 否则 .git 读取判定永远卡在 pending 等 Name
                        probe::probe_allowed(
                            matches!(op, FILE_OP_CREATE | FILE_OP_READ),
                            failed,
                            elapsed_ok,
                        )
                    };
                    if allowed {
                        self.stats.file_probe_tried.fetch_add(1, Relaxed);
                        match probe::probe_file_name(pid, fo) {
                            Some(name) => {
                                self.stats.file_probe_hit.fetch_add(1, Relaxed);
                                let mut g = self.fileobj.lock().unwrap();
                                g.insert(fo, name.clone());
                                self.stats.file_cache_entries.store(g.len() as u64, Relaxed);
                                drop(g);
                                self.emit_file_event(pid, op, &name);
                                return;
                            }
                            None => {
                                self.probe_failed.lock().unwrap().insert(fo, String::new());
                            }
                        }
                    }
                }
                // 无 FileObject 的事件永远等不到 Name（Name 事件以 FileObject 关联）
                // ——不入 pending（原以 key 0 登记吞 16384 配额且永无补发机会，
                // M4 待修清单 3）
                let Some(fo) = obj else { return };
                // Name 未到：挂起等 Name 事件补发（上限 16384，满则整表清空防涨内存）
                let mut pend = self.pending_files.lock().unwrap();
                if pend.len() >= 16384 {
                    pend.clear();
                }
                pend.insert(fo, (pid, op));
            }
        }
    }

    fn emit_file_event(&self, pid: Pid, op: u8, raw: &str) {
        let Some(id) = self.procs.get(&pid) else { return };
        let path = self.resolve_file_name(pid, raw);
        tracing::debug!("[file] pid={pid} op={op} root={:?} raw={raw:?} -> {}", id.harness_root.as_ref().map(|r| r.0.clone()), path.display());
        let st = id.start_time;
        match op {
            FILE_OP_CREATE => self.emit(RawEvent::FileCreate { pid, start_time: st, path }),
            FILE_OP_READ => self.emit(RawEvent::FileOpen { pid, start_time: st, path, access: Access::Read }),
            FILE_OP_WRITE => self.emit(RawEvent::FileOpen { pid, start_time: st, path, access: Access::Write }),
            _ => {}
        }
    }

    fn on_net(&self, record: &EventRecord, loc: &SchemaLocator) {
        self.stats.kernel_events_seen.fetch_add(1, Relaxed);
        let op = record.opcode();
        if !matches!(op, NET_OP_CONNECT | NET_OP_SEND | NET_OP_DISCONNECT) {
            return;
        }
        let Ok(schema) = loc.event_schema(record) else { return };
        let p = Parser::create(record, &schema);
        let mut pid = {
            let hp = record.process_id();
            if hp != 0 && hp != u32::MAX { hp } else { Self::parse_u32(&p, &["PID", "ProcessId"]).unwrap_or(u32::MAX) }
        };
        let saddr: IpAddr = p.try_parse("saddr").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let daddr: IpAddr = p.try_parse("daddr").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        // 端口在事件中为网络序存储，按原生读出后需换序
        let sport: u16 = p.try_parse::<u16>("sport").map(u16::from_be).unwrap_or(0);
        let dport: u16 = p.try_parse::<u16>("dport").map(u16::from_be).unwrap_or(0);
        let local = SocketAddr::new(saddr, sport);
        let remote = SocketAddr::new(daddr, dport);
        // conn_id 只按四元组（不含 pid：send/connect 事件的 PID 均可能为 -1，实测教训）
        let conn_id = ConnId(Self::conn_hash(local, remote));
        tracing::debug!("[net] op={op} pid={pid} {local} -> {remote}");

        match op {
            NET_OP_CONNECT => {
                // 归因：事件 PID 无效时查 TCP owner 表（必要时即时刷新）
                if pid == u32::MAX {
                    if let Some(owner) = self.lookup_tcp_owner(local, remote, true) {
                        pid = owner;
                    }
                }
                self.emitted_conns.insert(conn_id.0);
                self.monitored_quads.insert(conn_id.0, (local, remote));
                self.emit(RawEvent::ConnOpen {
                    pid,
                    start_time: StartTime(0),
                    conn_id,
                    proto: Proto::Tcp,
                    local,
                    remote,
                });
            }
            NET_OP_SEND => {
                let size = Self::parse_u32(&p, &["size", "Size"]).unwrap_or(0) as u64;
                // connect 事件缺失时的补登记：send 携带有效 pid 且属监控树 → 先发 ConnOpen
                if pid != u32::MAX && self.emitted_conns_guard() && self.emitted_conns.insert(conn_id.0) {
                    if self.procs.get(&pid).is_some_and(|id| id.harness_root.is_some()) {
                        let st = self.procs.get(&pid).map(|i| i.start_time).unwrap_or(StartTime(0));
                        self.monitored_quads.insert(conn_id.0, (local, remote));
                        self.emit(RawEvent::ConnOpen {
                            pid,
                            start_time: st,
                            conn_id,
                            proto: Proto::Tcp,
                            local,
                            remote,
                        });
                    }
                }
                self.emit(RawEvent::ConnTx { conn_id, bytes_out_delta: size });
            }
            NET_OP_DISCONNECT => {
                // 移除登记（同四元组复用可重登记；estats 轮询侧幂等兜底）
                self.emitted_conns.remove(&conn_id.0);
                self.monitored_quads.remove(&conn_id.0);
                self.emit(RawEvent::ConnClose { conn_id });
            }
            _ => {}
        }
    }

    fn emitted_conns_guard(&self) -> bool {
        if self.emitted_conns.len() > 262_144 {
            self.emitted_conns.clear();
            self.monitored_quads.clear();
        }
        true
    }

    fn lookup_tcp_owner(&self, local: SocketAddr, remote: SocketAddr, refresh: bool) -> Option<Pid> {
        {
            let g = self.tcp_owner.lock().unwrap();
            if let Some(pid) = g.1.get(&(local, remote)) {
                return Some(*pid);
            }
        }
        if refresh {
            self.refresh_tcp_owner();
            let g = self.tcp_owner.lock().unwrap();
            g.1.get(&(local, remote)).copied()
        } else {
            None
        }
    }

    /// GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL) 快照（约 1-5ms，连接级调用频率下可接受）。
    fn refresh_tcp_owner(&self) {
        use windows::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL};
            use windows::Win32::Networking::WinSock::AF_INET;
        unsafe {
            let mut size = 0u32;
            let _ = GetExtendedTcpTable(None, &mut size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
            if size == 0 || size > 16 * 1024 * 1024 {
                return;
            }
            let mut buf = vec![0u8; size as usize];
            if GetExtendedTcpTable(Some(buf.as_mut_ptr() as *mut _), &mut size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0) != 0 {
                return;
            }
            let n = *(buf.as_ptr() as *const u32);
            let row_size = std::mem::size_of::<u32>() * 6; // state+laddr+lport+raddr+rport+pid
            let mut map = HashMap::with_capacity(n as usize);
            for i in 0..n as usize {
                let row = buf.as_ptr().add(4 + i * row_size) as *const u32;
                let la = (*(row.add(1))).swap_bytes();
                let lp = ((*(row.add(2)) & 0xff) << 8 | (*(row.add(2)) & 0xff00) >> 8) as u16;
                let ra = (*(row.add(3))).swap_bytes();
                let rp = ((*(row.add(4)) & 0xff) << 8 | (*(row.add(4)) & 0xff00) >> 8) as u16;
                let pid = *(row.add(5));
                use std::net::Ipv4Addr;
                let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(la)), lp);
                let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ra)), rp);
                map.insert((local, remote), pid);
            }
            *self.tcp_owner.lock().unwrap() = (std::time::Instant::now(), map);
        }
    }

    /// ETW FileName 可能是：NT 设备路径 / 盘符绝对路径 / 进程相对路径（实测：
    /// cmd/tar 的相对打开只给相对名）。相对名按进程 cwd 拼接后做词法归一。
    fn resolve_file_name(&self, pid: Pid, raw: &str) -> PathBuf {
        let norm = raw.replace(chr_backslash(), "/");
        if norm.starts_with("/Device/") || norm.starts_with("/??/") || (norm.len() >= 2 && norm.as_bytes()[1] == b':') {
            return nt_to_win32(raw);
        }
        // 相对路径：cwd 拼接
        let cwd = self.pid_ctx.get(&pid).map(|c| c.cwd.clone()).unwrap_or_default();
        if cwd.as_os_str().is_empty() {
            return PathBuf::from(raw);
        }
        let base = cwd.display().to_string().replace(chr_backslash(), "/");
        let joined = format!("{}/{}", base.trim_end_matches('/'), norm);
        lexical_normalize(&joined)
    }

    fn conn_hash(local: SocketAddr, remote: SocketAddr) -> u64 {
        // fnv-1a over 四元组（唯一性足够：同四元组的并发连接不存在）
        let mut h: u64 = 0xcbf29ce484222325;
        for sock in [local, remote] {
            let (ip, port) = (sock.ip(), sock.port());
            let ipb: Vec<u8> = match ip {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            };
            for b in ipb {
                h ^= b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            for b in port.to_le_bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
        }
        h
    }

    fn on_dns(&self, record: &EventRecord, loc: &SchemaLocator) {
        self.stats.dns_events_seen.fetch_add(1, Relaxed);
        // 3008 = 查询完成（QueryName + QueryResults）
        if record.event_id() != 3008 {
            return;
        }
        let Ok(schema) = loc.event_schema(record) else { return };
        let p = Parser::create(record, &schema);
        let qname: Option<String> = p.try_parse::<String>("QueryName").ok().filter(|s| !s.is_empty());
        let Some(qname) = qname else { return };
        let pid = Self::parse_u32(&p, &["ProcessId", "PID"]).unwrap_or(0);
        let results: Option<String> = p.try_parse("QueryResults").ok();
        let answers = parse_dns_answers(results.as_deref());
        self.emit(RawEvent::DnsQuery { pid, qname, answers });
    }

    /// TaskScheduler 持久化检测（技术设计 §5.1 原文；M1 偏差表归位：原仅 RunKey
    /// 轮询、无计划任务覆盖）。事件语义：106=任务注册，140=任务更新，141=任务删除
    /// ——均属持久化面（141 单列"删除"语义，防误导调查；M4 待修清单 4）。
    /// pid 归因链（事件自身一般不携带）：
    /// ① 事件 ProcessId 字段（属监控树才采用）→ ② 实时扫描树内 cmdline 含注册
    /// 工具特征的进程 → ③ Exec 时缓存的候选（发起 cmd 常先于 106 退出，②必 miss
    /// ——复验竞态修复，detail 附 cmdline 供人工核对）→ ④ 0（未归因，引擎侧仍出
    /// Audit 判定，证据含 detail）。
    fn on_sched(&self, record: &EventRecord, loc: &SchemaLocator) {
        if !matches!(record.event_id(), 106 | 140 | 141) {
            return;
        }
        let Ok(schema) = loc.event_schema(record) else { return };
        let p = Parser::create(record, &schema);
        let task: Option<String> = p.try_parse::<String>("TaskName").ok().filter(|s| !s.is_empty());
        let Some(task) = task else { return };
        let user: String = p.try_parse::<String>("UserContext").unwrap_or_default();
        let kind = match record.event_id() {
            106 => "注册",
            140 => "更新",
            _ => "删除",
        };
        let event_pid = Self::parse_u32(&p, &["ProcessId", "ProcessID", "Pid"])
            .filter(|v| *v != 0 && self.procs.get(v).is_some());
        let (pid, how) = if let Some(v) = event_pid {
            (v, "已归因".to_string())
        } else if let Some(v) = self.scan_task_registrar() {
            (v, "已归因（实时扫描）".to_string())
        } else if let Some((v, cmdline)) = self.cached_task_registrar() {
            let brief: String = cmdline.chars().take(80).collect();
            (v, format!("缓存归因（进程已退出）：{brief}"))
        } else {
            (0, "未归因（无匹配注册进程）".to_string())
        };
        tracing::warn!("[持久化] 计划任务{kind}：{task}（user={user}，pid={pid}，{how}）");
        self.emit(RawEvent::Persistence {
            pid,
            kind: hg_model::PersistenceKind::SchedTask,
            detail: format!("计划任务{kind}：{task}（user={user}，pid={pid}，{how}）"),
        });
    }

    /// 实时归因扫描：监控树内 cmdline 含注册工具特征的进程（最近一个）。
    /// 无时间戳可依（Identity 不含 exec 时刻），属启发式归因——确定性不足时
    /// 返回 None，宁可缺归因不误归因。
    fn scan_task_registrar(&self) -> Option<Pid> {
        let mut found = None;
        for id in self.procs.snapshot() {
            if id.harness_root.is_none() {
                continue;
            }
            if is_task_registrar_cmdline(&id.cmdline) {
                found = Some(id.pid);
            }
        }
        found
    }

    /// Exec 时缓存含注册工具特征的候选（同 pid 覆盖；容量/时效封顶防涨）。
    fn remember_task_registrar(&self, pid: Pid, cmdline: &[std::ffi::OsString]) {
        if !is_task_registrar_cmdline(cmdline) {
            return;
        }
        let joined = cmdline.iter().map(|a| a.to_string_lossy()).collect::<Vec<_>>().join(" ");
        let mut g = self.sched_candidates.lock().unwrap();
        prune_sched_candidates(&mut g, Instant::now());
        g.retain(|c| c.pid != pid);
        g.push_back(SchedCandidate { pid, cmdline: joined, at: Instant::now() });
    }

    /// 取最新候选（供 106 事件归因兜底）；顺带做时效清理。
    fn cached_task_registrar(&self) -> Option<(Pid, String)> {
        let mut g = self.sched_candidates.lock().unwrap();
        prune_sched_candidates(&mut g, Instant::now());
        g.back().map(|c| (c.pid, c.cmdline.clone()))
    }
}

/// 候选表维护：清过期条目 + 容量封顶（预留下一个插入位，纯函数单测覆盖）。
fn prune_sched_candidates(g: &mut VecDeque<SchedCandidate>, now: Instant) {
    // duration_since 饱和（时钟回拨时按 0 计），不会 panic
    g.retain(|c| now.duration_since(c.at) < SCHED_CAND_MAX_AGE);
    while g.len() >= SCHED_CAND_CAP {
        g.pop_front();
    }
}

/// cmdline 是否含计划任务注册工具特征（小写匹配 [`SCHED_MARKERS`]；纯函数，单测覆盖）。
fn is_task_registrar_cmdline(cmdline: &[std::ffi::OsString]) -> bool {
    let joined = cmdline
        .iter()
        .map(|a| a.to_string_lossy().to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    SCHED_MARKERS.iter().any(|m| joined.contains(m))
}

/// QueryResults 形如 `type: 5 name; type: 1 1.2.3.4;`——提取其中的 IP。
fn chr_backslash() -> char {
    char::from_u32(0x5C).unwrap()
}

fn lexical_normalize(p: &str) -> PathBuf {
    let mut out: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    PathBuf::from(out.join("/"))
}

fn parse_dns_answers(results: Option<&str>) -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Some(s) = results {
        for part in s.split(';') {
            let token = part.trim().rsplit(' ').next().unwrap_or("");
            if let Ok(ip) = token.parse::<IpAddr>() {
                out.push(ip);
            }
        }
    }
    out
}

/// Windows ETW 事件源（实现 hg-platform::EventSource）。
pub struct EtwSource {
    inner: Arc<EtwInner>,
}

impl EtwSource {
    pub fn new(inner: Arc<EtwInner>) -> Self {
        Self { inner }
    }
}

impl hg_platform::EventSource for EtwSource {
    fn name(&self) -> &'static str {
        "etw-win"
    }

    fn run(self, tx: mpsc::Sender<Envelope>) -> std::convert::Infallible {
        let _ = self.inner.tx.set(tx.clone());
        let inner = self.inner;

        let process = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
            .add_callback({
                let inner = inner.clone();
                move |r, l| inner.on_process(r, l)
            })
            .build();
        let imgload = Provider::kernel(&kernel_providers::IMAGE_LOAD_PROVIDER)
            .add_callback({
                let inner = inner.clone();
                move |r, l| inner.on_image_load(r, l)
            })
            .build();
        let file = Provider::kernel(&kernel_providers::FILE_IO_PROVIDER)
            .add_callback({
                let inner = inner.clone();
                move |r, l| inner.on_file(r, l)
            })
            .build();
        let file_init = Provider::kernel(&kernel_providers::FILE_INIT_IO_PROVIDER)
            .add_callback({
                let inner = inner.clone();
                move |r, l| inner.on_file(r, l)
            })
            .build();
        let tcpip = Provider::kernel(&kernel_providers::TCP_IP_PROVIDER)
            .add_callback({
                let inner = inner.clone();
                move |r, l| inner.on_net(r, l)
            })
            .build();

        // 清理上次异常退出残留的同名会话（强杀不会停 ETW session；完整停机序列 §9.3 在 M4）
        let _ = ferrisetw::trace::stop_trace_by_name("HarnessGuard");
        let _ = ferrisetw::trace::stop_trace_by_name("HarnessGuardDns");
        let _ = ferrisetw::trace::stop_trace_by_name("HarnessGuardSched");

        let kernel_trace = KernelTrace::new()
            .named("HarnessGuard".into())
            .enable(process)
            .enable(imgload)
            .enable(file)
            .enable(file_init)
            .enable(tcpip)
            .start_and_process();
        match kernel_trace {
            Ok(_) => tracing::info!("ETW KernelTrace 已启动"),
            Err(e) => tracing::error!("ETW KernelTrace 启动失败（需管理员）: {e:?}"),
        }

        // Dns-Client：by GUID 挂独立 UserTrace（M0 轮 1/2 校准）
        let dns = Provider::by_guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d")
            .add_callback({
                let inner = inner.clone();
                move |r, l| inner.on_dns(r, l)
            })
            .build();
        let dns_trace = UserTrace::new()
            .named("HarnessGuardDns".into())
            .enable(dns)
            .start_and_process();
        match dns_trace {
            Ok(_) => tracing::info!("ETW UserTrace(Dns-Client) 已启动"),
            Err(e) => tracing::error!("ETW UserTrace(Dns-Client) 启动失败（需管理员）: {e:?}"),
        }

        // Microsoft-Windows-TaskScheduler（Operational 源 by GUID——实机复验修正：
        // 正确 GUID 为 de7b24ea-73c8-4a09-985d-5bdadcfa9017，注册表 Publishers 核对）：
        // 计划任务注册/更新 → Persistence 事件（M4 偏差归位；Operational 通道默认
        // 可能未启用，复验需 wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true）
        let sched = Provider::by_guid("de7b24ea-73c8-4a09-985d-5bdadcfa9017")
            .add_callback({
                let inner = inner.clone();
                move |r, l| inner.on_sched(r, l)
            })
            .build();
        let sched_trace = UserTrace::new()
            .named("HarnessGuardSched".into())
            .enable(sched)
            .start_and_process();
        match sched_trace {
            Ok(_) => tracing::info!("ETW UserTrace(TaskScheduler) 已启动"),
            Err(e) => tracing::error!("ETW UserTrace(TaskScheduler) 启动失败: {e:?}"),
        }

        // 事件源线程常驻（停机序列在进程退出时由 OS 回收 ETW session；M4 补优雅停机）
        loop {
            std::thread::park();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn args(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn 注册工具特征匹配矩阵() {
        assert!(is_task_registrar_cmdline(&args(&["cmd", "/c", "SCHTASKS", "/create", "/tn", "X"])), "大小写不敏感");
        assert!(is_task_registrar_cmdline(&args(&["powershell", "-Command", "Register-ScheduledTask", "-Name", "X"])));
        assert!(is_task_registrar_cmdline(&args(&["powershell", "-ComObj", "RegisterTask('x')"])), "COM RegisterTask 变体");
        assert!(!is_task_registrar_cmdline(&args(&["cmd", "/c", "type", "secret.txt"])));
        assert!(!is_task_registrar_cmdline(&args(&["git", "status"])));
        assert!(!is_task_registrar_cmdline(&[]), "空 cmdline 不匹配");
    }

    fn cand(pid: u32, cmdline: &str, at: Instant) -> SchedCandidate {
        SchedCandidate { pid, cmdline: cmdline.into(), at }
    }

    #[test]
    fn 候选表_容量封顶逐出最旧() {
        let mut g: VecDeque<SchedCandidate> = VecDeque::new();
        let now = Instant::now();
        for i in 0..(SCHED_CAND_CAP + 3) as u32 {
            g.push_back(cand(i, "schtasks /create", now));
        }
        prune_sched_candidates(&mut g, now);
        assert!(g.len() < SCHED_CAND_CAP, "预留下一个插入位");
        g.push_back(cand(9_999, "schtasks", now));
        assert!(g.len() <= SCHED_CAND_CAP, "插入后不超容量");
        assert!(g.iter().all(|c| c.pid != 0), "最旧的（pid=0 起）已被逐出");
    }

    #[test]
    fn 候选表_过期清理保留新鲜() {
        let mut g: VecDeque<SchedCandidate> = VecDeque::new();
        let now = Instant::now();
        g.push_back(cand(1, "schtasks", now - SCHED_CAND_MAX_AGE - std::time::Duration::from_secs(1)));
        g.push_back(cand(2, "schtasks", now));
        prune_sched_candidates(&mut g, now);
        assert_eq!(g.len(), 1);
        assert_eq!(g.front().unwrap().pid, 2, "过期候选被清理");
    }

    #[test]
    fn 候选缓存_同pid覆盖_非注册工具不入缓存() {
        let inner = EtwInner::new(Arc::new(ProcTable::new()), Arc::new(SourceStats::default()));
        inner.remember_task_registrar(100, &args(&["schtasks", "/create", "/tn", "A"]));
        inner.remember_task_registrar(101, &args(&["powershell", "-Command", "Register-ScheduledTask"]));
        let (pid, _) = inner.cached_task_registrar().expect("应有候选");
        assert_eq!(pid, 101, "取最新候选");
        // 同 pid 重新 Exec：覆盖旧候选而非并存
        inner.remember_task_registrar(100, &args(&["schtasks", "/delete", "/tn", "B"]));
        let (pid2, cmdline) = inner.cached_task_registrar().expect("应有候选");
        assert_eq!(pid2, 100);
        assert!(cmdline.contains("/delete"), "同 pid 覆盖旧候选");
        // 非注册工具 cmdline 不入缓存（不影响现有候选）
        inner.remember_task_registrar(102, &args(&["cmd", "/c", "dir"]));
        let (pid3, _) = inner.cached_task_registrar().expect("应有候选");
        assert_eq!(pid3, 100);
    }
}
