//! M0 Windows spike（技术设计 §11 验收项）：
//! 1. ferrisetw 消费 Kernel-Process / Kernel-Network(TCP-IP) / Dns-Client 的可用性与事件速率；
//! 2. Kernel-File 的 FileObject→Name 关联成功率（缓存方案，统计 unknown 率）；
//! 3. 实测 RSS 对照技术设计 §10 预估区间（30–55MB）。
//!
//! 需管理员权限运行（ETW kernel session）。用法：etw_spike.exe [采样秒数，默认 30]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ferrisetw::parser::{Parser, Pointer};
use ferrisetw::provider::{kernel_providers, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{KernelTrace, UserTrace};
use ferrisetw::EventRecord;

// ---- 进程 provider 计数 ----
static PROC_STARTS: AtomicU64 = AtomicU64::new(0);
static PROC_STOPS: AtomicU64 = AtomicU64::new(0);
static PROC_IMG_OK: AtomicU64 = AtomicU64::new(0);
static PROC_SAMPLES: AtomicU64 = AtomicU64::new(0);

// ---- 文件 provider 计数 ----
static FILE_TOTAL: AtomicU64 = AtomicU64::new(0);
static FILE_NAME_EVENTS: AtomicU64 = AtomicU64::new(0); // 自带 FileName 的事件（建缓存）
static FILE_RESOLVED: AtomicU64 = AtomicU64::new(0); // 无名但缓存命中
static FILE_UNRESOLVED: AtomicU64 = AtomicU64::new(0); // 无名且缓存未命中（unknown）
static FILE_NOOBJ: AtomicU64 = AtomicU64::new(0); // 连 FileObject 都取不到

static FILE_OBJ_CACHE: Mutex<Option<HashMap<u64, String>>> = Mutex::new(None);
const CACHE_CAP: usize = 262_144; // 缓存条目上限（控内存：约 262k × ~100B ≈ 25MB 上界）

// ---- 网络 provider 计数 ----
static NET_TOTAL: AtomicU64 = AtomicU64::new(0);
static NET_SIZE_SUM: AtomicU64 = AtomicU64::new(0);
static NET_ADDR_OK: AtomicU64 = AtomicU64::new(0);
static NET_SAMPLES: AtomicU64 = AtomicU64::new(0);

// ---- DNS provider 计数 ----
static DNS_TOTAL: AtomicU64 = AtomicU64::new(0);
static DNS_QUERY_OK: AtomicU64 = AtomicU64::new(0);
static DNS_SAMPLES: AtomicU64 = AtomicU64::new(0);

// ---- manifest 版 Kernel-Process 计数（补充验证：经典 kernel 事件无 ImageName）----
static MP_TOTAL: AtomicU64 = AtomicU64::new(0);
static MP_STARTS: AtomicU64 = AtomicU64::new(0);
static MP_STOPS: AtomicU64 = AtomicU64::new(0);
static MP_IMG_OK: AtomicU64 = AtomicU64::new(0);
static MP_CMD_OK: AtomicU64 = AtomicU64::new(0);
static MP_SAMPLES: AtomicU64 = AtomicU64::new(0);

// ---- Image Load 计数（M1 进程 exe 路径来源：经典 Process 事件无 ImageName）----
static IL_TOTAL: AtomicU64 = AtomicU64::new(0);
static IL_NAME_OK: AtomicU64 = AtomicU64::new(0);
static IL_SAMPLES: AtomicU64 = AtomicU64::new(0);

// opcode 分布（事件分类自发现：不预设 opcode 语义，按实测归纳）
static FILE_OPCODES: Mutex<Option<HashMap<u8, u64>>> = Mutex::new(None);
static NET_OPCODES: Mutex<Option<HashMap<u8, u64>>> = Mutex::new(None);

fn bump(map: &Mutex<Option<HashMap<u8, u64>>>, opcode: u8) {
    let mut g = map.lock().unwrap();
    g.get_or_insert_with(HashMap::new)
        .entry(opcode)
        .and_modify(|c| *c += 1)
        .or_insert(1);
}

/// 内核 MOF 与 manifest provider 的字段命名不一致（ProcessId/ProcessID/PID），
/// 多变体依次尝试。
fn parse_u32(p: &Parser, names: &[&str]) -> Option<u32> {
    for n in names {
        if let Ok(v) = p.try_parse(n) {
            return Some(v);
        }
    }
    None
}

fn on_process(record: &EventRecord, loc: &SchemaLocator) {
    let op = record.opcode();
    if op == 1 {
        PROC_STARTS.fetch_add(1, Relaxed);
    } else if op == 2 {
        PROC_STOPS.fetch_add(1, Relaxed);
        return;
    } else {
        return;
    }
    let Ok(schema) = loc.event_schema(record) else { return };
    let p = Parser::create(record, &schema);
    let pid = parse_u32(&p, &["ProcessId", "ProcessID"]).unwrap_or(0);
    let ppid = parse_u32(&p, &["ParentId", "ParentID"]).unwrap_or(0);
    let img: Option<String> = p.try_parse::<String>("ImageName").ok().filter(|s| !s.is_empty());
    if img.is_some() {
        PROC_IMG_OK.fetch_add(1, Relaxed);
    }
    if PROC_SAMPLES.fetch_add(1, Relaxed) < 5 {
        println!("[proc 样例] start pid={pid} ppid={ppid} image={img:?}");
    }
}

fn on_file(record: &EventRecord, loc: &SchemaLocator) {
    FILE_TOTAL.fetch_add(1, Relaxed);
    bump(&FILE_OPCODES, record.opcode());
    let Ok(schema) = loc.event_schema(record) else { return };
    let p = Parser::create(record, &schema);
    let name: Option<String> = p.try_parse::<String>("FileName").ok().filter(|s| !s.is_empty());
    let obj: Option<u64> = p
        .try_parse::<Pointer>("FileObject")
        .ok()
        .map(|ptr| *ptr as u64);

    match (name, obj) {
        (Some(n), Some(fo)) => {
            FILE_NAME_EVENTS.fetch_add(1, Relaxed);
            let mut g = FILE_OBJ_CACHE.lock().unwrap();
            let m = g.get_or_insert_with(HashMap::new);
            if m.len() < CACHE_CAP {
                m.insert(fo, n);
            }
        }
        (None, Some(fo)) => {
            let hit = FILE_OBJ_CACHE
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|m| m.contains_key(&fo));
            if hit {
                FILE_RESOLVED.fetch_add(1, Relaxed);
            } else {
                FILE_UNRESOLVED.fetch_add(1, Relaxed);
            }
        }
        _ => {
            FILE_NOOBJ.fetch_add(1, Relaxed);
        }
    }
}

fn on_net(record: &EventRecord, loc: &SchemaLocator) {
    NET_TOTAL.fetch_add(1, Relaxed);
    bump(&NET_OPCODES, record.opcode());
    let Ok(schema) = loc.event_schema(record) else { return };
    let p = Parser::create(record, &schema);
    if let Some(size) = parse_u32(&p, &["size", "Size"]) {
        NET_SIZE_SUM.fetch_add(size as u64, Relaxed);
    }
    if p.try_parse::<IpAddr>("daddr").is_ok() {
        NET_ADDR_OK.fetch_add(1, Relaxed);
    }
    if NET_SAMPLES.fetch_add(1, Relaxed) < 5 {
        let daddr: Option<IpAddr> = p.try_parse("daddr").ok();
        let saddr: Option<IpAddr> = p.try_parse("saddr").ok();
        let dport = parse_u32(&p, &["dport"]).unwrap_or(0);
        let pid = parse_u32(&p, &["PID", "ProcessId"]).unwrap_or(0);
        println!("[net 样例] opcode={} pid={pid} {saddr:?} -> {daddr:?}:{dport}", record.opcode());
    }
}

fn on_dns(record: &EventRecord, loc: &SchemaLocator) {
    DNS_TOTAL.fetch_add(1, Relaxed);
    let Ok(schema) = loc.event_schema(record) else { return };
    let p = Parser::create(record, &schema);
    let q: Option<String> = p.try_parse::<String>("QueryName").ok().filter(|s| !s.is_empty());
    if q.is_some() {
        DNS_QUERY_OK.fetch_add(1, Relaxed);
    }
    if DNS_SAMPLES.fetch_add(1, Relaxed) < 5 {
        let r: Option<String> = p.try_parse("QueryResults").ok();
        println!("[dns 样例] event_id={} qname={q:?} results={r:?}", record.event_id());
    }
}

/// manifest 版 Microsoft-Windows-Kernel-Process（GUID 22FB2CD6-0EF7-4A76-A270-5D6C8A5AE9E5）
/// 事件 1=ProcessStart 2=ProcessStop，验证 ImageName/CommandLine 可用性。
fn on_manifest_process(record: &EventRecord, loc: &SchemaLocator) {
    MP_TOTAL.fetch_add(1, Relaxed);
    let eid = record.event_id();
    if eid == 1 {
        MP_STARTS.fetch_add(1, Relaxed);
    } else if eid == 2 {
        MP_STOPS.fetch_add(1, Relaxed);
    }
    let Ok(schema) = loc.event_schema(record) else { return };
    let p = Parser::create(record, &schema);
    if eid != 1 {
        return;
    }
    let img: Option<String> = p.try_parse::<String>("ImageName").ok().filter(|s| !s.is_empty());
    let cmd: Option<String> = p.try_parse::<String>("CommandLine").ok().filter(|s| !s.is_empty());
    if img.is_some() {
        MP_IMG_OK.fetch_add(1, Relaxed);
    }
    if cmd.is_some() {
        MP_CMD_OK.fetch_add(1, Relaxed);
    }
    if MP_SAMPLES.fetch_add(1, Relaxed) < 5 {
        let pid = parse_u32(&p, &["ProcessID", "ProcessId"]).unwrap_or(0);
        let ppid = parse_u32(&p, &["ParentProcessID", "ParentId"]).unwrap_or(0);
        println!("[mp 样例] start pid={pid} ppid={ppid} image={img:?} cmdline={cmd:?}");
    }
}

/// Image Load 事件（opcode 10 = Load）：FileBase/FileName（完整 NT 路径）。
/// M1 进程身份的 exe 路径来源。
fn on_image_load(record: &EventRecord, loc: &SchemaLocator) {
    IL_TOTAL.fetch_add(1, Relaxed);
    if record.opcode() != 10 {
        return;
    }
    let Ok(schema) = loc.event_schema(record) else { return };
    let p = Parser::create(record, &schema);
    let name: Option<String> = p.try_parse::<String>("FileName").ok().filter(|s| !s.is_empty());
    if name.is_some() {
        IL_NAME_OK.fetch_add(1, Relaxed);
    }
    if IL_SAMPLES.fetch_add(1, Relaxed) < 5 {
        let pid = parse_u32(&p, &["ProcessID", "ProcessId"]).unwrap_or(0);
        println!("[img 样例] pid={pid} file={name:?}");
    }
}

#[derive(Clone)]
struct Snap {
    proc_starts: u64,
    file_total: u64,
    net_total: u64,
    dns_total: u64,
}

fn snap() -> Snap {
    Snap {
        proc_starts: PROC_STARTS.load(Relaxed),
        file_total: FILE_TOTAL.load(Relaxed),
        net_total: NET_TOTAL.load(Relaxed),
        dns_total: DNS_TOTAL.load(Relaxed),
    }
}

fn print_rss() {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    unsafe {
        let mut pmc = PROCESS_MEMORY_COUNTERS::default();
        pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let h: HANDLE = GetCurrentProcess();
        if GetProcessMemoryInfo(h, &mut pmc, pmc.cb) != 0 {
            println!(
                "RSS 当前 {:.1} MB / 峰值 {:.1} MB / 私有提交 {:.1} MB",
                pmc.WorkingSetSize as f64 / 1048576.0,
                pmc.PeakWorkingSetSize as f64 / 1048576.0,
                pmc.PagefileUsage as f64 / 1048576.0
            );
        } else {
            println!("RSS 读取失败");
        }
    }
}

fn main() {
    let secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let mode = std::env::args().nth(2).unwrap_or_default();
    match mode.as_str() {
        "manifest" => run_manifest_spike(secs, false),
        // KernelTrace 会话自动附加 EVENT_TRACE_SYSTEM_LOGGER_MODE，
        // manifest 内核 provider（Kernel-Process）挂普通 UserTrace 无事件，须挂 KernelTrace
        "km" => run_manifest_spike(secs, true),
        _ => run_kernel_spike(secs),
    }
}

/// 补充 spike：manifest 版 Kernel-Process（ImageName/CommandLine 可用性）+
/// Dns-Client 按 GUID 直连（by_name 在本机返回 PlaError::NotFound）。
fn run_manifest_spike(secs: u64, kernel_session: bool) {
    let session_kind = if kernel_session { "KernelTrace" } else { "UserTrace" };
    println!("== M0 补充 spike（{session_kind} + manifest Kernel-Process + Dns-Client）：{secs}s ==");
    let kp = Provider::by_guid("22fb2cd6-0ef7-4a76-a270-5d6c8a5ae9e5")
        .add_callback(on_manifest_process)
        .build();
    let dns = Provider::by_guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d")
        .add_callback(on_dns)
        .build();
    /// KernelTrace 与 UserTrace 类型不同，用枚举统一持有（spike 内部专用）。
    enum AnyTrace {
        K(KernelTrace),
        U(UserTrace),
    }
    impl AnyTrace {
        fn stop(self) {
            match self {
                AnyTrace::K(t) => {
                    let _ = t.stop();
                }
                AnyTrace::U(t) => {
                    let _ = t.stop();
                }
            }
        }
    }
    let started = if kernel_session {
        KernelTrace::new()
            .named("HgSpikeKm".into())
            .enable(kp)
            .enable(dns)
            .start_and_process()
            .map(AnyTrace::K)
    } else {
        UserTrace::new()
            .named("HgSpikeUser".into())
            .enable(kp)
            .enable(dns)
            .start_and_process()
            .map(AnyTrace::U)
    };
    let trace = match started {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{session_kind} 启动失败（需管理员权限）：{e:?}");
            return;
        }
    };
    println!("{session_kind}（Kernel-Process manifest + Dns-Client）已启动");
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(secs) {
        std::thread::sleep(Duration::from_secs(5));
        println!(
            "[{:>4}s] 累计：KP 事件 {}（启动 {}）| DNS 事件 {}（QueryName 成功 {}）",
            start.elapsed().as_secs(),
            MP_TOTAL.load(Relaxed),
            MP_STARTS.load(Relaxed),
            DNS_TOTAL.load(Relaxed),
            DNS_QUERY_OK.load(Relaxed)
        );
    }
    let _ = trace.stop();
    std::thread::sleep(Duration::from_millis(800));
    let total = start.elapsed().as_secs_f64();
    println!("\n===== manifest 模式汇总（{total:.0}s）=====");
    println!(
        "[Kernel-Process manifest] 总事件 {} | 启动 {}（{:.1}/s）| 停止 {} | ImageName 成功 {} | CommandLine 成功 {}",
        MP_TOTAL.load(Relaxed),
        MP_STARTS.load(Relaxed),
        MP_STARTS.load(Relaxed) as f64 / total,
        MP_STOPS.load(Relaxed),
        MP_IMG_OK.load(Relaxed),
        MP_CMD_OK.load(Relaxed)
    );
    println!(
        "[Dns-Client by GUID] 总事件 {} | QueryName 解析成功 {}",
        DNS_TOTAL.load(Relaxed),
        DNS_QUERY_OK.load(Relaxed)
    );
    println!("[内存] spike 进程：");
    print_rss();
    println!("===== spike 结束 =====");
}

fn run_kernel_spike(secs: u64) {
    println!("== HarnessGuard M0 Windows spike：采样 {secs}s，进程 PID={} ==", std::process::id());

    let process = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
        .add_callback(on_process)
        .build();
    let file = Provider::kernel(&kernel_providers::FILE_IO_PROVIDER)
        .add_callback(on_file)
        .build();
    let file_init = Provider::kernel(&kernel_providers::FILE_INIT_IO_PROVIDER)
        .add_callback(on_file)
        .build();
    let tcpip = Provider::kernel(&kernel_providers::TCP_IP_PROVIDER)
        .add_callback(on_net)
        .build();
    let imgload = Provider::kernel(&kernel_providers::IMAGE_LOAD_PROVIDER)
        .add_callback(on_image_load)
        .build();

    let kernel_trace = match KernelTrace::new()
        .named("HgSpikeKernel".into())
        .enable(process)
        .enable(file)
        .enable(file_init)
        .enable(tcpip)
        .enable(imgload)
        .start_and_process()
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("KernelTrace 启动失败（需管理员权限）：{e:?}");
            return;
        }
    };
    println!("KernelTrace（Process/File/TCP-IP）已启动");

    let dns_trace = match Provider::by_name("Microsoft-Windows-Dns-Client") {
        Ok(b) => match b.add_callback(on_dns).build() {
            provider => match UserTrace::new().named("HgSpikeDns".into()).enable(provider).start_and_process() {
                Ok(t) => {
                    println!("UserTrace（Dns-Client）已启动");
                    Some(t)
                }
                Err(e) => {
                    eprintln!("UserTrace(Dns-Client) 启动失败：{e:?}");
                    None
                }
            },
        },
        Err(e) => {
            eprintln!("Dns-Client provider 解析失败：{e:?}");
            None
        }
    };

    // 周期采样输出（事件速率）
    let start = Instant::now();
    let mut last = snap();
    while start.elapsed() < Duration::from_secs(secs) {
        std::thread::sleep(Duration::from_secs(5));
        let now = snap();
        println!(
            "[{:>4}s] 速率/s：进程启动 {:.1} | 文件 {:.0} | 网络 {:.1} | DNS {:.1}",
            start.elapsed().as_secs(),
            (now.proc_starts - last.proc_starts) as f64 / 5.0,
            (now.file_total - last.file_total) as f64 / 5.0,
            (now.net_total - last.net_total) as f64 / 5.0,
            (now.dns_total - last.dns_total) as f64 / 5.0,
        );
        last = now;
    }

    let _ = kernel_trace.stop();
    if let Some(t) = dns_trace {
        let _ = t.stop();
    }
    std::thread::sleep(Duration::from_millis(800)); // 等处理线程排空尾部事件

    let total = start.elapsed().as_secs_f64();
    println!("\n===== 汇总（{total:.0}s）=====");
    println!(
        "[Kernel-Process] 启动 {}（{:.1}/s）停止 {} ImageName 解析成功 {}",
        PROC_STARTS.load(Relaxed),
        PROC_STARTS.load(Relaxed) as f64 / total,
        PROC_STOPS.load(Relaxed),
        PROC_IMG_OK.load(Relaxed)
    );
    println!(
        "[Image-Load] 总事件 {} | Load(op10) FileName 解析成功 {}",
        IL_TOTAL.load(Relaxed),
        IL_NAME_OK.load(Relaxed)
    );
    let name_ev = FILE_NAME_EVENTS.load(Relaxed);
    let resolved = FILE_RESOLVED.load(Relaxed);
    let unresolved = FILE_UNRESOLVED.load(Relaxed);
    let noobj = FILE_NOOBJ.load(Relaxed);
    let cache_n = FILE_OBJ_CACHE.lock().unwrap().as_ref().map_or(0, |m| m.len());
    println!(
        "[Kernel-File] 总事件 {}（{:.0}/s）| Name事件 {} | 缓存命中 {} | unknown {} | 无FileObject {}",
        FILE_TOTAL.load(Relaxed),
        FILE_TOTAL.load(Relaxed) as f64 / total,
        name_ev,
        resolved,
        unresolved,
        noobj
    );
    if resolved + unresolved > 0 {
        println!(
            "  FileObject→Name 关联成功率：{:.2}%（unknown 率 {:.2}%），缓存条目 {cache_n}（上限 {CACHE_CAP}）",
            resolved as f64 / (resolved + unresolved) as f64 * 100.0,
            unresolved as f64 / (resolved + unresolved) as f64 * 100.0
        );
    }
    if let Some(m) = FILE_OPCODES.lock().unwrap().as_ref() {
        let mut v: Vec<_> = m.iter().collect();
        v.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        let top: Vec<String> = v.iter().take(10).map(|(o, c)| format!("op{o}:{c}")).collect();
        println!("  文件 opcode 分布（前10）：{}", top.join(" "));
    }
    println!(
        "[Kernel-Network] 总事件 {}（{:.1}/s）| size 字段累计 {} 字节（{:.1} MB）| daddr 解析成功 {}",
        NET_TOTAL.load(Relaxed),
        NET_TOTAL.load(Relaxed) as f64 / total,
        NET_SIZE_SUM.load(Relaxed),
        NET_SIZE_SUM.load(Relaxed) as f64 / 1048576.0,
        NET_ADDR_OK.load(Relaxed)
    );
    if let Some(m) = NET_OPCODES.lock().unwrap().as_ref() {
        let mut v: Vec<_> = m.iter().collect();
        v.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        let top: Vec<String> = v.iter().take(10).map(|(o, c)| format!("op{o}:{c}")).collect();
        println!("  网络 opcode 分布（前10）：{}", top.join(" "));
    }
    println!(
        "[Dns-Client] 总事件 {} | QueryName 解析成功 {}",
        DNS_TOTAL.load(Relaxed),
        DNS_QUERY_OK.load(Relaxed)
    );
    println!("[内存] spike 进程（ferrisetw 三会话 + FileObject 缓存）：");
    print_rss();
    println!("===== spike 结束 =====");
}
