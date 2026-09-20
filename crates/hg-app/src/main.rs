//! HarnessGuard 服务入口（技术设计 §2：配置加载、平台选择、组装装配）。
//! 运行形态：
//! - `run`（默认，无参）：控制台管理员模式（M1 行为，演示/调试用）
//! - `service`：SCM 服务宿主（M4 P2.8 归位；安装后由服务控制管理器拉起）
//! - `install` / `uninstall`：服务安装/卸载（含恢复策略配置，需管理员执行）

#[cfg(windows)]
mod service;

use std::path::PathBuf;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use hg_core::conn_registry::ConnRegistry;
use hg_core::engine::{Engine, EngineOutput};
use hg_core::health::{EngineStats, SourceStats};
use hg_core::proc_table::ProcTable;
use hg_core::rules::RulesSnapshot;
use hg_core::FileConfig;
use hg_model::{Envelope, Proto, StartTime};
use hg_platform::Enforcer;
use hg_store::writer::StoreOp;

fn main() -> anyhow::Result<()> {
    // 服务模式：滚动文件日志（Session 0 无 stderr；拍板见 M4 第二批报告——
    // 文件优先于 Event Log：无需消息清单注册、复验脚本可直接 tail）。
    // guard 随 main 存活，进程退出前 drop 刷写尾部日志（含停机序列）。
    let _log_guard = if std::env::args().nth(1).as_deref() == Some("service") {
        init_service_logging()
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .init();
        None
    };
    match std::env::args().nth(1).as_deref() {
        None | Some("run") => run_server(None, None),
        #[cfg(windows)]
        Some("service") => service::dispatch(),
        #[cfg(windows)]
        Some("install") => service::install(),
        #[cfg(windows)]
        Some("uninstall") => service::uninstall(),
        #[cfg(windows)]
        Some("enable-file-audit") => {
            let path = std::env::args()
                .nth(2)
                .ok_or_else(|| anyhow::anyhow!("用法：harnessguard enable-file-audit <目录>（需管理员，如工作区 .git）"))?;
            hg_plat_win::audit_setup::enable_file_audit(
                PathBuf::from(&path).as_path(),
                &hg_plat_win::audit_setup::cli_config_path(),
            )
        }
        #[cfg(windows)]
        Some("disable-file-audit") => {
            let path = std::env::args()
                .nth(2)
                .ok_or_else(|| anyhow::anyhow!("用法：harnessguard disable-file-audit <目录>（需管理员）"))?;
            hg_plat_win::audit_setup::disable_file_audit(
                PathBuf::from(&path).as_path(),
                &hg_plat_win::audit_setup::cli_config_path(),
            )
        }
        other => anyhow::bail!("未知参数 {other:?}；用法：harnessguard [run|service|install|uninstall|enable-file-audit <目录>|disable-file-audit <目录>]"),
    }
}

/// 服务模式日志初始化：exe 目录 logs/harnessguard.log.YYYY-MM-DD 按日轮转，
/// 非阻塞写（guard 返回给 main 持有，退出时刷尾）。启动时顺带清理过期日志。
/// 失败（目录不可建等）回落 stderr 并告警——日志不可用不得阻断服务启动。
fn init_service_logging() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::util::SubscriberInitExt;
    let dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("logs")));
    let fallback_stderr = || {
        // 日志目录不可用不得阻断服务启动：回落 stderr subscriber（前台调试
        // service 模式时仍可见；Session 0 下丢弃——评审 L-1，注释如实）
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .init();
    };
    let Some(dir) = dir else {
        eprintln!("[日志] 无法定位 exe 目录，日志回落 stderr（Session 0 下不可见）");
        fallback_stderr();
        return None;
    };
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("[日志] 创建日志目录失败（{}）：{e}，日志回落 stderr", dir.display());
        fallback_stderr();
        return None;
    }
    cleanup_old_logs(&dir, LOG_KEEP_DAYS);
    let appender = tracing_appender::rolling::daily(&dir, "harnessguard.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false) // 文件输出无 ANSI 转义
        .with_env_filter(filter)
        .finish()
        .init();
    Some(guard)
}

/// 日志保留天数（按日轮转，§8.2 自保护目录内；磁盘预算远小于 storage.max_disk_mb）
const LOG_KEEP_DAYS: i64 = 14;

/// 清理过期轮转日志（按文件名日期判定；非本命名模式的文件不动）。
fn cleanup_old_logs(dir: &std::path::Path, keep_days: i64) {
    let today = days_from_civil(today_ymd());
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if log_stale(&name, today, keep_days).unwrap_or(false) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// `harnessguard.log.YYYY-MM-DD` 是否过期（保留窗口外）；非本模式 None。
fn log_stale(name: &str, today: i64, keep_days: i64) -> Option<bool> {
    let date = name.strip_prefix("harnessguard.log.")?;
    let mut it = date.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(today - days_from_civil((y, m, d)) > keep_days)
}

/// 今天 (y, m, d)（UTC——与 tracing-appender rolling::daily 的文件名同为 UTC
/// 日期，天然一致；14 天窗口 >> 潜在本地时区 1 天偏差，不影响清理语义）
fn today_ymd() -> (i64, i64, i64) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    civil_from_days(days)
}

/// 儒略日 → 公历（Howard Hinnant civil_from_days 算法；单测锚定已知日期）
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 公历 → 儒略日（days_from_civil，Hinnant 算法；与 civil_from_days 互逆）
fn days_from_civil((y, m, d): (i64, i64, i64)) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// 等待停止信号：控制台模式等 Ctrl+C；服务模式等 SCM Stop（经 watch 通道，
/// Session 0 无控制台，Ctrl+C 分支仅为异常场景兜底）。
async fn wait_for_stop(mut stop: Option<tokio::sync::watch::Receiver<bool>>) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("收到 Ctrl+C"),
        _ = async {
            match stop.as_mut() {
                Some(rx) => rx.changed().await.ok(),
                None => std::future::pending::<Option<()>>().await,
            }
        } => tracing::info!("收到服务停止信号"),
    }
}

/// 服务主体（控制台/SCM 共用）：装配全链路并阻塞至停止信号，
/// 随后执行停机序列（技术设计 §9.3 摘要：ETW 会话回收 + 存储冲刷）。
/// `on_ready`：装配完成（含 Web 监听就绪）时回调——服务宿主据此上报 RUNNING
/// （此前 START_PENDING 已先行上报；控制台模式传 None）。
pub(crate) fn run_server(
    stop: Option<tokio::sync::watch::Receiver<bool>>,
    on_ready: Option<Box<dyn FnOnce() + Send>>,
) -> anyhow::Result<()> {
    // 配置路径：`run [config]` 或 `service [config]`；缺省当前目录 config.toml
    let args: Vec<String> = std::env::args().skip(1).collect();
    const MODES: [&str; 4] = ["run", "service", "install", "uninstall"];
    let cfg_path = PathBuf::from(match args.first().map(|s| s.as_str()) {
        Some(m) if MODES.contains(&m) => args.get(1).cloned().unwrap_or_else(|| "config.toml".into()),
        _ => args.first().cloned().unwrap_or_else(|| "config.toml".into()),
    });
    let cfg = if cfg_path.exists() {
        FileConfig::load(&cfg_path)?
    } else {
        std::fs::write(&cfg_path, FileConfig::default_toml())?;
        tracing::warn!("配置不存在，已写入默认配置：{}", cfg_path.display());
        FileConfig::default()
    };
    let db_path = cfg.storage.db_path.clone();
    hg_store::open(&db_path)?; // 确保库与 schema 就绪（写线程也会再开写连接）

    let whitelist = hg_store::writer::whitelist_paths(&db_path).unwrap_or_default();
    let snapshot = RulesSnapshot::compile(&cfg.to_rules_config(whitelist))?;
    let rules = Arc::new(ArcSwap::from_pointee(snapshot));

    let procs = Arc::new(ProcTable::new());
    let conns = Arc::new(ConnRegistry::new());
    let src_stats = Arc::new(SourceStats::default());
    let eng_stats = Arc::new(EngineStats::default());

    // 通道：事件流 mpsc(65536)（技术设计 §9.2）；引擎输出；存储写入；
    // SSE 多播（容量 1024：UI 消费慢则丢帧 + lagged 提示，不反压执行器）
    let (etw_tx, etw_rx) = tokio::sync::mpsc::channel::<Envelope>(65536);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<EngineOutput>(4096);
    let (store_tx, store_rx) = std::sync::mpsc::channel::<StoreOp>();
    let (sse_tx, _) = tokio::sync::broadcast::channel::<hg_web::SseEvent>(1024);
    let writer_handle = hg_store::writer::spawn_writer(&db_path, store_rx, cfg.storage.retention_days);

    // 平台事件源（Windows ETW）+ 持久化轮询
    let inner = hg_plat_win::EtwInner::new(procs.clone(), src_stats.clone());
    let source = hg_plat_win::EtwSource::new(inner.clone());
    let tx_src = etw_tx.clone();
    std::thread::Builder::new()
        .name("etw-source".into())
        .spawn(move || hg_platform::EventSource::run(source, tx_src))
        .expect("spawn ETW");
    std::thread::sleep(Duration::from_millis(800)); // 等 ETW 线程注入 tx 后再起轮询
    hg_plat_win::runkey::spawn_runkey_poll(inner.clone());
    // 场景 A opt-in 备选通道（拍板记录 11）：Security 4663 订阅。默认关——
    // 启用端需系统侧配置（auditpol + SACL，enable-file-audit 子命令）
    if cfg.file_audit.enabled {
        hg_plat_win::sec_audit::spawn_sec_audit(inner.clone(), cfg.file_audit.watch_paths.clone());
    } else if !cfg.file_audit.watch_paths.is_empty() {
        tracing::info!(
            "[file-audit] watch_paths 已配置但 enabled=false（enable-file-audit 子命令可开启系统侧与消费侧）"
        );
    }
    // 场景 C 字节计数补充路径（M4 复验定案：ETW send 事件为主路径；本机 estats
    // Set rc=50 不可用——轮询线程逐连接降级跳过，不影响主路径）：
    // estats 轮询按 monitored_quads 差分 DataBytesOut 补喂 ConnTx
    hg_plat_win::estats::spawn_estats_poll(inner.clone());
    let inner_shutdown = inner;

    // 启动补扫描（技术设计 §3.2）
    let entries: Vec<_> = hg_plat_win::bootstrap::snapshot_processes()
        .into_iter()
        .map(|e| (e.pid, e.ppid, PathBuf::from(e.exe), StartTime(e.start_time)))
        .collect();
    let n = procs.apply_bootstrap(&rules.load_full(), entries);
    tracing::info!("启动补扫描：{n} 个监控树进程入表");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // 引擎
    let engine = Arc::new(Engine::new(
        procs.clone(),
        conns.clone(),
        rules.clone(),
        out_tx,
        eng_stats.clone(),
    ));
    rt.spawn(engine.clone().run(etw_rx));

    // 执行器：处置/通知/落库/SSE 推送（异步路径，技术设计 §1.2）
    let enforcer = Arc::new(hg_plat_win::WinEnforcer::new());
    let notifier = Arc::new(hg_plat_win::WinNotifier::new());
    {
        let enforcer = enforcer.clone();
        let notifier = notifier.clone();
        let store_tx = store_tx.clone();
        let eng_stats = eng_stats.clone();
        let sse_tx = sse_tx.clone();
        rt.spawn(async move {
            while let Some(out) = out_rx.recv().await {
                execute(out, &enforcer, &notifier, &store_tx, &eng_stats, &sse_tx);
            }
        });
    }

    // Web UI（127.0.0.1 + 随机 token + Host 校验，需求 §6.2）
    let token = random_token();
    if stop.is_some() {
        // 服务模式（Session 0 无控制台，println 无人可见）：token 落 exe 目录
        // web-token.txt（评审修正：否则服务化后每次重启 token 随机且无处获取；
        // 文件 ACL 收紧入 M4 待修清单）
        if let Some(dir) =
            std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()))
        {
            let p = dir.join("web-token.txt");
            match std::fs::write(&p, format!("{token}\n")) {
                Ok(()) => {
                    // 写后立即应用拍板 14 DACL（管理员全控 + Users 只读）：
                    // 覆盖旧版仅管理员收紧态（特权进程持 WRITE_DAC），
                    // 非提权用户可直接读取取用
                    if let Err(e) = hg_plat_win::acl::protect_file(&p) {
                        tracing::error!("web-token.txt DACL 应用失败：{e:#}（文件可能仅管理员可读）");
                    }
                    tracing::info!("服务模式：Web token 已写入 {}（Users 可读）", p.display());
                }
                Err(e) => tracing::error!("Web token 写盘失败（{}）：{e}", p.display()),
            }
        }
    }
    let bind = cfg.web.bind.clone();
    // 自保护自检目标（cfg_path 随 AppState 移动，先克隆；db 取实际配置路径）
    let guard_files_seed: Vec<PathBuf> =
        vec![cfg_path.clone(), PathBuf::from(&db_path)];
    let state = Arc::new(hg_web::AppState {
        expected_host: bind.clone(),
        token: token.clone(),
        rules: rules.clone(),
        config: Arc::new(std::sync::RwLock::new(cfg)),
        config_path: cfg_path,
        db_path: db_path.clone(),
        procs: procs.clone(),
        conns: conns.clone(),
        src_stats: src_stats.clone(),
        eng_stats: eng_stats.clone(),
        store_tx: store_tx.clone(),
        sse: sse_tx,
        started: std::time::Instant::now(),
    });
    let app = hg_web::router(state);
    let listener = rt.block_on(tokio::net::TcpListener::bind(&bind))?;
    rt.spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("Web 服务退出：{e}");
        }
    });

    // 控制台横幅仅非服务模式打印（服务模式 Session 0 无 stdout，println!
    // 写失败会 panic——复验前预防性修复；服务模式改走 tracing）
    if stop.is_none() {
        println!("==================================================================");
        println!(" HarnessGuard M4 已启动（控制台模式；服务宿主：harnessguard install）");
        println!(" Web UI： http://{bind}/?token={token}");
        println!("==================================================================");
    } else {
        // token 不落日志（日志文件在未保护目录，防泄漏；token 见 web-token.txt）
        tracing::info!("HarnessGuard 服务模式已启动，Web UI：http://{bind}/（token 见安装目录 web-token.txt）");
        // 自保护自检（§8.2 / 待修 11）：配置/库/token（含 db WAL 衍生文件）
        // 未保护则告警并自愈应用（拍板 14 口径：管理员全控 + Users 只读，
        // 覆盖 install 后首次启动新建的文件与旧版仅管理员收紧态）
        let mut guard_files = guard_files_seed.clone();
        guard_files.push(PathBuf::from(format!("{db_path}-wal")));
        guard_files.push(PathBuf::from(format!("{db_path}-shm")));
        if let Some(dir) =
            std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()))
        {
            guard_files.push(dir.join("web-token.txt"));
        }
        hg_plat_win::acl::startup_selfcheck(&guard_files);
    }

    // 初始化完成（装配 + Web 监听就绪）：通知宿主（服务模式上报 RUNNING，
    // M4 待修清单 8）
    if let Some(cb) = on_ready {
        cb();
    }

    rt.block_on(wait_for_stop(stop));

    // 停机序列（技术设计 §9.3，完整化 M4 第二批 P1-6）：
    // ① 回收 ETW 会话（防残留——强杀会话不死，M1 实测教训；回调线程随进程退出）
    // ② 关闭事件通道（inner tx 置 None + 释放本函数持有的 etw_tx）→ 引擎
    //    recv 自然返回 → 执行器随 out_rx 关闭退出 → 释放 store_tx 克隆
    // ③ 运行时限时收尾（排水 + 兜底取消未竟任务）
    // ④ writer 汇合冲刷（限时，防 SQLite 卡死阻塞停机）
    tracing::info!("停机序列：回收 ETW 会话");
    hg_plat_win::stop_etw_sessions();
    inner_shutdown.close_channel();
    drop(etw_tx);
    tracing::info!("停机序列：事件通道已关闭（引擎排水中）");
    drop(store_tx);
    rt.shutdown_timeout(Duration::from_secs(3));
    tracing::info!("停机序列：运行时已收尾（引擎/执行器排水完成或超时兜底）");
    let (writer_done, writer_done_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let _ = writer_handle.join();
        let _ = writer_done.send(());
    });
    if writer_done_rx.recv_timeout(Duration::from_secs(3)).is_err() {
        tracing::error!("存储冲刷 3s 未完成，可能截断（WAL 下次启动恢复）");
    }
    tracing::info!("停机完成");
    Ok(())
}

fn execute(
    out: EngineOutput,
    enforcer: &Arc<hg_plat_win::WinEnforcer>,
    notifier: &Arc<hg_plat_win::WinNotifier>,
    store: &std::sync::mpsc::Sender<StoreOp>,
    stats: &Arc<EngineStats>,
    sse: &tokio::sync::broadcast::Sender<hg_web::SseEvent>,
) {
    match out {
        EngineOutput::Verdict { ts, pid, exe, verdict } => {
            // SSE 推送（技术设计 §7：无订阅者时发送即弃；ts 为 UTC 毫秒，与轮询行同构）
            let _ = sse.send(hg_web::SseEvent {
                event: "verdict",
                data: serde_json::json!({
                    "ts": ts,
                    "rule_id": verdict.rule_id.0,
                    "action": verdict.action.as_str(),
                    "pid": pid,
                    "exe": exe,
                    "summary": verdict.evidence.summary,
                })
                .to_string(),
            });
            let _ = store.send(StoreOp::Verdict {
                ts: ts as i64,
                rule_id: verdict.rule_id.0.to_string(),
                action: verdict.action.as_str().to_string(),
                pid: pid as i64,
                exe,
                evidence: serde_json::to_string(&serde_json::json!({
                    "summary": verdict.evidence.summary,
                    "detail": verdict.evidence.detail,
                }))
                .unwrap_or_default(),
                notified: 0,
            });
        }
        EngineOutput::Kill { pid, start_time, reason } => {
            stats.kills.fetch_add(1, Relaxed);
            tracing::warn!("[处置] 杀进程 {pid}：{reason}");
            if let Err(e) = enforcer.kill_process(pid, start_time) {
                tracing::error!("[处置] 杀进程失败：{e:#}");
            }
        }
        EngineOutput::DropTcp { quad, reason } => {
            stats.connections_dropped.fetch_add(1, Relaxed);
            tracing::warn!("[处置] 断连接 {} -> {}：{reason}", quad.local, quad.remote);
            if let Err(e) = enforcer.drop_tcp(quad) {
                tracing::error!("[处置] 断连接失败：{e:#}");
            }
        }
        EngineOutput::BlockIp { ip, ttl, reason } => {
            stats.ips_blocked.fetch_add(1, Relaxed);
            tracing::warn!("[处置] 封禁 {ip}（{:?}）：{reason}", ttl);
            if let Err(e) = enforcer.block_endpoint_temporary(ip, ttl) {
                tracing::error!("[处置] 封禁失败：{e:#}");
            }
        }
        EngineOutput::Notify { title, body } => {
            notifier.notify(&title, &body);
        }
        EngineOutput::StoreEvent { ts, kind, pid, detail } => {
            // SSE 推送审计事件（事件流页实时刷新；数据与 /api/events 行同构减 id）
            let _ = sse.send(hg_web::SseEvent {
                event: "audit",
                data: serde_json::json!({
                    "ts": ts,
                    "kind": kind,
                    "pid": pid,
                    "detail": detail,
                })
                .to_string(),
            });
            let _ = store.send(StoreOp::Event {
                ts: ts as i64,
                pid: pid as i64,
                start_ts: 0,
                kind,
                detail: detail.to_string(),
            });
        }
        EngineOutput::StoreProcess { pid, start_ts, exe, cmdline, harness_root, exit_ts } => {
            let _ = store.send(StoreOp::Process {
                pid: pid as i64,
                start_ts: start_ts as i64,
                exe,
                cmdline,
                harness_root,
                exit_ts: exit_ts.map(|t| t as i64),
            });
        }
        EngineOutput::StoreConn { conn_id, pid, harness_root, remote, proto, bytes_out, opened_ts, closed_ts } => {
            let _ = store.send(StoreOp::Conn {
                conn_id: format!("c{}", conn_id.0),
                pid: pid as i64,
                harness_root,
                remote_ip: remote.ip().to_string(),
                remote_port: remote.port() as i64,
                proto: match proto {
                    Proto::Tcp => "tcp".into(),
                    Proto::Udp => "udp".into(),
                },
                bytes_out: bytes_out as i64,
                opened_ts: opened_ts as i64,
                closed_ts: closed_ts as i64,
            });
        }
        EngineOutput::StoreDns { qname, ip, pid, ts } => {
            let _ = store.send(StoreOp::Dns {
                qname,
                ip: ip.to_string(),
                pid: pid as i64,
                ts: ts as i64,
            });
        }
    }
}

fn random_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 18];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 儒略日互逆与已知日期锚定() {
        // 已知锚点：1970-01-01 = 0，2000-03-01 = 11017（Hinnant 算法文献值）
        assert_eq!(days_from_civil((1970, 1, 1)), 0);
        assert_eq!(days_from_civil((2000, 3, 1)), 11017);
        // 互逆：随机取几个日期往返
        for (y, m, d) in [(2026, 9, 20), (2024, 2, 29), (1999, 12, 31), (2100, 3, 1)] {
            assert_eq!(civil_from_days(days_from_civil((y, m, d))), (y, m, d));
        }
    }

    #[test]
    fn 日志过期判定矩阵() {
        let today = days_from_civil((2026, 9, 20));
        assert_eq!(log_stale("harnessguard.log.2026-09-20", today, 14), Some(false));
        assert_eq!(log_stale("harnessguard.log.2026-09-06", today, 14), Some(false), "恰好 14 天：保留");
        assert_eq!(log_stale("harnessguard.log.2026-09-05", today, 14), Some(true), "超过 14 天：清理");
        // 非本命名模式 / 非法日期：不动
        assert_eq!(log_stale("harnessguard.log", today, 14), None);
        assert_eq!(log_stale("other.log.2020-01-01", today, 14), None);
        assert_eq!(log_stale("harnessguard.log.2026-13-01", today, 14), None);
        assert_eq!(log_stale("harnessguard.log.2026-09", today, 14), None);
        assert_eq!(log_stale("harnessguard.log.0000-01-01", today, 14), None, "年份越界不动");
    }
}
