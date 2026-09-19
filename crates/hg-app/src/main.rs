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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    match std::env::args().nth(1).as_deref() {
        None | Some("run") => run_server(None),
        #[cfg(windows)]
        Some("service") => service::dispatch(),
        #[cfg(windows)]
        Some("install") => service::install(),
        #[cfg(windows)]
        Some("uninstall") => service::uninstall(),
        other => anyhow::bail!("未知参数 {other:?}；用法：harnessguard [run|service|install|uninstall]"),
    }
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
pub(crate) fn run_server(
    stop: Option<tokio::sync::watch::Receiver<bool>>,
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
    // 场景 C 字节计数补充路径（M4 复验定案：ETW send 事件为主路径；本机 estats
    // Set rc=50 不可用——轮询线程逐连接降级跳过，不影响主路径）：
    // estats 轮询按 monitored_quads 差分 DataBytesOut 补喂 ConnTx
    hg_plat_win::estats::spawn_estats_poll(inner);

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
                Ok(()) => tracing::info!("服务模式：Web token 已写入 {}", p.display()),
                Err(e) => tracing::error!("Web token 写盘失败（{}）：{e}", p.display()),
            }
        }
    }
    let bind = cfg.web.bind.clone();    let state = Arc::new(hg_web::AppState {
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
        tracing::info!("HarnessGuard 服务模式已启动，Web UI：http://{bind}/?token={token}");
    }

    rt.block_on(wait_for_stop(stop));

    // 停机序列（技术设计 §9.3）：ETW 会话显式回收（防残留——强杀会话不死，
    // M1 实测教训）→ 写通道全闭 → 运行时收尾释放执行器的 store_tx 克隆 →
    // writer 汇合冲刷（限时，防 SQLite 卡死阻塞停机）。
    // 已知限制（评审披露）：ETW 线程常驻持有 etw_tx 且 OnceLock 不可清空，
    // 引擎侧 recv 不会自然返回——执行器任务实为超时强制收尾，完整源侧可关闭
    // 通道留待后续（M4 报告待修清单）
    tracing::info!("停机序列：回收 ETW 会话");
    hg_plat_win::stop_etw_sessions();
    drop(store_tx);
    rt.shutdown_timeout(Duration::from_secs(2));
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
