//! HarnessGuard 服务入口（技术设计 §2：配置加载、平台选择、组装装配）。
//! M1：Windows 控制台模式（管理员运行）；windows-service 宿主化与完整停机
//! 序列（§9.3）在 M4。

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

    let cfg_path = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "config.toml".into()),
    );
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

    // 通道：事件流 mpsc(65536)（技术设计 §9.2）；引擎输出；存储写入
    let (etw_tx, etw_rx) = tokio::sync::mpsc::channel::<Envelope>(65536);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<EngineOutput>(4096);
    let (store_tx, store_rx) = std::sync::mpsc::channel::<StoreOp>();
    hg_store::writer::spawn_writer(&db_path, store_rx);

    // 平台事件源（Windows ETW）+ 持久化轮询
    let inner = hg_plat_win::EtwInner::new(procs.clone(), src_stats.clone());
    let source = hg_plat_win::EtwSource::new(inner.clone());
    let tx_src = etw_tx.clone();
    std::thread::Builder::new()
        .name("etw-source".into())
        .spawn(move || hg_platform::EventSource::run(source, tx_src))
        .expect("spawn ETW");
    std::thread::sleep(Duration::from_millis(800)); // 等 ETW 线程注入 tx 后再起轮询
    hg_plat_win::runkey::spawn_runkey_poll(inner);

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

    // 执行器：处置/通知/落库（异步路径，技术设计 §1.2）
    let enforcer = Arc::new(hg_plat_win::WinEnforcer::new());
    let notifier = Arc::new(hg_plat_win::WinNotifier::new());
    {
        let enforcer = enforcer.clone();
        let notifier = notifier.clone();
        let store_tx = store_tx.clone();
        let eng_stats = eng_stats.clone();
        rt.spawn(async move {
            while let Some(out) = out_rx.recv().await {
                execute(out, &enforcer, &notifier, &store_tx, &eng_stats);
            }
        });
    }

    // Web UI（127.0.0.1 + 随机 token + Host 校验，需求 §6.2）
    let token = random_token();
    let bind = cfg.web.bind.clone();
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
        started: std::time::Instant::now(),
    });
    let app = hg_web::router(state);
    let listener = rt.block_on(tokio::net::TcpListener::bind(&bind))?;
    rt.spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("Web 服务退出：{e}");
        }
    });

    println!("==================================================================");
    println!(" HarnessGuard M1 已启动（控制台模式）");
    println!(" Web UI： http://{bind}/?token={token}");
    println!("==================================================================");

    rt.block_on(async {
        let _ = tokio::signal::ctrl_c().await;
    });
    tracing::info!("收到 Ctrl+C：M1 直接退出（ETW session 随进程回收；完整停机序列 §9.3 在 M4）");
    Ok(())
}

fn execute(
    out: EngineOutput,
    enforcer: &Arc<hg_plat_win::WinEnforcer>,
    notifier: &Arc<hg_plat_win::WinNotifier>,
    store: &std::sync::mpsc::Sender<StoreOp>,
    stats: &Arc<EngineStats>,
) {
    match out {
        EngineOutput::Verdict { ts, pid, exe, verdict } => {
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
