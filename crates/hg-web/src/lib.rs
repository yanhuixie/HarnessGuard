//! Web UI 服务（技术设计 §7）：
//! - 仅监听 127.0.0.1（装配方保证）；随机 token；`Authorization: Bearer` 鉴权；
//! - Host 校验中间件（防 DNS rebinding，需求 §6.2）；
//! - 静态资源 rust-embed 嵌入（无构建前端）；
//! - `/api/stream`（SSE）实时推送判定与审计事件（M4 接入，替换 M1 的 UI 3s 轮询）；
//!   鉴权例外：query token 仅放行本端点（拍板记录 8——EventSource 无法带 header）。
//!
//! 已知偏差（相对设计 §7）：封禁 WFP→netsh 见 M1 报告（M4 换 FwpmFilterAdd）。

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use hg_core::conn_registry::ConnRegistry;
use hg_core::health::{EngineStats, SourceStats};
use hg_core::proc_table::ProcTable;
use hg_core::rules::RulesSnapshot;
use hg_core::FileConfig;
use rust_embed::Embed;
use serde::Deserialize;
use serde_json::json;
use tokio_stream::StreamExt;

#[derive(Embed)]
#[folder = "../../ui/"]
struct Assets;

/// SSE 推送事件：`event` 为事件名（verdict/audit），`data` 为预序列化 JSON。
/// 经 broadcast 通道多播给所有已连接的 UI（无订阅者时发送即弃，不阻塞执行器）。
#[derive(Debug, Clone)]
pub struct SseEvent {
    pub event: &'static str,
    pub data: String,
}

pub struct AppState {
    pub token: String,
    /// Host 校验目标（配置的 127.0.0.1:port）
    pub expected_host: String,
    pub rules: Arc<ArcSwap<RulesSnapshot>>,
    pub config: Arc<RwLock<FileConfig>>,
    pub config_path: PathBuf,
    pub db_path: String,
    pub procs: Arc<ProcTable>,
    pub conns: Arc<ConnRegistry>,
    pub src_stats: Arc<SourceStats>,
    pub eng_stats: Arc<EngineStats>,
    /// 存储写入通道（执行器落库同一通道）：手动清理经 StoreOp::Purge
    /// 转入写入线程执行（技术设计 §4：唯一 DELETE 路径）
    pub store_tx: std::sync::mpsc::Sender<hg_store::writer::StoreOp>,
    /// SSE 多播通道（执行器喂入，/api/stream 订阅）
    pub sse: tokio::sync::broadcast::Sender<SseEvent>,
    pub started: Instant,
}

impl AppState {
    /// 白名单/配置变更后重建规则快照并原子替换（热更新，技术设计 §3.3）。
    pub fn rebuild_rules(&self) -> anyhow::Result<()> {
        let wl = hg_store::writer::whitelist_paths(&self.db_path).unwrap_or_default();
        let cfg = self.config.read().unwrap();
        let snap = RulesSnapshot::compile(&cfg.to_rules_config(wl))?;
        self.rules.store(Arc::new(snap));
        Ok(())
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/api/status", get(status))
        .route("/api/verdicts", get(verdicts))
        .route("/api/events", get(events))
        .route("/api/processes", get(processes))
        .route("/api/whitelist", get(wl_list).post(wl_add))
        .route("/api/whitelist", delete(wl_del))
        .route("/api/config", get(config_get).put(config_put))
        .route("/api/data/clear", post(data_clear))
        .route("/api/stream", get(stream));
    Router::new()
        .route("/", get(index))
        .merge(api.route_layer(middleware::from_fn_with_state(state.clone(), auth)))
        .with_state(state)
}

/// Bearer 鉴权 + Host 校验（仅 /api/*；静态首页为壳页面不鉴权）。
/// SSE 例外（技术设计 §7 / 拍板记录 8）：query token 仅放行 `/api/stream`。
async fn auth(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    // Host 校验：防 DNS rebinding（需求 §6.2）
    if let Some(host) = headers.get("host").and_then(|h| h.to_str().ok()) {
        if !host.eq_ignore_ascii_case(&st.expected_host) {
            return (StatusCode::FORBIDDEN, "Host 校验失败").into_response();
        }
    } else {
        return (StatusCode::FORBIDDEN, "缺少 Host").into_response();
    }
    let bearer_ok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| t == st.token);
    // query token 仅对 /api/stream 有效（token 为 hex，无需百分号解码）
    let query_ok = req.uri().path() == "/api/stream"
        && req
            .uri()
            .query()
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("token=")))
            .is_some_and(|t| t == st.token);
    if !bearer_ok && !query_ok {
        return (StatusCode::UNAUTHORIZED, "无效 token").into_response();
    }
    next.run(req).await
}

async fn index() -> Html<String> {
    let page = Assets::get("index.html").expect("嵌入 index.html");
    Html(
        std::str::from_utf8(page.data.as_ref())
            .unwrap_or("<html>M1</html>")
            .to_string(),
    )
}

type ApiResult = Result<Json<serde_json::Value>, (StatusCode, String)>;

fn db_err<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}"))
}

async fn status(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let s = &st.src_stats;
    let e = &st.eng_stats;
    Json(json!({
        "service": "harnessguard",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_s": st.started.elapsed().as_secs(),
        "source": {
            "kernel_events_seen": s.kernel_events_seen.load(Relaxed),
            "dns_events_seen": s.dns_events_seen.load(Relaxed),
            "events_sent": s.events_sent.load(Relaxed),
            "events_dropped_full": s.events_dropped_full.load(Relaxed),
            "file_resolved": s.file_resolved.load(Relaxed),
            "file_unknown": s.file_unknown.load(Relaxed),
            "file_cache_entries": s.file_cache_entries.load(Relaxed),
            "file_probe_tried": s.file_probe_tried.load(Relaxed),
            "file_probe_hit": s.file_probe_hit.load(Relaxed),
        },
        "engine": {
            "events_processed": e.events_processed.load(Relaxed),
            "verdicts": e.verdicts.load(Relaxed),
            "blocks": e.blocks.load(Relaxed),
            "kills": e.kills.load(Relaxed),
            "connections_dropped": e.connections_dropped.load(Relaxed),
            "ips_blocked": e.ips_blocked.load(Relaxed),
        },
        "procs": st.procs.len(),
        "conns": st.conns.len(),
    }))
}

#[derive(Deserialize)]
struct LimitQ {
    limit: Option<usize>,
    #[allow(dead_code)] // 预留：分页游标（设计 §7 since 参数）
    since: Option<i64>,
}

async fn verdicts(State(st): State<Arc<AppState>>, Query(p): Query<LimitQ>) -> ApiResult {
    let limit = p.limit.unwrap_or(50).min(500) as i64;
    // db 打开失败按 500 返回（原 unwrap_or_else(unreachable!) 在库缺失/损坏时
    // 直接 panic 整个 worker——M4 待修清单 12，三处同修）
    let conn = hg_store::open(&st.db_path).map_err(db_err)?;
    let mut stmt = conn
        .prepare("SELECT id, ts, rule_id, action, pid, exe, evidence_json, notified FROM verdicts ORDER BY id DESC LIMIT ?1")
        .map_err(db_err)?;
    let rows = stmt.query_map([limit], |r| {
        Ok(json!({
            "id": r.get::<_, i64>(0)?,
            "ts": r.get::<_, i64>(1)?,
            "rule_id": r.get::<_, String>(2)?,
            "action": r.get::<_, String>(3)?,
            "pid": r.get::<_, i64>(4)?,
            "exe": r.get::<_, String>(5)?,
            "evidence": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(6)?).unwrap_or(json!({})),
            "notified": r.get::<_, i64>(7)?,
        }))
    }).map_err(db_err)?;
    let out: Vec<_> = rows.filter_map(|x| x.ok()).collect();
    Ok(Json(json!(out)))
}

async fn events(State(st): State<Arc<AppState>>, Query(p): Query<LimitQ>) -> ApiResult {
    let limit = p.limit.unwrap_or(50).min(500) as i64;
    let conn = hg_store::open(&st.db_path).map_err(db_err)?;
    let mut stmt = conn
        .prepare("SELECT id, ts, pid, kind, detail_json FROM events ORDER BY id DESC LIMIT ?1")
        .map_err(db_err)?;
    let rows = stmt.query_map([limit], |r| {
        Ok(json!({
            "id": r.get::<_, i64>(0)?,
            "ts": r.get::<_, i64>(1)?,
            "pid": r.get::<_, i64>(2)?,
            "kind": r.get::<_, String>(3)?,
            "detail": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(4)?).unwrap_or(json!({})),
        }))
    }).map_err(db_err)?;
    let out: Vec<_> = rows.filter_map(|x| x.ok()).collect();
    Ok(Json(json!(out)))
}

async fn processes(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let out: Vec<_> = st
        .procs
        .snapshot()
        .into_iter()
        .map(|id| {
            json!({
                "pid": id.pid,
                "start_time": id.start_time.0,
                "exe": id.exe.display().to_string(),
                "cmdline": id.cmdline.iter().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>().join(" "),
                "harness_root": id.harness_root.as_ref().map(|h| h.0.clone()),
                "tool_exempt": id.tool_exempt,
            })
        })
        .collect();
    Json(json!(out))
}

async fn wl_list(State(st): State<Arc<AppState>>) -> ApiResult {
    let conn = hg_store::open(&st.db_path).map_err(db_err)?;
    let mut stmt = conn
        .prepare("SELECT id, kind, value, note, created_ts FROM whitelist ORDER BY id DESC")
        .map_err(db_err)?;
    let rows = stmt
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "kind": r.get::<_, String>(1)?,
                "value": r.get::<_, String>(2)?,
                "note": r.get::<_, String>(3)?,
                "created_ts": r.get::<_, i64>(4)?,
            }))
        })
        .map_err(db_err)?;
    Ok(Json(json!(rows.filter_map(|x| x.ok()).collect::<Vec<_>>())))
}

#[derive(Deserialize)]
struct WlAdd {
    kind: String,
    value: String,
    #[serde(default)]
    note: String,
}

async fn wl_add(State(st): State<Arc<AppState>>, Json(body): Json<WlAdd>) -> Response {
    if !matches!(body.kind.as_str(), "endpoint" | "path" | "proc") {
        return (StatusCode::BAD_REQUEST, "kind 须为 endpoint|path|proc").into_response();
    }
    let Ok(conn) = hg_store::open(&st.db_path) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "打开数据库失败").into_response();
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    match conn.execute(
        "INSERT OR IGNORE INTO whitelist(kind, value, note, created_ts) VALUES (?1,?2,?3,?4)",
        rusqlite::params![body.kind, body.value, body.note, ts],
    ) {
        Ok(_) => {
            if let Err(e) = st.rebuild_rules() {
                tracing::error!("白名单热更新失败：{e:#}");
            }
            (StatusCode::OK, "已添加").into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response(),
    }
}

/// query 值经 serde_urlencoded 进 struct 时自动 parse 成目标类型；
/// 不能用 serde_json::Value 承接（值恒为 String，数字提取必失败）
#[derive(Deserialize)]
struct WlDelQ {
    id: i64,
}

async fn wl_del(State(st): State<Arc<AppState>>, Query(p): Query<WlDelQ>) -> Response {
    let Ok(conn) = hg_store::open(&st.db_path) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "打开数据库失败").into_response();
    };
    match conn.execute("DELETE FROM whitelist WHERE id = ?1", [p.id]) {
        Ok(_) => {
            if let Err(e) = st.rebuild_rules() {
                tracing::error!("白名单热更新失败：{e:#}");
            }
            (StatusCode::OK, "已删除").into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response(),
    }
}

async fn config_get(State(st): State<Arc<AppState>>) -> Response {
    // 返回 TOML 文本（设置页原样编辑，双通道同一份文件，技术设计 §6）
    let text = std::fs::read_to_string(&st.config_path).unwrap_or_else(|_| {
        toml::to_string_pretty(&*st.config.read().unwrap()).unwrap_or_default()
    });
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        text,
    )
        .into_response()
}

async fn config_put(State(st): State<Arc<AppState>>, body: String) -> Response {
    let parsed: FileConfig = match toml_parse(&body) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("TOML 解析失败: {e}")).into_response(),
    };
    // 设置页是"原文件文本→编辑→提交"的往返：校验通过后按提交原文落盘，
    // 保留文件注释与用户在 UI 里对注释的修改（save() 合并会以旧文件注释为准）。
    if let Err(e) = std::fs::write(&st.config_path, &body) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("保存失败: {e}")).into_response();
    }
    *st.config.write().unwrap() = parsed;
    if let Err(e) = st.rebuild_rules() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("快照重建失败: {e:#}"),
        )
            .into_response();
    }
    (StatusCode::OK, "配置已生效").into_response()
}

fn toml_parse(s: &str) -> anyhow::Result<FileConfig> {
    Ok(toml::from_str(s)?)
}

/// 手动清空审计数据（技术设计 §4：与每日清理同一路径——经写入线程
/// StoreOp::Purge 执行，临时禁用触发器；范围 events/verdicts/conns/
/// dns_map 全量 + processes 已退出，白名单与配置不动）。
async fn data_clear(State(st): State<Arc<AppState>>) -> Response {
    let (ack_tx, ack_rx) = std::sync::mpsc::channel::<u64>();
    if st
        .store_tx
        .send(hg_store::writer::StoreOp::Purge { ack: ack_tx })
        .is_err()
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "存储写入线程未运行").into_response();
    }
    // 写入线程 200ms 批量窗口 + 全表 DELETE，正常毫秒级返回；超时按 504 上报
    match ack_rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(n) => (StatusCode::OK, Json(json!({ "deleted": n }))).into_response(),
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "清理超时").into_response(),
    }
}

/// SSE 帧编码（event + data 各一行，空行结尾）。
fn sse_frame(ev: &SseEvent) -> axum::body::Bytes {
    axum::body::Bytes::from(format!("event: {}\ndata: {}\n\n", ev.event, ev.data))
}

/// `/api/stream`：SSE 实时推送（技术设计 §7）。
/// - 首帧 `retry: 3000`（EventSource 断线 3s 重连）；
/// - verdict/audit 事件经 broadcast 多播；15s keepalive 注释帧探测死连接；
/// - broadcast 滞后（UI 慢）时丢帧并发 `: lagged` 注释，UI 按需重新拉取列表。
async fn stream(State(st): State<Arc<AppState>>) -> Response {
    use std::time::Duration;
    let retry = tokio_stream::iter(vec![Ok::<_, std::convert::Infallible>(
        axum::body::Bytes::from_static(b"retry: 3000\n\n"),
    )]);
    let events = tokio_stream::wrappers::BroadcastStream::new(st.sse.subscribe()).map(|r| {
        Ok::<_, std::convert::Infallible>(match r {
            Ok(ev) => sse_frame(&ev),
            // 滞后丢帧：注释帧告知客户端，随后 UI 靠重新拉取对齐
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                axum::body::Bytes::from(format!(": lagged {n}\n\n"))
            }
        })
    });
    let mut ka = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(15),
        Duration::from_secs(15),
    );
    ka.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let keepalive = tokio_stream::wrappers::IntervalStream::new(ka).map(|_| {
        Ok::<_, std::convert::Infallible>(axum::body::Bytes::from_static(b": keepalive\n\n"))
    });
    let body = Body::from_stream(retry.chain(events.merge(keepalive)));
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "text/event-stream"),
            (axum::http::header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

// IpAddr 预留（端点白名单 IP 校验扩展）
#[allow(dead_code)]
fn _unused(_ip: IpAddr) {}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    /// 构造可服务的最小状态（stream/status 路径不触库，db_path 占位即可）。
    fn test_state() -> Arc<AppState> {
        test_state_with_db("unused.db")
    }

    fn test_state_with_db(db_path: &str) -> Arc<AppState> {
        // 悬空通道：data_clear 的 Purge 发送失败路径（503）用
        let (dead_tx, _keep_rx) = std::sync::mpsc::channel();
        state_with(db_path, dead_tx)
    }

    fn state_with(
        db_path: &str,
        store_tx: std::sync::mpsc::Sender<hg_store::writer::StoreOp>,
    ) -> Arc<AppState> {
        let (sse_tx, _keep) = tokio::sync::broadcast::channel(64);
        let cfg = FileConfig::default();
        let snap = RulesSnapshot::compile(&cfg.to_rules_config(vec![])).expect("编译规则");
        Arc::new(AppState {
            token: "t123".into(),
            expected_host: "127.0.0.1:18099".into(),
            rules: Arc::new(ArcSwap::from_pointee(snap)),
            config: Arc::new(RwLock::new(cfg)),
            config_path: "unused.toml".into(),
            db_path: db_path.into(),
            procs: Arc::new(ProcTable::new()),
            conns: Arc::new(ConnRegistry::new()),
            src_stats: Arc::new(SourceStats::default()),
            eng_stats: Arc::new(EngineStats::default()),
            store_tx,
            sse: sse_tx,
            started: Instant::now(),
        })
    }

    /// db 打开失败返回 500 而非 panic（M4 待修清单 12 回归锚定：
    /// 目录作库路径使打开必失败，三端点均应 500）。
    #[tokio::test]
    async fn db打开失败返回500而非panic() {
        let dir = std::env::temp_dir().join("hg-web-db-500-test");
        std::fs::create_dir_all(&dir).unwrap();
        let st = test_state_with_db(&dir.display().to_string());
        assert_eq!(
            call(&st, "/api/verdicts", true).await.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            call(&st, "/api/events", true).await.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            call(&st, "/api/whitelist", true).await.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    async fn call(state: &Arc<AppState>, uri: &str, bearer: bool) -> axum::response::Response {
        let mut b = axum::http::Request::builder()
            .uri(uri)
            .header("host", "127.0.0.1:18099");
        if bearer {
            b = b.header("authorization", "Bearer t123");
        }
        router(state.clone())
            .oneshot(b.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn call_post(state: &Arc<AppState>, uri: &str) -> axum::response::Response {
        let b = axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("host", "127.0.0.1:18099")
            .header("authorization", "Bearer t123");
        router(state.clone())
            .oneshot(b.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// 写入线程不在（通道闭合）时清理端点应 503 而非静默成功。
    #[tokio::test]
    async fn 手动清理_写入线程不在_返回503() {
        let st = test_state();
        let r = call_post(&st, "/api/data/clear").await;
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// 手动清理端到端：经完整 router 发 Purge → 写入线程清库 → 回删除条数；
    /// 白名单不动（技术设计 §4 清理范围回归）。
    #[tokio::test]
    async fn 手动清理_经写入线程清库并回条数() {
        let dir = std::env::temp_dir().join("hg-web-purge-test");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let _ = std::fs::remove_file(&db);
        let db_path = db.display().to_string();
        // 铺数据：2 条判定 + 1 条白名单
        {
            let conn = hg_store::open(&db_path).unwrap();
            for i in 0..2i64 {
                conn.execute(
                    "INSERT INTO verdicts(ts, rule_id, action, pid, exe, evidence_json, notified) VALUES (?1,'r','block',1,'e','{}',0)",
                    [i],
                ).unwrap();
            }
            conn.execute(
                "INSERT INTO whitelist(kind, value, note, created_ts) VALUES ('path','C:/ok','',1)",
                [],
            )
            .unwrap();
        }
        let (tx, rx) = std::sync::mpsc::channel::<hg_store::writer::StoreOp>();
        let writer = hg_store::writer::spawn_writer(&db_path, rx, 30);
        let st = state_with(&db_path, tx);
        let r = call_post(&st, "/api/data/clear").await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = axum::Json::<serde_json::Value>::from_bytes(
            &r.into_body().collect().await.unwrap().to_bytes(),
        )
        .unwrap();
        assert_eq!(body["deleted"], 2, "应删 2 条 verdicts：{body:?}");
        // 库内验证：判定已清、白名单保留
        let conn = hg_store::open(&db_path).unwrap();
        let (v, w): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM verdicts), (SELECT COUNT(*) FROM whitelist)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((v, w), (0, 1));
        drop(st); // 通道唯一发送端随 state 释放，写入线程退出
        let _ = writer.join();
        let _ = std::fs::remove_file(&db);
    }

    /// 白名单删除回归：UI 经 `?id=N` 删除。曾用 serde_json::Value 承接 query，
    /// 值恒为字符串致 as_i64 必失败、删除按钮从未生效（400 缺 id）。
    #[tokio::test]
    async fn 白名单删除_query数字id生效() {
        let dir = std::env::temp_dir().join("hg-web-wldel-test");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let _ = std::fs::remove_file(&db);
        let db_path = db.display().to_string();
        {
            let conn = hg_store::open(&db_path).unwrap();
            conn.execute(
                "INSERT INTO whitelist(kind, value, note, created_ts) VALUES ('endpoint','api.openai.com','n',1)",
                [],
            )
            .unwrap();
        }
        let st = test_state_with_db(&db_path);
        let call_del = |st: Arc<AppState>, uri: &'static str| async move {
            let req = axum::http::Request::builder()
                .method("DELETE")
                .uri(uri)
                .header("host", "127.0.0.1:18099")
                .header("authorization", "Bearer t123")
                .body(Body::empty())
                .unwrap();
            router(st).oneshot(req).await.unwrap()
        };
        let res = call_del(st.clone(), "/api/whitelist?id=1").await;
        assert_eq!(res.status(), StatusCode::OK, "数字 id 应解析成功");
        let conn = hg_store::open(&db_path).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM whitelist", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "条目应被删除");
        // 缺 id → 400（Query 提取失败）
        let r2 = call_del(st, "/api/whitelist").await;
        assert_eq!(r2.status(), StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn sse_帧编码() {
        let f = sse_frame(&SseEvent {
            event: "verdict",
            data: "{\"id\":1}".into(),
        });
        assert_eq!(
            std::str::from_utf8(&f).unwrap(),
            "event: verdict\ndata: {\"id\":1}\n\n"
        );
    }

    /// 拍板记录 8 的验收：query token 仅放行 /api/stream，其余端点仅 Bearer。
    #[tokio::test]
    async fn query_token_仅放行_stream端点() {
        let st = test_state();
        // 无任何 token
        assert_eq!(
            call(&st, "/api/status", false).await.status(),
            StatusCode::UNAUTHORIZED
        );
        // query token 打普通 API → 拒绝
        assert_eq!(
            call(&st, "/api/status?token=t123", false).await.status(),
            StatusCode::UNAUTHORIZED
        );
        // 错误 query token 打 SSE → 拒绝
        assert_eq!(
            call(&st, "/api/stream?token=wrong", false).await.status(),
            StatusCode::UNAUTHORIZED
        );
        // 正确 query token 打 SSE → 放行且为事件流
        let r = call(&st, "/api/stream?token=t123", false).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(r
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/event-stream")));
        // Bearer 打普通 API → 正常（回归）
        assert_eq!(
            call(&st, "/api/status", true).await.status(),
            StatusCode::OK
        );
    }

    /// SSE 首帧为 retry 指令、事件帧可推送到订阅者（端到端经完整 router）。
    #[tokio::test]
    async fn sse_首帧retry与事件推送() {
        let st = test_state();
        let r = call(&st, "/api/stream?token=t123", false).await;
        let mut body = r.into_body();
        let f1 = tokio::time::timeout(std::time::Duration::from_secs(2), body.frame())
            .await
            .expect("首帧超时")
            .unwrap()
            .expect("流提前结束");
        assert_eq!(f1.data_ref().unwrap(), "retry: 3000\n\n");
        // 喂入一帧事件，应原样到达订阅端
        st.sse
            .send(SseEvent {
                event: "verdict",
                data: "{\"rule\":\"r\"}".into(),
            })
            .expect("发送事件");
        let f2 = tokio::time::timeout(std::time::Duration::from_secs(2), body.frame())
            .await
            .expect("事件帧超时")
            .unwrap()
            .expect("流提前结束");
        assert_eq!(
            f2.data_ref().unwrap(),
            "event: verdict\ndata: {\"rule\":\"r\"}\n\n"
        );
    }

    #[test]
    fn 路由可构建() {
        // 静态资源嵌入回归（M1 原测试保留）
        let page = Assets::get("index.html");
        assert!(page.is_some(), "index.html 未嵌入");
    }
}
