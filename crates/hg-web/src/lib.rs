//! Web UI 服务（技术设计 §7）：
//! - 仅监听 127.0.0.1（装配方保证）；随机 token；`Authorization: Bearer` 鉴权；
//! - Host 校验中间件（防 DNS rebinding，需求 §6.2）；
//! - 静态资源 rust-embed 嵌入（无构建前端）；
//! - `/api/stream`（SSE）M1 未实现（UI 以 3s 轮询替代），M4 接入——已知偏差。
//!
//! 已知偏差（相对设计 §7）：封禁 WFP→netsh 见 M1 报告；SSE→轮询见本文件头。

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use arc_swap::ArcSwap;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use hg_core::conn_registry::ConnRegistry;
use hg_core::health::{EngineStats, SourceStats};
use hg_core::proc_table::ProcTable;
use hg_core::rules::RulesSnapshot;
use hg_core::FileConfig;
use rust_embed::Embed;
use serde::Deserialize;
use serde_json::json;

#[derive(Embed)]
#[folder = "../../ui/"]
struct Assets;

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
        .route("/api/stream", get(stream_stub));
    Router::new()
        .route("/", get(index))
        .merge(api.route_layer(middleware::from_fn_with_state(state.clone(), auth)))
        .with_state(state)
}

/// Bearer 鉴权 + Host 校验（仅 /api/*；静态首页为壳页面不鉴权）。
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
    let ok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| t == st.token);
    if !ok {
        return (StatusCode::UNAUTHORIZED, "无效 token").into_response();
    }
    next.run(req).await
}

async fn index() -> Html<String> {
    let page = Assets::get("index.html").expect("嵌入 index.html");
    Html(std::str::from_utf8(page.data.as_ref()).unwrap_or("<html>M1</html>").to_string())
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

async fn verdicts(
    State(st): State<Arc<AppState>>,
    Query(p): Query<LimitQ>,
) -> ApiResult {
    let limit = p.limit.unwrap_or(50).min(500) as i64;
    let conn = hg_store::open(&st.db_path).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}"))).unwrap_or_else(|_| unreachable!());
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

async fn events(
    State(st): State<Arc<AppState>>,
    Query(p): Query<LimitQ>,
) -> ApiResult {
    let limit = p.limit.unwrap_or(50).min(500) as i64;
    let conn = hg_store::open(&st.db_path).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}"))).unwrap_or_else(|_| unreachable!());
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
    let conn = hg_store::open(&st.db_path).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}"))).unwrap_or_else(|_| unreachable!());
    let mut stmt = conn
        .prepare("SELECT id, kind, value, note, created_ts FROM whitelist ORDER BY id DESC")
        .map_err(db_err)?;
    let rows = stmt.query_map([], |r| {
        Ok(json!({
            "id": r.get::<_, i64>(0)?,
            "kind": r.get::<_, String>(1)?,
            "value": r.get::<_, String>(2)?,
            "note": r.get::<_, String>(3)?,
            "created_ts": r.get::<_, i64>(4)?,
        }))
    }).map_err(db_err)?;
    Ok(Json(json!(rows.filter_map(|x| x.ok()).collect::<Vec<_>>())))
}

#[derive(Deserialize)]
struct WlAdd {
    kind: String,
    value: String,
    #[serde(default)]
    note: String,
}

async fn wl_add(
    State(st): State<Arc<AppState>>,
    Json(body): Json<WlAdd>,
) -> Response {
    if !matches!(body.kind.as_str(), "endpoint" | "path" | "proc") {
        return (StatusCode::BAD_REQUEST, "kind 须为 endpoint|path|proc").into_response();
    }
    let Ok(conn) = hg_store::open(&st.db_path) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "打开数据库失败").into_response();
    };
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
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

async fn wl_del(State(st): State<Arc<AppState>>, Query(p): Query<serde_json::Value>) -> Response {
    let Some(id) = p.get("id").and_then(|v| v.as_i64()) else {
        return (StatusCode::BAD_REQUEST, "缺 id").into_response();
    };
    let Ok(conn) = hg_store::open(&st.db_path) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "打开数据库失败").into_response();
    };
    match conn.execute("DELETE FROM whitelist WHERE id = ?1", [id]) {
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
    (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")], text).into_response()
}

async fn config_put(State(st): State<Arc<AppState>>, body: String) -> Response {
    let parsed: FileConfig = match toml_parse(&body) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("TOML 解析失败: {e}")).into_response(),
    };
    if let Err(e) = parsed.save(&st.config_path) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("保存失败: {e}")).into_response();
    }
    *st.config.write().unwrap() = parsed;
    if let Err(e) = st.rebuild_rules() {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("快照重建失败: {e:#}")).into_response();
    }
    (StatusCode::OK, "配置已生效").into_response()
}

fn toml_parse(s: &str) -> anyhow::Result<FileConfig> {
    Ok(toml::from_str(s)?)
}

/// `/api/stream`：SSE 实时推送。M1 以 UI 轮询替代（技术设计 §7 已知偏差，M4 接入）。
async fn stream_stub() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "SSE 实时流 M4 接入；当前请轮询 /api/verdicts 与 /api/events",
    )
        .into_response()
}

// IpAddr 预留（端点白名单 IP 校验扩展）
#[allow(dead_code)]
fn _unused(_ip: IpAddr) {}

#[cfg(test)]
mod tests {
    #[test]
    fn 路由可构建() {
        // 状态依赖较多，此处仅验证静态资源嵌入
        let page = super::Assets::get("index.html");
        assert!(page.is_some(), "index.html 未嵌入");
    }
}
