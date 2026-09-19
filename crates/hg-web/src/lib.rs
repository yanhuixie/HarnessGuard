//! Web UI 服务（技术设计 §7）。
//!
//! 骨架阶段仅提供状态端点。M1 接入：仅监听 127.0.0.1、启动随机 token、
//! Bearer 鉴权（query token 仅放行 /api/stream SSE）、Host 校验中间件
//! （防 DNS rebinding）、rust-embed 静态资源、事件流/判定/白名单/配置端点。

use axum::routing::get;
use axum::{Json, Router};

/// `GET /api/status`：服务状态（骨架占位；M1 汇总事件源健康度、当前监控
/// harness 列表、资源占用，技术设计 §7 端点表）。
async fn status() -> Json<serde_json::Value> {
    serde_json::json!({
        "service": "harnessguard",
        "stage": "skeleton",
    })
    .into()
}

/// 构建 API 路由（端点按技术设计 §7 表逐版本补齐）。
pub fn router() -> Router {
    Router::new().route("/api/status", get(status))
}

pub fn describe() -> &'static str {
    "hg-web：内嵌 Web UI（127.0.0.1 + 随机 token + Host 校验，M1 接入）"
}

#[cfg(test)]
mod tests {
    #[test]
    fn 路由可构建() {
        let _router = super::router();
    }
}
