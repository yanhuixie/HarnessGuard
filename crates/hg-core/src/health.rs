//! 健康统计（技术设计 §9.1/§9.2）：事件源心跳/丢弃计数、引擎判定计数。
//! 定义在 hg-core（而非平台 crate），使 Web 状态页无需依赖平台 crate 即可读取。

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// 事件源健康统计。
#[derive(Default)]
pub struct SourceStats {
    pub kernel_events_seen: AtomicU64,
    pub dns_events_seen: AtomicU64,
    pub events_sent: AtomicU64,
    pub events_dropped_full: AtomicU64,
    pub file_resolved: AtomicU64,
    pub file_unknown: AtomicU64,
    pub file_cache_entries: AtomicU64,
    /// unknown Create 句柄探测（M4 场景 A 缓解）：尝试 / 命中
    pub file_probe_tried: AtomicU64,
    pub file_probe_hit: AtomicU64,
}

/// 引擎判定统计。
#[derive(Default)]
pub struct EngineStats {
    pub events_processed: AtomicU64,
    pub verdicts: AtomicU64,
    pub blocks: AtomicU64,
    pub kills: AtomicU64,
    pub connections_dropped: AtomicU64,
    pub ips_blocked: AtomicU64,
}

pub fn load64(v: &AtomicU64) -> u64 {
    v.load(Relaxed)
}
