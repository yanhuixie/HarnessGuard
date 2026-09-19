//! 连接注册表（技术设计 §3.1）：ConnId → 归因与上行累计，全部在内存表完成
//! （不可能依赖 SQLite）。连接关闭时汇总落库（conns 表）。

use std::collections::hash_map::RandomState;
use std::net::SocketAddr;

use dashmap::DashMap;
use hg_model::{ConnId, HarnessId, Pid, Proto, StartTime, Timestamp};

#[derive(Debug, Clone)]
pub struct ConnEntry {
    pub pid: Pid,
    pub start_time: StartTime,
    pub harness_root: Option<HarnessId>,
    pub proto: Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub bytes_out: u64,
    pub opened_ts: Timestamp,
}

/// 上行增量归因样本（慢路径网络阈值判定的输入，技术设计 §3.3）。
#[derive(Debug, Clone)]
pub struct TxSample {
    pub pid: Pid,
    pub start_time: StartTime,
    pub harness_root: Option<HarnessId>,
    pub remote: SocketAddr,
    /// 该连接累计上行字节。
    pub bytes_out_total: u64,
}

/// 连接关闭汇总（落库 conns 表，技术设计 §4）。
#[derive(Debug, Clone)]
pub struct ConnSummary {
    pub conn_id: ConnId,
    pub pid: Pid,
    pub harness_root: Option<HarnessId>,
    pub proto: Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub bytes_out: u64,
    pub opened_ts: Timestamp,
    pub closed_ts: Timestamp,
}

#[derive(Default)]
pub struct ConnRegistry {
    inner: DashMap<ConnId, ConnEntry, RandomState>,
}

impl ConnRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on_open(&self, conn_id: ConnId, entry: ConnEntry) {
        self.inner.insert(conn_id, entry);
    }

    /// 上行字节累计（ConnTx 只带 conn_id，归因在此完成，技术设计 §3.1）。
    pub fn on_tx(&self, conn_id: ConnId, delta: u64) -> Option<TxSample> {
        let mut e = self.inner.get_mut(&conn_id)?;
        e.bytes_out += delta;
        Some(TxSample {
            pid: e.pid,
            start_time: e.start_time,
            harness_root: e.harness_root.clone(),
            remote: e.remote,
            bytes_out_total: e.bytes_out,
        })
    }

    pub fn on_close(&self, conn_id: ConnId, closed_ts: Timestamp) -> Option<ConnSummary> {
        let (_, e) = self.inner.remove(&conn_id)?;
        Some(ConnSummary {
            conn_id,
            pid: e.pid,
            harness_root: e.harness_root,
            proto: e.proto,
            local: e.local,
            remote: e.remote,
            bytes_out: e.bytes_out,
            opened_ts: e.opened_ts,
            closed_ts,
        })
    }

    pub fn get(&self, conn_id: &ConnId) -> Option<ConnEntry> {
        self.inner.get(conn_id).map(|v| v.clone())
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_entry(pid: Pid, root: Option<&str>, remote: &str) -> ConnEntry {
        ConnEntry {
            pid,
            start_time: StartTime(1),
            harness_root: root.map(|r| HarnessId(r.into())),
            proto: Proto::Tcp,
            local: "127.0.0.1:5000".parse().unwrap(),
            remote: remote.parse().unwrap(),
            bytes_out: 0,
            opened_ts: Timestamp(100),
        }
    }

    #[test]
    fn 累计上行字节并归因() {
        let r = ConnRegistry::new();
        r.on_open(ConnId(7), open_entry(42, Some("claude-code"), "1.2.3.4:443"));
        assert_eq!(r.on_tx(ConnId(7), 1000).unwrap().bytes_out_total, 1000);
        let s = r.on_tx(ConnId(7), 2_000).unwrap();
        assert_eq!(s.bytes_out_total, 3000);
        assert_eq!(s.pid, 42);
        assert_eq!(s.harness_root.as_ref().unwrap().0, "claude-code");
        assert_eq!(s.remote.port(), 443);
    }

    #[test]
    fn 关闭汇总落库并清理() {
        let r = ConnRegistry::new();
        r.on_open(ConnId(7), open_entry(42, None, "1.2.3.4:443"));
        r.on_tx(ConnId(7), 500);
        let sum = r.on_close(ConnId(7), Timestamp(200)).unwrap();
        assert_eq!(sum.bytes_out, 500);
        assert_eq!(sum.closed_ts, Timestamp(200));
        assert!(r.is_empty());
        assert!(r.on_close(ConnId(7), Timestamp(300)).is_none());
    }

    #[test]
    fn 未知连接的增量被丢弃() {
        let r = ConnRegistry::new();
        assert!(r.on_tx(ConnId(99), 1).is_none());
    }
}
