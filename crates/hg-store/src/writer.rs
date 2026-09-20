//! 批量写入线程（技术设计 §4 写入策略）：每 200ms 或 500 条 flush；
//! 追加写触发器（运行期禁 UPDATE/DELETE）；每日清理任务（唯一删除路径，
//! 清理时临时禁用触发器）。滚动清理按 retention_days（磁盘上限 M4 补）。

use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use anyhow::Result;
use rusqlite::Connection;

use crate::open;

#[derive(Debug)]
pub enum StoreOp {
    Event { ts: i64, pid: i64, start_ts: i64, kind: String, detail: String },
    Verdict { ts: i64, rule_id: String, action: String, pid: i64, exe: String, evidence: String, notified: i64 },
    Conn { conn_id: String, pid: i64, harness_root: String, remote_ip: String, remote_port: i64, proto: String, bytes_out: i64, opened_ts: i64, closed_ts: i64 },
    Dns { qname: String, ip: String, pid: i64, ts: i64 },
    Process { pid: i64, start_ts: i64, exe: String, cmdline: String, harness_root: String, exit_ts: Option<i64> },
    /// 手动全量清理（Web UI"清空审计数据"入口）：与每日清理同一删除路径
    /// （技术设计 §4 拍板：唯一 DELETE 路径在写入线程，临时禁用触发器）。
    /// ack 回传删除总条数（写入线程已执行完毕才回）。
    Purge { ack: std::sync::mpsc::Sender<u64> },
}

const TRIGGERS_SQL: &str = r#"
CREATE TRIGGER IF NOT EXISTS tr_events_append AFTER UPDATE ON events BEGIN
  SELECT RAISE(ABORT, 'events 只允许追加'); END;
CREATE TRIGGER IF NOT EXISTS tr_events_delete AFTER DELETE ON events BEGIN
  SELECT RAISE(ABORT, 'events 删除仅限清理任务'); END;
CREATE TRIGGER IF NOT EXISTS tr_verdicts_append AFTER UPDATE ON verdicts BEGIN
  SELECT RAISE(ABORT, 'verdicts 只允许追加'); END;
CREATE TRIGGER IF NOT EXISTS tr_verdicts_delete AFTER DELETE ON verdicts BEGIN
  SELECT RAISE(ABORT, 'verdicts 删除仅限清理任务'); END;
CREATE TRIGGER IF NOT EXISTS tr_conns_append AFTER UPDATE ON conns BEGIN
  SELECT RAISE(ABORT, 'conns 只允许追加'); END;
CREATE TRIGGER IF NOT EXISTS tr_conns_delete AFTER DELETE ON conns BEGIN
  SELECT RAISE(ABORT, 'conns 删除仅限清理任务'); END;
"#;

const DROP_TRIGGERS_SQL: &str = "DROP TRIGGER IF EXISTS tr_events_append; DROP TRIGGER IF EXISTS tr_events_delete; DROP TRIGGER IF EXISTS tr_verdicts_append; DROP TRIGGER IF EXISTS tr_verdicts_delete; DROP TRIGGER IF EXISTS tr_conns_append; DROP TRIGGER IF EXISTS tr_conns_delete;";

/// 启动写入线程（独占一个写连接；WAL 下读连接并发不受影响）。
/// 返回 JoinHandle 供停机序列汇合冲刷（通道全闭后线程 flush 并退出）。
pub fn spawn_writer(db_path: &str, rx: Receiver<StoreOp>, retention_days: u32) -> std::thread::JoinHandle<()> {
    let path = db_path.to_string();
    std::thread::Builder::new()
        .name("hg-store-writer".into())
        .spawn(move || {
            let conn = match open(&path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("存储写入线程打开库失败：{e:#}");
                    return;
                }
            };
            if let Err(e) = conn.execute_batch(TRIGGERS_SQL) {
                tracing::error!("追加触发器创建失败：{e}");
            }
            let mut last_flush = Instant::now();
            let mut last_cleanup = Instant::now();
            let mut pending: Vec<StoreOp> = Vec::new();
            loop {
                // 200ms 批量窗口（技术设计 §4）
                match rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(op) => {
                        // 控制操作不进批量窗口：先冲刷挂起数据再就地清理，
                        // 保证 ack 返回时清理点之前的落库数据已全部删除
                        if let StoreOp::Purge { ack } = op {
                            flush(&conn, &mut pending);
                            let n = purge(&conn);
                            tracing::info!("手动清理审计数据：{n} 条");
                            let _ = ack.send(n);
                            continue;
                        }
                        pending.push(op);
                        if pending.len() >= 500 {
                            flush(&conn, &mut pending);
                            last_flush = Instant::now();
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        flush(&conn, &mut pending);
                        tracing::info!("存储写入线程退出（通道关闭）");
                        return;
                    }
                }
                if last_flush.elapsed() >= Duration::from_millis(200) && !pending.is_empty() {
                    flush(&conn, &mut pending);
                    last_flush = Instant::now();
                }
                if last_cleanup.elapsed() >= Duration::from_secs(3600 * 24) {
                    cleanup(&conn, retention_days as u64);
                    last_cleanup = Instant::now();
                }
            }
        })
        .expect("spawn store writer")
}

fn flush(conn: &Connection, pending: &mut Vec<StoreOp>) {
    if pending.is_empty() {
        return;
    }
    if let Err(e) = conn.execute_batch("BEGIN") {
        tracing::error!("事务开始失败：{e}");
        pending.clear();
        return;
    }
    for op in pending.drain(..) {
        let r = match op {
            StoreOp::Event { ts, pid, start_ts, kind, detail } => conn.execute(
                "INSERT INTO events(ts, pid, start_ts, kind, detail_json) VALUES (?1,?2,?3,?4,?5)",
                rusqlite::params![ts, pid, start_ts, kind, detail],
            ),
            StoreOp::Verdict { ts, rule_id, action, pid, exe, evidence, notified } => conn.execute(
                "INSERT INTO verdicts(ts, rule_id, action, pid, exe, evidence_json, notified) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params![ts, rule_id, action, pid, exe, evidence, notified],
            ),
            StoreOp::Conn { conn_id, pid, harness_root, remote_ip, remote_port, proto, bytes_out, opened_ts, closed_ts } => conn.execute(
                "INSERT OR REPLACE INTO conns(conn_id, pid, harness_root, remote_ip, remote_port, proto, bytes_out, opened_ts, closed_ts) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                rusqlite::params![conn_id, pid, harness_root, remote_ip, remote_port, proto, bytes_out, opened_ts, closed_ts],
            ),
            StoreOp::Dns { qname, ip, pid, ts } => conn.execute(
                "INSERT INTO dns_map(qname, ip, pid, ts) VALUES (?1,?2,?3,?4)",
                rusqlite::params![qname, ip, pid, ts],
            ),
            StoreOp::Process { pid, start_ts, exe, cmdline, harness_root, exit_ts } => conn.execute(
                "INSERT INTO processes(pid, start_ts, exe, cmdline, harness_root, exit_ts) VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![pid, start_ts, exe, cmdline, harness_root, exit_ts],
            ),
            // Purge 在进入批量窗口前已被 spawn_writer 拦截，不会出现在此
            StoreOp::Purge { .. } => unreachable!("Purge 不进批量窗口"),
        };
        if let Err(e) = r {
            tracing::error!("落库失败：{e}");
        }
    }
    if let Err(e) = conn.execute_batch("COMMIT") {
        tracing::error!("事务提交失败：{e}");
    }
}

/// 每日清理（技术设计 §4 拍板：唯一 DELETE 路径，临时禁用触发器）。
/// conns 表无 ts 列，按 opened_ts 清理——原实现按 ts 删的语句因列不存在
/// 恒失败且被静默吞掉（conns 从未被滚动清理），本次随手动清理入口一并修正。
fn cleanup(conn: &Connection, retention_days: u64) {
    let cutoff = now_ms() as i64 - (retention_days as i64) * 86_400_000;
    let _ = conn.execute_batch(DROP_TRIGGERS_SQL);
    for (table, col) in [("events", "ts"), ("verdicts", "ts"), ("conns", "opened_ts"), ("dns_map", "ts")] {
        match conn.execute(&format!("DELETE FROM {table} WHERE {col} < ?1"), [cutoff]) {
            Ok(n) if n > 0 => tracing::info!("清理 {table}：{n} 条"),
            Err(e) => tracing::warn!("清理 {table} 失败：{e}"),
            _ => {}
        }
    }
    if let Err(e) = conn.execute("DELETE FROM processes WHERE exit_ts IS NOT NULL AND exit_ts < ?1", [cutoff]) {
        tracing::warn!("清理 processes 失败：{e}");
    }
    let _ = conn.execute_batch(TRIGGERS_SQL);
}

/// 手动全量清理（Web UI"清空审计数据"入口）：与每日清理同范围同路径
/// （技术设计 §4：临时禁用触发器执行 DELETE，白名单不在此列），
/// 不看保留期；运行中进程的身份记录保留。返回删除总条数。
fn purge(conn: &Connection) -> u64 {
    let _ = conn.execute_batch(DROP_TRIGGERS_SQL);
    let mut total = 0u64;
    for table in ["events", "verdicts", "conns", "dns_map"] {
        match conn.execute(&format!("DELETE FROM {table}"), []) {
            Ok(n) => total += n as u64,
            Err(e) => tracing::warn!("清理 {table} 失败：{e}"),
        }
    }
    if let Ok(n) = conn.execute("DELETE FROM processes WHERE exit_ts IS NOT NULL", []) {
        total += n as u64;
    }
    let _ = conn.execute_batch(TRIGGERS_SQL);
    total
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 白名单路径查询（快照重建输入）。
pub fn whitelist_paths(db_path: &str) -> Result<Vec<String>> {
    let conn = open(db_path)?;
    let mut stmt = conn.prepare("SELECT value FROM whitelist WHERE kind = 'path'")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 建好触发器的内存库，并铺一份覆盖各表的数据：
    /// events/verdicts/conns/dns_map 各 2 条（1 新 1 旧），processes 2 条（1 活跃 1 已退出），
    /// whitelist 1 条。
    fn seeded_conn() -> Connection {
        let conn = open(":memory:").unwrap();
        conn.execute_batch(TRIGGERS_SQL).unwrap();
        let old = now_ms() as i64 - 40 * 86_400_000; // 40 天前（超默认保留期）
        let now = now_ms() as i64;
        for ts in [old, now] {
            conn.execute(
                "INSERT INTO events(ts, pid, start_ts, kind, detail_json) VALUES (?1,1,1,'k','{}')",
                [ts],
            ).unwrap();
            conn.execute(
                "INSERT INTO verdicts(ts, rule_id, action, pid, exe, evidence_json, notified) VALUES (?1,'r','block',1,'e','{}',0)",
                [ts],
            ).unwrap();
            // conns 无 ts 列，新旧以 opened_ts 区分（bug 修正回归的数据基础）
            conn.execute(
                "INSERT INTO conns(conn_id, pid, harness_root, remote_ip, remote_port, proto, bytes_out, opened_ts, closed_ts) VALUES (?1,1,'r','1.2.3.4',443,'tcp',0,?2,0)",
                rusqlite::params![format!("c{ts}"), ts],
            ).unwrap();
            conn.execute(
                "INSERT INTO dns_map(qname, ip, pid, ts) VALUES ('q','1.1.1.1',1,?1)",
                [ts],
            ).unwrap();
        }
        conn.execute(
            "INSERT INTO processes(pid, start_ts, exe, cmdline, harness_root, exit_ts) VALUES (1,1,'e','c','r',NULL)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO processes(pid, start_ts, exe, cmdline, harness_root, exit_ts) VALUES (2,1,'e','c','r',?1)",
            [old],
        ).unwrap();
        conn.execute(
            "INSERT INTO whitelist(kind, value, note, created_ts) VALUES ('path','C:/ok','',1)",
            [],
        ).unwrap();
        conn
    }

    fn count(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn 手动清理_全量删审计数据_保留白名单与活跃进程() {
        let conn = seeded_conn();
        let n = purge(&conn);
        // events/verdicts/conns/dns_map 各 2 条 + 已退出 processes 1 条
        assert_eq!(n, 9);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM events"), 0);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM verdicts"), 0);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM conns"), 0);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM dns_map"), 0);
        // 活跃进程身份与白名单保留
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM processes"), 1);
        assert!(count(&conn, "SELECT COUNT(*) FROM processes WHERE exit_ts IS NULL") == 1);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM whitelist"), 1);
        // 清理后触发器防护仍生效（追加写拍板回归）：行级触发器需删到行才
        // 触发，先补插一行再验证 DELETE 被拦
        conn.execute(
            "INSERT INTO events(ts, pid, start_ts, kind, detail_json) VALUES (1,1,1,'k','{}')",
            [],
        ).unwrap();
        assert!(conn.execute("DELETE FROM events WHERE ts = 1", []).is_err());
    }

    #[test]
    fn 每日清理_conns按opened_ts删除_且只删过期() {
        let conn = seeded_conn();
        cleanup(&conn, 30); // 保留 30 天：40 天前的删、现在的留
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM events"), 1);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM conns"), 1, "conns 应按 opened_ts 清理（原按 ts 恒失败）");
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM processes"), 1, "已退出进程应被清理");
    }
}
