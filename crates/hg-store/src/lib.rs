//! SQLite 存储层（技术设计 §4）。
//!
//! 骨架阶段：建库 + schema 初始化（rusqlite bundled，静态编译 sqlite3.c，
//! 免系统依赖）。M1 补齐：追加写触发器（运行期禁 UPDATE/DELETE，唯一删除路径
//! 是每日清理任务持有内部标记）、批量 flush（每 200ms 或 500 条）、滚动清理
//! （30 天 / 500MB 双条件）、查询接口。

pub mod writer;

use anyhow::Result;
use rusqlite::Connection;

/// 技术设计 §4 全部表与索引。
pub const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS processes(
  pid INTEGER, start_ts INTEGER, exe TEXT, cmdline TEXT,
  harness_root TEXT, exit_ts INTEGER);
CREATE INDEX IF NOT EXISTS idx_proc_root ON processes(harness_root, start_ts);

CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, ts INTEGER, pid INTEGER, start_ts INTEGER,
  kind TEXT, detail_json TEXT);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS conns(
  conn_id TEXT PRIMARY KEY, pid INTEGER, harness_root TEXT,
  remote_ip TEXT, remote_port INTEGER, proto TEXT,
  bytes_out INTEGER, opened_ts INTEGER, closed_ts INTEGER);
CREATE INDEX IF NOT EXISTS idx_conns_root ON conns(harness_root, remote_ip);

CREATE TABLE IF NOT EXISTS verdicts(
  id INTEGER PRIMARY KEY, ts INTEGER, rule_id TEXT, action TEXT,
  pid INTEGER, exe TEXT, evidence_json TEXT, notified INTEGER);
CREATE INDEX IF NOT EXISTS idx_verdicts_ts ON verdicts(ts);

CREATE TABLE IF NOT EXISTS dns_map(
  qname TEXT, ip TEXT, pid INTEGER, ts INTEGER);
CREATE INDEX IF NOT EXISTS idx_dns_ip ON dns_map(ip);

CREATE TABLE IF NOT EXISTS whitelist(
  id INTEGER PRIMARY KEY, kind TEXT,
  value TEXT, note TEXT, created_ts INTEGER, UNIQUE(kind, value));
"#;

/// 打开数据库并完成初始化（WAL + NORMAL 同步；`:memory:` 供测试）。
/// 库文件 ACL（仅管理员可写）由安装器/服务启动时设置（技术设计 §4/§8.2）。
pub fn open(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    // :memory: 库无法切 WAL（结果仍为 memory），忽略该情形
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.execute_batch(SCHEMA_SQL)?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 内存库建库与写入回读() {
        let conn = open(":memory:").unwrap();
        conn.execute(
            "INSERT INTO verdicts(ts, rule_id, action, pid, exe, evidence_json, notified)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                0i64,
                "git-dir",
                "block",
                4242i64,
                "C:/x/claude.exe",
                "{}",
                0i64
            ],
        )
        .unwrap();
        let (rule, action): (String, String) = conn
            .query_row(
                "SELECT rule_id, action FROM verdicts WHERE pid = 4242",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(rule, "git-dir");
        assert_eq!(action, "block");
    }
}
