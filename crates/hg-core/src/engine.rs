//! 引擎主循环（技术设计 §3.3 慢路径）：消费 Envelope 流，维护身份表/连接表，
//! 产出判定与处置动作。引擎本身无 IO——所有副作用经 [`EngineOutput`] 通道由
//! 装配方（hg-app）的执行器落地（SQLite / Enforcer / 通知），满足"hg-core 无 IO"。

use std::net::IpAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::{DashMap, DashSet};
use hg_model::{
    Action, ConnId, Envelope, Evidence, Pid, Proto, RawEvent, RuleId, StartTime, TcpQuad,
    Timestamp, Verdict,
};
use tokio::sync::mpsc;

use crate::conn_registry::{ConnEntry, ConnRegistry};
use crate::health::EngineStats;
use crate::proc_table::ProcTable;
use crate::rules::{judge_perm_sync, RulesSnapshot};

/// 引擎 → 执行器的输出（全部异步路径落地）。
pub enum EngineOutput {
    Verdict {
        ts: u64, // UTC 毫秒（引擎换算）
        pid: Pid,
        exe: String,
        verdict: Verdict,
    },
    Kill {
        pid: Pid,
        start_time: StartTime,
        reason: String,
    },
    DropTcp {
        quad: TcpQuad,
        reason: String,
    },
    BlockIp {
        ip: IpAddr,
        ttl: Duration,
        reason: String,
    },
    Notify {
        title: String,
        body: String,
    },
    StoreEvent {
        ts: u64,
        kind: String,
        pid: Pid,
        detail: serde_json::Value,
    },
    StoreProcess {
        pid: Pid,
        start_ts: u64,
        exe: String,
        cmdline: String,
        harness_root: String,
        exit_ts: Option<u64>,
    },
    StoreConn {
        conn_id: ConnId,
        pid: Pid,
        harness_root: String,
        remote: std::net::SocketAddr,
        proto: Proto,
        bytes_out: u64,
        opened_ts: u64,
        closed_ts: u64,
    },
    StoreDns {
        qname: String,
        ip: IpAddr,
        pid: Pid,
        ts: u64,
    },
}

pub struct Engine {
    pub procs: Arc<ProcTable>,
    pub conns: Arc<ConnRegistry>,
    /// 规则快照（arc-swap 原子热替换，技术设计 §3.3）
    pub rules: Arc<ArcSwap<RulesSnapshot>>,
    pub out: mpsc::Sender<EngineOutput>,
    pub stats: Arc<EngineStats>,
    /// 域名→IP 反查表（端点白名单判定：IP → 域名）
    dns: DashMap<IpAddr, String>,
    /// (harness_root, remote_ip) 累计上行字节（阈值判定状态）
    root_bytes: DashMap<(String, IpAddr), u64>,
    /// 已读敏感文件的监控根（两级评分联动，需求 §3.1/技术设计 §3.3）
    root_sensitive: DashSet<String>,
    /// 已放行 .git 工作流面的监控根（首见 Audit 取证线索；按 root 数天然
    /// 封顶，与 root_sensitive 同构，需求 §3.1 拍板记录 12）
    root_git_flow: DashSet<String>,
    /// 已处置连接（防重复处置风暴）
    handled_conns: DashSet<u64>,
    /// 单调毫秒 → UTC 毫秒换算基准
    base_utc_ms: u64,
}

impl Engine {
    pub fn new(
        procs: Arc<ProcTable>,
        conns: Arc<ConnRegistry>,
        rules: Arc<ArcSwap<RulesSnapshot>>,
        out: mpsc::Sender<EngineOutput>,
        stats: Arc<EngineStats>,
    ) -> Self {
        Self {
            procs,
            conns,
            rules,
            out,
            stats,
            dns: DashMap::new(),
            root_bytes: DashMap::new(),
            root_sensitive: DashSet::new(),
            root_git_flow: DashSet::new(),
            handled_conns: DashSet::new(),
            base_utc_ms: utc_now_ms(),
        }
    }

    fn utc(&self, ts: Timestamp) -> u64 {
        self.base_utc_ms.saturating_add(ts.0)
    }

    pub async fn run(self: Arc<Self>, mut rx: mpsc::Receiver<Envelope>) {
        while let Some(env) = rx.recv().await {
            self.stats.events_processed.fetch_add(1, Relaxed);
            if let Err(e) = self.handle(env).await {
                tracing::error!("事件处理失败：{e:#}");
            }
        }
        tracing::warn!("事件流关闭，引擎退出");
    }

    fn send(&self, out: EngineOutput) {
        if self.out.try_send(out).is_err() {
            // 执行器阻塞时的丢弃计数（技术设计 §9.2 精神：检测不被落库拖累）
            tracing::warn!("执行器通道满，输出被丢弃");
        }
    }

    async fn handle(&self, env: Envelope) -> anyhow::Result<()> {
        match env.event {
            RawEvent::Exec { pid, ppid, start_time, exe, cmdline, cwd } => {
                self.on_exec(pid, ppid, start_time, exe, cmdline, cwd, env.ts)
            }
            RawEvent::Exit { pid, start_time } => {
                if let Some(id) = self.procs.apply_exit(pid, start_time) {
                    if let Some(root) = &id.harness_root {
                        self.send(EngineOutput::StoreProcess {
                            pid,
                            start_ts: start_time.0,
                            exe: id.exe.display().to_string(),
                            cmdline: join_cmdline(&id.cmdline),
                            harness_root: root.0.clone(),
                            exit_ts: Some(self.utc(env.ts)),
                        });
                    }
                }
                Ok(())
            }
            RawEvent::FileOpen { pid, start_time: _, path, access } => {
                self.on_file_open(pid, &path, access)
            }
            RawEvent::FileCreate { pid, start_time: _, path } => {
                self.on_file_create(pid, &path, env.ts)
            }
            RawEvent::ConnOpen { pid, start_time, conn_id, proto, local, remote } => {
                // 只登记监控树进程的连接（非监控进程不干预，技术设计 §3.3 快路径规则 1）
                if let Some(id) = self.procs.get(&pid) {
                    if id.harness_root.is_some() {
                        self.conns.on_open(
                            conn_id,
                            ConnEntry {
                                pid,
                                start_time,
                                harness_root: id.harness_root.clone(),
                                proto,
                                local,
                                remote,
                                bytes_out: 0,
                                opened_ts: env.ts,
                            },
                        );
                    }
                }
                Ok(())
            }
            RawEvent::ConnTx { conn_id, bytes_out_delta } => {
                self.on_conn_tx(conn_id, bytes_out_delta, env.ts);
                Ok(())
            }
            RawEvent::ConnClose { conn_id } => {
                if let Some(s) = self.conns.on_close(conn_id, env.ts) {
                    if let Some(root) = &s.harness_root {
                        self.send(EngineOutput::StoreConn {
                            conn_id: s.conn_id,
                            pid: s.pid,
                            harness_root: root.0.clone(),
                            remote: s.remote,
                            proto: s.proto,
                            bytes_out: s.bytes_out,
                            opened_ts: self.utc(s.opened_ts),
                            closed_ts: self.utc(s.closed_ts),
                        });
                    }
                }
                Ok(())
            }
            RawEvent::DnsQuery { pid, qname, answers } => {
                let ts = self.utc(env.ts);
                // 容量护栏（评审 #4：长期运行内存上限，粗粒度整表重建）
                if self.dns.len() > 65536 {
                    self.dns.clear();
                }
                if self.root_bytes.len() > 16384 {
                    self.root_bytes.clear();
                }
                if self.handled_conns.len() > 65536 {
                    self.handled_conns.clear();
                }
                for ip in answers {
                    self.dns.insert(ip, qname.clone());
                    self.send(EngineOutput::StoreDns {
                        qname: qname.clone(),
                        ip,
                        pid,
                        ts,
                    });
                }
                Ok(())
            }
            RawEvent::Persistence { pid, kind: _, detail } => {
                // 高可疑告警（审计不阻断，需求 §3.5）
                let v = Verdict {
                    rule_id: RuleId("persistence"),
                    action: Action::Audit,
                    evidence: Evidence {
                        summary: format!("持久化行为：{detail}"),
                        detail: serde_json::json!({ "detail": detail, "pid": pid }),
                    },
                };
                self.emit_verdict(pid, "", v.clone(), env.ts);
                self.send(EngineOutput::Notify {
                    title: "HarnessGuard：持久化行为告警".into(),
                    body: v.evidence.summary,
                });
                Ok(())
            }
        }
    }

    fn on_exec(
        &self,
        pid: Pid,
        ppid: Pid,
        start_time: StartTime,
        exe: std::path::PathBuf,
        cmdline: Vec<std::ffi::OsString>,
        cwd: std::path::PathBuf,
        ts: Timestamp,
    ) -> anyhow::Result<()> {
        let rules = self.rules.load();
        let id = self.procs.apply_exec(&rules, pid, ppid, start_time, &exe, cmdline);
        tracing::debug!(
            "[exec] pid={pid} ppid={ppid} root={:?} exe={} cwd={} cmdline='{}'",
            id.harness_root.as_ref().map(|r| r.0.clone()),
            exe.display(),
            cwd.display(),
            join_cmdline(&id.cmdline)
        );
        let Some(root) = &id.harness_root else { return Ok(()) };

        // 命令封堵（需求 §3.3）。cmdline 为空（短命进程 PEB 读取竞态，M1 报告披露）
        // 时按 exe 文件名兜底匹配——宁多判勿漏判，命中即视为导出型命令。
        let blocked_hit = if id.cmdline.is_empty() {
            let mut argv = vec![std::ffi::OsString::from(
                exe.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default(),
            )];
            argv[0] = std::ffi::OsString::from(
                argv[0].to_string_lossy().trim_end_matches(".exe").to_string(),
            );
            rules.match_blocked_command(&argv)
        } else {
            rules.match_blocked_command(&id.cmdline)
        };
        if blocked_hit {
            let summary = format!(
                "[{}] 封堵命令：{}（pid {pid}）",
                root.0,
                join_cmdline(&id.cmdline)
            );
            let v = Verdict {
                rule_id: RuleId("cmd-block"),
                action: Action::Block,
                evidence: Evidence {
                    summary: summary.clone(),
                    detail: serde_json::json!({ "cmdline": join_cmdline(&id.cmdline), "exe": exe.display().to_string() }),
                },
            };
            self.emit_verdict(pid, &exe.display().to_string(), v, ts);
            self.send(EngineOutput::Kill { pid, start_time, reason: summary.clone() });
            self.send(EngineOutput::Notify {
                title: "HarnessGuard：已封堵导出命令".into(),
                body: summary,
            });
            return Ok(());
        }
        // 审计：监控树内进程启动（短命进程历史可查）
        self.send(EngineOutput::StoreEvent {
            ts: self.utc(ts),
            kind: "exec".into(),
            pid,
            detail: serde_json::json!({ "exe": exe.display().to_string(), "cmdline": join_cmdline(&id.cmdline), "root": root.0 }),
        });
        Ok(())
    }

    fn on_file_open(
        &self,
        pid: Pid,
        path: &std::path::Path,
        access: hg_model::Access,
    ) -> anyhow::Result<()> {
        let Some(id) = self.procs.get(&pid) else { return Ok(()) };
        let rules = self.rules.load();
        let v = judge_perm_sync(&rules, &id, path, access);
        match v.action {
            Action::Block => {
                // Windows 文件无同步拒绝点，处置语义事后（技术设计 §3.1/拍板 2）。
                // git-dir 注入面是否升级杀进程由 git_dir_kill 决定（拍板记录 13，
                // 缺省 false：Block 判定 + 通知即止——ETW 事后杀仅止损，且打包
                // 封堵与网络阈值两重兜底仍在）。
                let summary = v.evidence.summary.clone();
                self.emit_verdict(pid, &id.exe.display().to_string(), v.clone(), Timestamp(0));
                if v.rule_id.0 != "git-dir" || rules.git_dir_kill {
                    self.send(EngineOutput::Kill {
                        pid,
                        start_time: id.start_time,
                        reason: summary.clone(),
                    });
                }
                self.send(EngineOutput::Notify {
                    title: "HarnessGuard：已阻断敏感路径访问".into(),
                    body: summary,
                });
            }
            Action::Audit => {
                if let Some(root) = &id.harness_root {
                    self.root_sensitive.insert(root.0.clone());
                }
                self.emit_verdict(pid, &id.exe.display().to_string(), v, Timestamp(0));
            }
            Action::Allow => {
                // .git 工作流面首见取证（拍板记录 12）：放行不阻断，每个监控根
                // 留一条线索供事后调查（harness 是否在动 .git）
                if v.rule_id.0 == "git-dir-workflow" {
                    if let Some(root) = &id.harness_root {
                        if self.root_git_flow.insert(root.0.clone()) {
                            self.emit_verdict(pid, &id.exe.display().to_string(), v, Timestamp(0));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn on_file_create(&self, pid: Pid, path: &std::path::Path, ts: Timestamp) -> anyhow::Result<()> {
        let Some(id) = self.procs.get(&pid) else { return Ok(()) };
        let Some(root) = &id.harness_root else { return Ok(()) };
        let rules = self.rules.load();
        // Create 事件先于 Read/Write 到达（Windows 事后处置语义下两者都要判，
        // 防只靠后续事件漏判）。按写语义复用快路径统一判定，仅注入面 Kill
        // （hooks/**、config 写，拍板记录 12）；工作流面放行 + root 首见取证。
        if crate::rules::under_git_dir(path) {
            let mut v = judge_perm_sync(&rules, &id, path, hg_model::Access::Write);
            v.evidence.summary = format!("{}（创建，pid {pid}）", v.evidence.summary);
            v.evidence.detail = serde_json::json!({
                "path": path.display().to_string(),
                "via": "file-create",
            });
            match v.action {
                Action::Block => {
                    let summary = v.evidence.summary.clone();
                    self.emit_verdict(pid, &id.exe.display().to_string(), v, ts);
                    // 杀进程升级由 git_dir_kill 决定（拍板记录 13，缺省不杀）
                    if rules.git_dir_kill {
                        self.send(EngineOutput::Kill { pid, start_time: id.start_time, reason: summary.clone() });
                    }
                    self.send(EngineOutput::Notify {
                        title: "HarnessGuard：已阻断敏感路径访问".into(),
                        body: summary,
                    });
                }
                Action::Audit => {
                    self.emit_verdict(pid, &id.exe.display().to_string(), v, ts);
                }
                Action::Allow => {
                    if self.root_git_flow.insert(root.0.clone()) {
                        self.emit_verdict(pid, &id.exe.display().to_string(), v, ts);
                    }
                }
            }
            return Ok(());
        }
        if rules.match_archive(path) {
            let summary = format!(
                "[{}] 创建归档产物：{}（pid {pid}）",
                root.0,
                path.display()
            );
            let v = Verdict {
                rule_id: RuleId("archive-create"),
                action: match rules.archive_action {
                    crate::rules::FileAction::Block => Action::Block,
                    crate::rules::FileAction::Audit => Action::Audit,
                },
                evidence: Evidence {
                    summary: summary.clone(),
                    detail: serde_json::json!({ "path": path.display().to_string() }),
                },
            };
            self.emit_verdict(pid, &id.exe.display().to_string(), v, ts);
            if matches!(rules.archive_action, crate::rules::FileAction::Block) {
                self.send(EngineOutput::Kill {
                    pid,
                    start_time: id.start_time,
                    reason: summary.clone(),
                });
                self.send(EngineOutput::Notify {
                    title: "HarnessGuard：已阻断打包行为".into(),
                    body: summary,
                });
            }
        }
        Ok(())
    }

    fn on_conn_tx(&self, conn_id: ConnId, delta: u64, ts: Timestamp) {
        let Some(sample) = self.conns.on_tx(conn_id, delta) else { return };
        let Some(root) = &sample.harness_root else { return };
        if self.handled_conns.contains(&conn_id.0) {
            return;
        }
        let ip = sample.remote.ip();
        let rules = self.rules.load();
        let domain = self.dns.get(&ip).map(|d| d.clone());
        if rules.endpoint_allowed(domain.as_deref(), ip) {
            return; // 白名单端点不累计阈值（仍会关闭落库）
        }
        let total = {
            let mut e = self
                .root_bytes
                .entry((root.0.clone(), ip))
                .or_insert(0);
            *e += delta;
            *e
        };
        // 两级评分联动：已读敏感文件的监控根阈值降档（需求 §3.1）
        let mut threshold = rules.upload_threshold_bytes;
        if self.root_sensitive.contains(&root.0) {
            threshold /= rules.escalation_divisor;
        }
        tracing::debug!(
            "[conn-tx] pid={} root={:?} {} bytes_out_total={} threshold={}",
            sample.pid,
            sample.harness_root.as_ref().map(|r| r.0.clone()),
            sample.remote,
            total,
            threshold
        );
        if total > threshold {
            self.handled_conns.insert(conn_id.0);
            let summary = format!(
                "[{}] 上行超阈值：{} 累计 {:.1} MB > 阈值 {:.1} MB，端点 {}（域名 {:?}）",
                root.0,
                sample.pid,
                total as f64 / 1048576.0,
                threshold as f64 / 1048576.0,
                ip,
                domain.clone().unwrap_or_else(|| "<未知（DoH？）>".into())
            );
            let v = Verdict {
                rule_id: RuleId("net-threshold"),
                action: Action::Block,
                evidence: Evidence {
                    summary: summary.clone(),
                    detail: serde_json::json!({
                        "remote": sample.remote.to_string(),
                        "domain": domain,
                        "bytes_out_total": total,
                        "threshold_bytes": threshold,
                        "root": root.0,
                    }),
                },
            };
            let exe = self
                .procs
                .get(&sample.pid)
                .map(|id| id.exe.display().to_string())
                .unwrap_or_default();
            self.emit_verdict(sample.pid, &exe, v, ts);
            self.send(EngineOutput::DropTcp {
                quad: TcpQuad { local: sample.local, remote: sample.remote },
                reason: summary.clone(),
            });
            self.send(EngineOutput::BlockIp {
                ip,
                ttl: Duration::from_secs(600),
                reason: summary.clone(),
            });
            self.send(EngineOutput::Notify {
                title: "HarnessGuard：已阻断外传".into(),
                body: summary,
            });
        }
    }

    fn emit_verdict(&self, pid: Pid, exe: &str, verdict: Verdict, ts: Timestamp) {
        self.stats.verdicts.fetch_add(1, Relaxed);
        if verdict.action == Action::Block {
            self.stats.blocks.fetch_add(1, Relaxed);
        }
        self.send(EngineOutput::Verdict {
            ts: if ts.0 == 0 { utc_now_ms() } else { self.utc(ts) },
            pid,
            exe: exe.to_string(),
            verdict,
        });
    }
}

fn join_cmdline(argv: &[std::ffi::OsString]) -> String {
    argv.iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn utc_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc_table::ProcTable;
    use crate::rules::{RulesConfig, RulesSnapshot};
    use std::path::Path;

    fn engine_with(mut cfg: RulesConfig) -> (Arc<Engine>, tokio::sync::mpsc::Receiver<EngineOutput>) {
        let (tx, rx) = mpsc::channel(64);
        let procs = Arc::new(ProcTable::new());
        procs.bootstrap_insert(ProcTable::test_identity(
            20812,
            "C:/Program Files/ZCode/ZCode.exe",
            Some("zcode"),
        ));
        let rules = Arc::new(ArcSwap::from_pointee(RulesSnapshot::compile(&cfg).unwrap()));
        let eng = Engine::new(procs, Arc::new(ConnRegistry::new()), rules, tx, Arc::new(EngineStats::default()));
        (Arc::new(eng), rx)
    }

    fn engine() -> (Arc<Engine>, tokio::sync::mpsc::Receiver<EngineOutput>) {
        engine_with(RulesConfig::default())
    }

    fn drain(rx: &mut tokio::sync::mpsc::Receiver<EngineOutput>) -> Vec<EngineOutput> {
        let mut out = Vec::new();
        while let Ok(o) = rx.try_recv() {
            out.push(o);
        }
        out
    }

    fn kill_count(out: &[EngineOutput]) -> usize {
        out.iter().filter(|o| matches!(o, EngineOutput::Kill { .. })).count()
    }

    fn block_verdict_count(out: &[EngineOutput]) -> usize {
        out.iter()
            .filter(|o| matches!(
                o,
                EngineOutput::Verdict { verdict: v, .. } if v.rule_id.0 == "git-dir" && v.action == Action::Block
            ))
            .count()
    }

    /// 注入面（hooks 写 / config 写）创建 → Block 判定 + 通知，**默认不杀**
    /// （拍板记录 13：git_dir_kill 缺省 false，打包与网络两重兜底仍在）
    #[test]
    fn 创建_git_注入面_默认阻断不杀() {
        for p in ["D:/repo/.git/hooks/pre-commit", "D:/repo/.git/config"] {
            let (eng, mut rx) = engine();
            eng.on_file_create(20812, Path::new(p), Timestamp(0)).unwrap();
            let out = drain(&mut rx);
            assert_eq!(block_verdict_count(&out), 1, "{p}：应有 git-dir Block 判定");
            assert_eq!(kill_count(&out), 0, "{p}：默认不得杀进程");
            assert!(out.iter().any(|o| matches!(o, EngineOutput::Notify { .. })), "{p}：应有通知");
        }
    }

    /// git_dir_kill=true 时注入面创建升级为杀进程（用户显式开启）
    #[test]
    fn 创建_git_注入面_开启kill则杀() {
        let mut cfg = RulesConfig::default();
        cfg.git_dir_kill = true;
        let (eng, mut rx) = engine_with(cfg);
        eng.on_file_create(20812, Path::new("D:/repo/.git/hooks/pre-commit"), Timestamp(0)).unwrap();
        let out = drain(&mut rx);
        assert_eq!(kill_count(&out), 1);
        assert_eq!(block_verdict_count(&out), 1);
    }

    /// 打开路径（Read/Write 事件）同样受 git_dir_kill 门控
    #[test]
    fn 打开_git_注入面_默认不杀_kil开启则杀() {
        let (eng, mut rx) = engine();
        eng.on_file_open(20812, Path::new("D:/repo/.git/hooks/pre-commit"), hg_model::Access::Read).unwrap();
        let out = drain(&mut rx);
        assert_eq!(block_verdict_count(&out), 1);
        assert_eq!(kill_count(&out), 0);

        let mut cfg = RulesConfig::default();
        cfg.git_dir_kill = true;
        let (eng, mut rx) = engine_with(cfg);
        eng.on_file_open(20812, Path::new("D:/repo/.git/hooks/pre-commit"), hg_model::Access::Read).unwrap();
        let out = drain(&mut rx);
        assert_eq!(kill_count(&out), 1);
    }

    /// 工作流面创建（commit 写 objects / HEAD.lock）→ 放行不杀，每 root 首见一条取证
    #[test]
    fn 创建_git_工作流面_放行且首见留痕() {
        let (eng, mut rx) = engine();
        eng.on_file_create(20812, Path::new("D:/repo/.git/objects/1b/bdae002"), Timestamp(0)).unwrap();
        let first = drain(&mut rx);
        assert_eq!(kill_count(&first), 0);
        assert!(first.iter().any(|o| matches!(
            o,
            EngineOutput::Verdict { verdict: v, .. }
                if v.rule_id.0 == "git-dir-workflow" && v.action == Action::Allow
        )));
        // 同 root 第二条工作流面访问：静默（防 status/diff 高频读写刷库）
        eng.on_file_create(20812, Path::new("D:/repo/.git/HEAD.lock"), Timestamp(0)).unwrap();
        let second = drain(&mut rx);
        assert!(second.is_empty());
    }

    /// 工作流面读（status 读 config）放行且无任何处置
    #[test]
    fn 打开_git_工作流面_放行() {
        let (eng, mut rx) = engine();
        eng.on_file_open(20812, Path::new("D:/repo/.git/config"), hg_model::Access::Read).unwrap();
        let out = drain(&mut rx);
        assert_eq!(kill_count(&out), 0);
        assert!(out.iter().any(|o| matches!(
            o,
            EngineOutput::Verdict { verdict: v, .. }
                if v.rule_id.0 == "git-dir-workflow" && v.action == Action::Allow
        )));
    }

    /// 打包双信号之信号 2（需求 §3.1）：进程内创建归档产物（无独立子进程，
    /// 模拟 Node archiver 类库）→ archive-create Block + 杀进程。
    /// 打包封堵不受 git_dir_kill 门控（拍板记录 13 仅作用于 git 注入面）。
    #[test]
    fn 创建归档产物_阻断并杀进程() {
        for name in ["D:/tmp/out2.zip", "D:/tmp/repo.tar.gz", "D:/tmp/x.7z"] {
            let (eng, mut rx) = engine();
            eng.on_file_create(20812, Path::new(name), Timestamp(0)).unwrap();
            let out = drain(&mut rx);
            assert!(
                out.iter().any(|o| matches!(
                    o,
                    EngineOutput::Verdict { verdict: v, .. }
                        if v.rule_id.0 == "archive-create" && v.action == Action::Block
                )),
                "{name}：应有 archive-create Block 判定"
            );
            assert_eq!(kill_count(&out), 1, "{name}：打包封堵应杀进程");
        }
    }

    /// 归档产物：archive_action=audit 时不杀只记录
    #[test]
    fn 创建归档产物_audit模式不杀() {
        let mut cfg = RulesConfig::default();
        cfg.archive_action = crate::rules::FileAction::Audit;
        let (eng, mut rx) = engine_with(cfg);
        eng.on_file_create(20812, Path::new("D:/tmp/out.zip"), Timestamp(0)).unwrap();
        let out = drain(&mut rx);
        assert_eq!(kill_count(&out), 0);
        assert!(out.iter().any(|o| matches!(
            o,
            EngineOutput::Verdict { verdict: v, .. }
                if v.rule_id.0 == "archive-create" && v.action == Action::Audit
        )));
    }

    // ---------- 网络层（on_conn_tx 阈值路径，需求 §3.2）----------

    use hg_model::HarnessId;

    fn conn_open(eng: &Engine, cid: u64, ip: &str) {
        eng.conns.on_open(
            ConnId(cid),
            crate::conn_registry::ConnEntry {
                pid: 20812,
                start_time: StartTime(1),
                harness_root: Some(HarnessId("zcode".into())),
                proto: Proto::Tcp,
                local: "127.0.0.1:50000".parse().unwrap(),
                remote: ip.parse().unwrap(),
                bytes_out: 0,
                opened_ts: Timestamp(0),
            },
        );
    }

    fn net_output_count(out: &[EngineOutput]) -> (usize, usize, usize) {
        // (net-threshold Block 判定, DropTcp, BlockIp)
        (
            out.iter().filter(|o| matches!(o,
                EngineOutput::Verdict { verdict: v, .. }
                    if v.rule_id.0 == "net-threshold" && v.action == Action::Block)).count(),
            out.iter().filter(|o| matches!(o, EngineOutput::DropTcp { .. })).count(),
            out.iter().filter(|o| matches!(o, EngineOutput::BlockIp { .. })).count(),
        )
    }

    /// 累计上行超阈值 → net-threshold Block + 断连接 + 封 IP（需求 §3.2）
    #[test]
    fn 上行超阈值_阻断断连封ip() {
        let mut cfg = RulesConfig::default();
        cfg.upload_threshold_mb = 1; // 1MB 阈值便于测试
        let (eng, mut rx) = engine_with(cfg);
        conn_open(&eng, 7, "8.8.8.8:443");
        // 两笔累计 1.5MB：第一笔未超，第二笔越线触发
        eng.on_conn_tx(ConnId(7), 600 * 1024, Timestamp(0));
        assert_eq!(net_output_count(&drain(&mut rx)), (0, 0, 0), "未超阈值不得处置");
        eng.on_conn_tx(ConnId(7), 900 * 1024, Timestamp(1));
        let (v, drop, block) = net_output_count(&drain(&mut rx));
        assert_eq!((v, drop, block), (1, 1, 1), "超阈值应出判定+断连+封IP");
    }

    /// 白名单端点不计入阈值（域名经 dns_map 反查命中，需求 §3.2）
    #[test]
    fn 白名单端点_不计入阈值() {
        let mut cfg = RulesConfig::default();
        cfg.upload_threshold_mb = 1;
        let (eng, mut rx) = engine_with(cfg);
        conn_open(&eng, 8, "1.2.3.4:443");
        eng.dns.insert("1.2.3.4".parse().unwrap(), "api.anthropic.com".into());
        eng.on_conn_tx(ConnId(8), 5 * 1024 * 1024, Timestamp(0)); // 5MB 远超 1MB
        let out = drain(&mut rx);
        assert!(out.is_empty(), "白名单端点大流量也不得触发处置");
    }

    /// 两级评分联动（需求 §3.1）：监控根读过敏感文件后阈值降为 1/N
    #[test]
    fn 敏感降档_阈值十分之一即触发() {
        let mut cfg = RulesConfig::default();
        cfg.upload_threshold_mb = 1;
        cfg.sensitive_escalation_divisor = 10;
        let (eng, mut rx) = engine_with(cfg);
        eng.root_sensitive.insert("zcode".into()); // 模拟已读敏感文件
        conn_open(&eng, 9, "8.8.8.8:443");
        // 200KB < 1MB 原阈值，但 > 1MB/10 降档阈值 → 触发
        eng.on_conn_tx(ConnId(9), 200 * 1024, Timestamp(0));
        let (v, _, _) = net_output_count(&drain(&mut rx));
        assert_eq!(v, 1, "降档后 200KB 即应触发");
    }

    /// 已处置连接（handled_conns）不再重复处置（防处置风暴）
    #[test]
    fn 已处置连接_不重复处置() {
        let mut cfg = RulesConfig::default();
        cfg.upload_threshold_mb = 1;
        let (eng, mut rx) = engine_with(cfg);
        conn_open(&eng, 10, "8.8.8.8:443");
        eng.on_conn_tx(ConnId(10), 2 * 1024 * 1024, Timestamp(0));
        assert_eq!(net_output_count(&drain(&mut rx)).0, 1);
        // 同连接继续上行：不再出第二条判定
        eng.on_conn_tx(ConnId(10), 2 * 1024 * 1024, Timestamp(1));
        let out = drain(&mut rx);
        assert!(out.is_empty(), "同连接不得重复处置");
    }
}
