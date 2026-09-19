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
                // Windows 文件无同步拒绝点：事后杀进程（技术设计 §3.1/拍板 2）
                let summary = v.evidence.summary.clone();
                self.emit_verdict(pid, &id.exe.display().to_string(), v.clone(), Timestamp(0));
                self.send(EngineOutput::Kill {
                    pid,
                    start_time: id.start_time,
                    reason: summary.clone(),
                });
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
            Action::Allow => {}
        }
        Ok(())
    }

    fn on_file_create(&self, pid: Pid, path: &std::path::Path, ts: Timestamp) -> anyhow::Result<()> {
        let Some(id) = self.procs.get(&pid) else { return Ok(()) };
        let Some(root) = &id.harness_root else { return Ok(()) };
        let rules = self.rules.load();
        // .git 目录下创建文件同样命中 git-dir 规则（Create 事件先于 Read 到达，
        // Windows 事后处置语义下两者都要拦，防只靠后续事件漏判）
        if crate::rules::under_git_dir(path) {
            let summary = format!(
                "[{}] {} 触碰 .git（创建）：{}（pid {pid}）",
                root.0,
                id.exe.display(),
                path.display()
            );
            let v = Verdict {
                rule_id: RuleId("git-dir"),
                action: match rules.git_dir_action {
                    crate::rules::FileAction::Block => Action::Block,
                    crate::rules::FileAction::Audit => Action::Audit,
                },
                evidence: Evidence {
                    summary: summary.clone(),
                    detail: serde_json::json!({ "path": path.display().to_string(), "via": "file-create" }),
                },
            };
            self.emit_verdict(pid, &id.exe.display().to_string(), v, ts);
            if matches!(rules.git_dir_action, crate::rules::FileAction::Block) {
                self.send(EngineOutput::Kill { pid, start_time: id.start_time, reason: summary.clone() });
                self.send(EngineOutput::Notify {
                    title: "HarnessGuard：已阻断敏感路径访问".into(),
                    body: summary,
                });
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
