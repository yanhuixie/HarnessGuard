//! 进程身份表（技术设计 §3.2）：pid → Identity，DashMap 分片锁，Exec/Exit 热路径无全局锁。

use std::collections::hash_map::RandomState;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use dashmap::DashMap;
use hg_model::{HarnessId, Identity, Pid, StartTime};

use crate::rules::RulesSnapshot;

#[derive(Default)]
pub struct ProcTable {
    inner: DashMap<Pid, Identity, RandomState>,
}

impl ProcTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, pid: &Pid) -> Option<Identity> {
        self.inner.get(pid).map(|v| v.clone())
    }

    /// Exec 事件落地：三步身份判定（技术设计 §3.2）并写入表。
    /// 1. exe 命中 harness 特征库 → 自成监控根；
    /// 2. 否则继承父进程的 harness_root（跨 shell 链传播，覆盖计划任务/shell/
    ///    第三方拉起，需求 §3.4）；
    /// 3. 命中 tool_exempt 表 → 标记豁免身份——仍继承 harness_root（豁免靠
    ///    "工具 × 路径"矩阵分支，不脱离进程树，需求 §3.3）。
    ///
    /// 同 pid 重复 Exec（pid 复用）时按 start_time 自然覆盖为最新身份。
    pub fn apply_exec(
        &self,
        rules: &RulesSnapshot,
        pid: Pid,
        ppid: Pid,
        start_time: StartTime,
        exe: &Path,
        cmdline: Vec<OsString>,
    ) -> Identity {
        let own_root = rules
            .match_harness(exe)
            .map(|name| HarnessId(name.to_string()));
        let inherited = own_root
            .is_none()
            .then(|| self.get(&ppid))
            .flatten()
            .and_then(|p| p.harness_root.clone());
        let id = Identity {
            pid,
            start_time,
            exe: exe.to_path_buf(),
            cmdline,
            harness_root: own_root.or(inherited),
            tool_exempt: rules.match_tool_exempt(exe).map(|s| s.to_string()),
        };
        self.inner.insert(pid, id.clone());
        id
    }

    /// Exit 事件清理：pid + start_time 双匹配才删（防误删复用 pid 的新进程）。
    pub fn apply_exit(&self, pid: Pid, start_time: StartTime) -> Option<Identity> {
        if let Some(entry) = self.inner.get(&pid) {
            if entry.start_time != start_time {
                return None;
            }
            drop(entry);
            return self.inner.remove(&pid).map(|(_, v)| v);
        }
        None
    }

    /// 启动补扫描写入（技术设计 §3.2：服务晚于 harness 启动时按 exe 特征直接判定，
    /// 宁标勿漏；中间父链无法精确重建）。
    pub fn bootstrap_insert(&self, id: Identity) {
        self.inner.insert(id.pid, id);
    }

    /// 启动补扫描（技术设计 §3.2）：全量进程快照按特征库补建根身份，子进程继承
    /// 传播（迭代至收敛，防快照顺序影响；未观察到的中间父链按 exe 特征直接判定，
    /// 宁标勿漏）。
    pub fn apply_bootstrap(
        &self,
        rules: &RulesSnapshot,
        entries: Vec<(Pid, Pid, PathBuf, StartTime)>,
    ) -> usize {
        use std::collections::HashMap;
        let mut roots: HashMap<Pid, Option<HarnessId>> =
            entries.iter().map(|(pid, _, _, _)| (*pid, None)).collect();
        let by_pid: HashMap<Pid, (Pid, PathBuf, StartTime)> = entries
            .iter()
            .map(|(pid, ppid, exe, st)| (*pid, (*ppid, exe.clone(), *st)))
            .collect();
        for _round in 0..8 {
            let mut changed = false;
            for (pid, (ppid, exe, _)) in &by_pid {
                if roots.get(pid).is_some_and(|r| r.is_some()) {
                    continue;
                }
                let own = rules
                    .match_harness(exe)
                    .map(|name| HarnessId(name.to_string()));
                let inherited = own
                    .is_none()
                    .then(|| roots.get(ppid))
                    .flatten()
                    .cloned()
                    .flatten();
                let next = own.or(inherited);
                if next.is_some() {
                    roots.insert(*pid, next);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let mut inserted = 0usize;
        for (pid, (ppid, exe, st)) in &by_pid {
            let root = roots.get(pid).cloned().flatten();
            if root.is_none() {
                continue; // 非监控进程不入表（早过滤依赖表内查询）
            }
            let tool_exempt = rules.match_tool_exempt(exe).map(|s| s.to_string());
            self.bootstrap_insert(Identity {
                pid: *pid,
                start_time: *st,
                exe: exe.clone(),
                cmdline: vec![],
                harness_root: root,
                tool_exempt,
            });
            inserted += 1;
            let _ = ppid;
        }
        inserted
    }

    /// 身份表快照（UI /api/processes 用）。
    pub fn snapshot(&self) -> Vec<Identity> {
        self.inner.iter().map(|v| v.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// 测试辅助：按路径构造身份。
    #[cfg(test)]
    pub fn test_identity(pid: Pid, exe: &str, root: Option<&str>) -> Identity {
        Identity {
            pid,
            start_time: StartTime(pid as u64),
            exe: std::path::PathBuf::from(exe),
            cmdline: vec![],
            harness_root: root.map(|r| HarnessId(r.into())),
            tool_exempt: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{HarnessFeature, RulesConfig, RulesSnapshot};

    fn snapshot() -> RulesSnapshot {
        let mut cfg = RulesConfig::default();
        cfg.harness.push(HarnessFeature {
            name: "test-harness".into(),
            path_globs: vec!["**/testharness.exe".into()],
        });
        RulesSnapshot::compile(&cfg).unwrap()
    }

    #[test]
    fn exe_命中特征库自成监控根() {
        let t = ProcTable::new();
        let rules = snapshot();
        let id = t.apply_exec(
            &rules,
            10,
            1,
            StartTime(100),
            Path::new("C:/apps/testharness.exe"),
            vec![],
        );
        assert_eq!(id.harness_root.as_ref().unwrap().0, "test-harness");
    }

    #[test]
    fn 子进程跨_shell_链继承监控根() {
        let t = ProcTable::new();
        let rules = snapshot();
        // harness → cmd.exe（未命中特征库，纯继承）
        t.apply_exec(
            &rules,
            10,
            1,
            StartTime(100),
            Path::new("C:/apps/testharness.exe"),
            vec![],
        );
        let id = t.apply_exec(
            &rules,
            11,
            10,
            StartTime(110),
            Path::new("C:/Windows/system32/cmd.exe"),
            vec![],
        );
        assert_eq!(id.harness_root.as_ref().unwrap().0, "test-harness");
        // 再嵌一层：cmd → node
        let id2 = t.apply_exec(
            &rules,
            12,
            11,
            StartTime(120),
            Path::new("C:/node/node.exe"),
            vec![],
        );
        assert_eq!(id2.harness_root.as_ref().unwrap().0, "test-harness");
    }

    #[test]
    fn git_子进程标记豁免且不脱离进程树() {
        let t = ProcTable::new();
        let rules = snapshot();
        t.apply_exec(
            &rules,
            10,
            1,
            StartTime(100),
            Path::new("C:/apps/testharness.exe"),
            vec![],
        );
        let id = t.apply_exec(
            &rules,
            11,
            10,
            StartTime(110),
            Path::new("C:/Program Files/Git/cmd/git.exe"),
            vec![],
        );
        assert_eq!(id.tool_exempt.as_deref(), Some("git"));
        assert_eq!(id.harness_root.as_ref().unwrap().0, "test-harness"); // 仍继承 root
    }

    #[test]
    fn exit_双匹配防_pid_复用误删() {
        let t = ProcTable::new();
        t.bootstrap_insert(ProcTable::test_identity(10, "C:/x.exe", Some("root")));
        // start_time 不一致（pid 已被复用为新进程）→ 不删
        assert!(t.apply_exit(10, StartTime(999)).is_none());
        assert_eq!(t.len(), 1);
        // 匹配 → 删
        assert!(t.apply_exit(10, StartTime(10)).is_some());
        assert!(t.is_empty());
    }

    #[test]
    fn 无关进程_无监控根() {
        let t = ProcTable::new();
        let rules = snapshot();
        let id = t.apply_exec(
            &rules,
            100,
            99,
            StartTime(1),
            Path::new("C:/Windows/system32/notepad.exe"),
            vec![],
        );
        assert!(id.harness_root.is_none());
        assert!(id.tool_exempt.is_none());
    }
}
