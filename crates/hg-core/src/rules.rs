//! 规则配置、预编译快照与快路径同步判定（技术设计 §3.3 / §6）。
//!
//! 快路径 [`judge_perm_sync`]：纯函数、无 IO、无系统调用。唯一有同步判定预算的
//! 调用方是 Linux fanotify PERM 事件（微秒级）；Windows/macOS 的事件流文件判定
//! 在异步线程复用同一函数，语义一致。
//! 规则热更新：快照经 arc-swap 原子替换（M1 接入），快慢路径读取全程无锁。
//!
//! 匹配约定：所有 glob 匹配统一大小写不敏感（Windows 文件系统大小写不敏感，
//! 宁多判勿漏判）；路径匹配前把 `\` 归一化为 `/`。

use std::ffi::OsString;
use std::net::IpAddr;
use std::path::Path;

use hg_model::{Access, Action, Evidence, Identity, RuleId, Verdict};
use serde::{Deserialize, Serialize};

/// 文件类规则动作（需求 §3.1：默认阻断，用户可改为审计）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileAction {
    Block,
    Audit,
}

/// harness 特征库条目（需求 §3.4：路径 glob；哈希特征 M1 扩展）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessFeature {
    pub name: String,
    /// 设计 §6 TOML 键名为 `paths`，此处字段名 path_globs，serde alias 双兼容
    #[serde(alias = "paths")]
    pub path_globs: Vec<String>,
}

/// 默认 harness 特征库（需求 §3.4 路径 glob；ProcessesConf 与 RulesConfig 的
/// Default 共用此单一来源）。匹配大小写不敏感（见 build_matcher），glob 用小写。
/// 覆盖各工具 CLI / IDE / 桌面形态；纯 VS Code 扩展形态（roo-code、cline/kilo-code
/// 扩展）无独立 exe，路径特征不可达。autoclaw/workbuddy 的 exe 名来自第三方
/// 资料（官方未文档化），待实机确认。
pub fn default_harness_features() -> Vec<HarnessFeature> {
    vec![
        HarnessFeature { name: "claude-code".into(), path_globs: vec!["**/claude*".into()] },
        HarnessFeature { name: "zcode".into(), path_globs: vec!["**/zcode*".into()] },
        HarnessFeature { name: "codex".into(), path_globs: vec!["**/codex*".into()] },
        HarnessFeature { name: "cursor".into(), path_globs: vec!["**/cursor*".into()] },
        HarnessFeature { name: "autoclaw".into(), path_globs: vec!["**/autoclaw*".into()] },
        HarnessFeature { name: "workbuddy".into(), path_globs: vec!["**/workbuddy*".into()] },
        HarnessFeature { name: "codebuddy".into(), path_globs: vec!["**/codebuddy*".into()] },
        HarnessFeature { name: "qoder".into(), path_globs: vec!["**/qoder*".into()] },
        HarnessFeature { name: "trae".into(), path_globs: vec!["**/trae*".into()] },
        HarnessFeature { name: "cline".into(), path_globs: vec!["**/cline*".into()] },
        HarnessFeature { name: "opencode".into(), path_globs: vec!["**/opencode*".into()] },
        HarnessFeature { name: "kilo-code".into(), path_globs: vec!["**/kilocode*".into()] },
    ]
}

/// 身份矩阵豁免条目（需求 §3.3：工具 × 路径模式）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExemptConf {
    pub exe: String,
    pub allow_paths: Vec<String>,
}

/// 规则配置的内存形态（技术设计 §6 的默认值即 [`RulesConfig::default`]；
/// TOML 解析与"文件 + Web UI 双通道"写回在 M1 接入）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    pub upload_threshold_mb: u64,
    pub sensitive_escalation_divisor: u64,
    pub endpoints_allow: Vec<String>,
    pub git_dir_action: FileAction,
    pub archive_action: FileAction,
    pub sensitive_patterns: Vec<String>,
    pub archive_patterns: Vec<String>,
    pub blocked_commands: Vec<String>,
    pub harness: Vec<HarnessFeature>,
    pub tool_exempt: Vec<ToolExemptConf>,
    pub whitelist_paths: Vec<String>,
}

impl Default for RulesConfig {
    /// 技术设计 §6 内置默认值（编译进二进制，用户配置覆盖式合并）。
    fn default() -> Self {
        Self {
            upload_threshold_mb: 100,
            sensitive_escalation_divisor: 10,
            endpoints_allow: vec![
                "api.anthropic.com".into(),
                "api.openai.com".into(),
                "*.github.com".into(),
                "*.googleapis.com".into(),
            ],
            git_dir_action: FileAction::Block,
            archive_action: FileAction::Block,
            sensitive_patterns: vec![
                ".env".into(),
                ".env.*".into(),
                "*_rsa".into(),
                "*.pem".into(),
                "*credentials*".into(),
            ],
            archive_patterns: vec![
                "*.zip".into(),
                "*.tar".into(),
                "*.tar.gz".into(),
                "*.tgz".into(),
                "*.7z".into(),
                "*.gz".into(),
                "*.zst".into(),
            ],
            blocked_commands: vec![
                "git archive*".into(),
                "git bundle*".into(),
                "git format-patch*".into(),
                "tar *".into(),
                "zip *".into(),
                "7z *".into(),
                "gzip *".into(),
                "zstd *".into(),
            ],
            harness: default_harness_features(),
            tool_exempt: vec![ToolExemptConf {
                exe: "git".into(),
                allow_paths: vec![".git/**".into()],
            }],
            whitelist_paths: vec![],
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RulesError {
    #[error("非法 glob 模式 {pattern:?}: {source}")]
    BadGlob {
        pattern: String,
        #[source]
        source: globset::Error,
    },
}

/// 预编译的工具豁免条目。
#[derive(Debug, Clone)]
struct ToolExemptCompiled {
    exe: String,
    /// 目录型模式（如 ".git/**" 的 ".git"）：路径任一组件命中即视为目录内访问。
    exempt_dirs: Vec<String>,
    /// 其余模式：对规范化完整路径做 glob 匹配。
    allow_globs: globset::GlobSet,
}

/// 预编译规则快照（技术设计 §3.3）：构建时把通配符编译为 glob、端点编译为
/// 域名 glob + IP 哈希集；读取全程无锁。热更新 = 整体原子替换（M1 挂 arc-swap）。
#[derive(Debug, Clone)]
pub struct RulesSnapshot {
    harness: Vec<(globset::GlobMatcher, String)>,
    tool_exempt: Vec<ToolExemptCompiled>,
    whitelist_paths: globset::GlobSet,
    sensitive: Vec<globset::GlobMatcher>,
    archive: Vec<globset::GlobMatcher>,
    blocked_commands: Vec<globset::GlobMatcher>,
    endpoints_domain: Vec<globset::GlobMatcher>,
    endpoints_ip: Vec<IpAddr>,
    pub git_dir_action: FileAction,
    pub archive_action: FileAction,
    pub upload_threshold_bytes: u64,
    pub escalation_divisor: u64,
}

fn norm(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn build_matcher(pattern: &str) -> Result<globset::GlobMatcher, RulesError> {
    globset::GlobBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .map(|g| g.compile_matcher())
        .map_err(|e| RulesError::BadGlob {
            pattern: pattern.to_string(),
            source: e,
        })
}

fn build_set(patterns: &[String]) -> Result<globset::GlobSet, RulesError> {
    let mut b = globset::GlobSetBuilder::new();
    for p in patterns {
        let g = globset::GlobBuilder::new(p)
            .case_insensitive(true)
            .build()
            .map_err(|e| RulesError::BadGlob {
                pattern: p.clone(),
                source: e,
            })?;
        b.add(g);
    }
    b.build().map_err(|e| RulesError::BadGlob {
        pattern: "<globset>".into(),
        source: e,
    })
}

impl RulesSnapshot {
    pub fn compile(cfg: &RulesConfig) -> Result<Self, RulesError> {
        let harness = cfg
            .harness
            .iter()
            .flat_map(|h| h.path_globs.iter().map(move |p| (p, h.name.clone())))
            .map(|(p, name)| Ok((build_matcher(p)?, name)))
            .collect::<Result<Vec<_>, RulesError>>()?;

        let tool_exempt = cfg
            .tool_exempt
            .iter()
            .map(|t| {
                // 目录型模式（后缀 "/**"）拆出来走组件匹配，其余走完整路径 glob。
                let mut exempt_dirs = Vec::new();
                let mut plain = Vec::new();
                for p in &t.allow_paths {
                    if let Some(dir) = p.strip_suffix("/**") {
                        exempt_dirs.push(dir.to_string());
                    } else {
                        plain.push(p.clone());
                    }
                }
                Ok(ToolExemptCompiled {
                    exe: t.exe.clone(),
                    exempt_dirs,
                    allow_globs: build_set(&plain)?,
                })
            })
            .collect::<Result<Vec<_>, RulesError>>()?;

        let mut endpoints_domain = Vec::new();
        let mut endpoints_ip = Vec::new();
        for e in &cfg.endpoints_allow {
            if let Ok(ip) = e.parse::<IpAddr>() {
                endpoints_ip.push(ip);
            } else {
                endpoints_domain.push(build_matcher(e)?);
            }
        }

        Ok(Self {
            harness,
            tool_exempt,
            whitelist_paths: build_set(&cfg.whitelist_paths)?,
            sensitive: cfg
                .sensitive_patterns
                .iter()
                .map(|p| build_matcher(p))
                .collect::<Result<Vec<_>, _>>()?,
            archive: cfg
                .archive_patterns
                .iter()
                .map(|p| build_matcher(p))
                .collect::<Result<Vec<_>, _>>()?,
            blocked_commands: cfg
                .blocked_commands
                .iter()
                .map(|p| build_matcher(p))
                .collect::<Result<Vec<_>, _>>()?,
            endpoints_domain,
            endpoints_ip,
            git_dir_action: cfg.git_dir_action,
            archive_action: cfg.archive_action,
            upload_threshold_bytes: cfg.upload_threshold_mb.saturating_mul(1024 * 1024),
            escalation_divisor: cfg.sensitive_escalation_divisor.max(1),
        })
    }

    /// exe 完整路径命中 harness 特征库 → 返回特征名（监控根标识）。
    pub fn match_harness(&self, exe: &Path) -> Option<&str> {
        let s = norm(exe);
        self.harness
            .iter()
            .find(|(m, _)| m.is_match(&s))
            .map(|(_, name)| name.as_str())
    }

    /// exe 文件名命中 tool_exempt 表 → 返回工具名（文件名先去 .exe 后缀归一化）。
    pub fn match_tool_exempt(&self, exe: &Path) -> Option<&str> {
        let raw = exe.file_name()?.to_str()?;
        let name = raw
            .strip_suffix(".exe")
            .or_else(|| raw.strip_suffix(".EXE"))
            .unwrap_or(raw);
        self.tool_exempt
            .iter()
            .find(|t| t.exe.eq_ignore_ascii_case(name))
            .map(|t| t.exe.as_str())
    }

    /// 身份矩阵豁免判定：豁免工具 × 豁免路径（需求 §3.3）。
    fn tool_exempt_allows(&self, tool: &str, path: &Path) -> bool {
        let Some(t) = self
            .tool_exempt
            .iter()
            .find(|t| t.exe.eq_ignore_ascii_case(tool))
        else {
            return false;
        };
        if path.components().any(|c| {
            let comp = c.as_os_str().to_string_lossy();
            t.exempt_dirs.iter().any(|d| comp.eq_ignore_ascii_case(d))
        }) {
            return true;
        }
        t.allow_globs.is_match(&norm(path))
    }

    /// 用户路径白名单（快路径规则 0 短路，需求 §4.3）。
    pub fn is_path_whitelisted(&self, path: &Path) -> bool {
        self.whitelist_paths.is_match(&norm(path))
    }

    /// 敏感文件命中（文件名级 glob，需求 §3.1 规则 1）。
    pub fn match_sensitive(&self, path: &Path) -> bool {
        match path.file_name().map(|f| f.to_string_lossy()) {
            Some(name) => self.sensitive.iter().any(|m| m.is_match(name.as_ref())),
            None => false,
        }
    }

    /// 归档产物后缀命中（文件名级 glob，需求 §3.1 打包双信号之一）。
    pub fn match_archive(&self, path: &Path) -> bool {
        match path.file_name().map(|f| f.to_string_lossy()) {
            Some(name) => self.archive.iter().any(|m| m.is_match(name.as_ref())),
            None => false,
        }
    }

    /// Exec 命令行封堵（需求 §3.3 导出型命令封堵）。
    /// argv[0] 归一化（取文件名、去 .exe 后缀）后与参数按空白拼接匹配 glob；
    /// 引号/转义信息已丢失，按空白拼接是保守近似，M1 视实测需要可改 token 级匹配。
    pub fn match_blocked_command(&self, argv: &[OsString]) -> bool {
        match join_argv(argv) {
            Some(joined) => self.blocked_commands.iter().any(|m| m.is_match(&joined)),
            None => false,
        }
    }

    /// 端点白名单（域名优先经 dns_map 解析匹配，DoH 下退化按 IP，需求 §3.2）。
    pub fn endpoint_allowed(&self, domain: Option<&str>, ip: IpAddr) -> bool {
        if let Some(d) = domain {
            if self.endpoints_domain.iter().any(|m| m.is_match(d)) {
                return true;
            }
        }
        self.endpoints_ip.contains(&ip)
    }
}

fn join_argv(argv: &[OsString]) -> Option<String> {
    let mut s = String::new();
    for (i, a) in argv.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        if i == 0 {
            let raw = a.to_string_lossy().into_owned();
            let p = Path::new(&raw);
            let name = p
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or(raw);
            let name = name
                .strip_suffix(".exe")
                .or_else(|| name.strip_suffix(".EXE"))
                .unwrap_or(name.as_str());
            s.push_str(name);
        } else {
            s.push_str(&a.to_string_lossy());
        }
    }
    Some(s)
}

/// 路径任一组件为 ".git"（即 .git 目录下文件；含嵌套如 .git/objects/xx）。
pub fn under_git_dir(path: &Path) -> bool {
    path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .is_some_and(|s| s.eq_ignore_ascii_case(".git"))
    })
}

fn verdict(rule_id: &'static str, action: Action, summary: impl Into<String>) -> Verdict {
    Verdict {
        rule_id: RuleId(rule_id),
        action,
        evidence: Evidence {
            summary: summary.into(),
            detail: serde_json::Value::Null, // M1 填结构化证据（路径/连接/累计字节/关联记录）
        },
    }
}

/// 快路径同步判定（技术设计 §3.3）。纯函数、无 IO、无系统调用。
///
/// 判定次序（编号对应技术设计 §3.3 步骤）：
/// 0. 用户白名单短路 → Allow；
/// 1. 非监控进程（harness_root 为 None）→ Allow（不干预）；
/// 2. tool_exempt 工具 × 豁免路径 → Allow（需求 §3.3 身份矩阵）；
/// 3. harness 进程（非豁免工具）触碰 `.git/**` → 按 git_dir_action（默认 Block）；
/// 4. 敏感文件命中 → Audit（放行不阻断，供取证与评分联动）；
/// 5. 默认 Allow。
///
/// 说明：规则 3 对读/写一律生效——设计原文为"读 .git 阻断"，但 harness 进程
/// 无正当直写 .git 的场景（写 .git 走 git 工具的豁免分支），读写一并拒更保守。
pub fn judge_perm_sync(rules: &RulesSnapshot, id: &Identity, path: &Path, _access: Access) -> Verdict {
    // 0. 用户白名单短路
    if rules.is_path_whitelisted(path) {
        return verdict("whitelist", Action::Allow, format!("路径在用户白名单：{}", path.display()));
    }

    // 1. 非监控进程不干预
    let Some(root) = id.harness_root.as_ref() else {
        return verdict("non-harness", Action::Allow, "非监控进程");
    };

    // 2. 身份矩阵豁免：豁免工具的本职路径访问
    if let Some(tool) = &id.tool_exempt {
        if rules.tool_exempt_allows(tool, path) {
            return verdict(
                "tool-exempt",
                Action::Allow,
                format!("豁免工具 {tool} 的本职路径访问：{}", path.display()),
            );
        }
    }

    // 3. .git/**（需求 §3.1：窃取 .git = 窃取全仓库历史与凭据配置）
    if under_git_dir(path) {
        let summary = format!(
            "[{}] {} 触碰 .git：{}",
            root.0,
            id.exe.display(),
            path.display()
        );
        return match rules.git_dir_action {
            FileAction::Block => verdict("git-dir", Action::Block, summary),
            FileAction::Audit => verdict("git-dir", Action::Audit, summary),
        };
    }

    // 4. 敏感文件：放行 + Audit（不阻断，读取常见于正常工作流，需求 §3.1）
    if rules.match_sensitive(path) {
        return verdict(
            "sensitive-read",
            Action::Audit,
            format!("[{}] 读取敏感文件：{}", root.0, path.display()),
        );
    }

    // 5. 默认放行（异步路径仍可审计）
    verdict("default-allow", Action::Allow, "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hg_model::{HarnessId, StartTime};
    use std::path::PathBuf;

    fn snapshot() -> RulesSnapshot {
        RulesSnapshot::compile(&RulesConfig::default()).unwrap()
    }

    fn harness_identity(exe: &str) -> Identity {
        Identity {
            pid: 100,
            start_time: StartTime(1),
            exe: PathBuf::from(exe),
            cmdline: vec![],
            harness_root: Some(HarnessId("test".into())),
            tool_exempt: None,
        }
    }

    #[test]
    fn 快路径_非监控进程默认放行() {
        let rules = snapshot();
        let mut id = harness_identity("C:/x/node.exe");
        id.harness_root = None;
        let v = judge_perm_sync(&rules, &id, Path::new("D:/repo/.git/config"), Access::Read);
        assert_eq!(v.rule_id.0, "non-harness");
        assert_eq!(v.action, Action::Allow);
    }

    #[test]
    fn 快路径_harness_触碰_git_阻断() {
        let rules = snapshot();
        let id = harness_identity("C:/x/node.exe");
        let v = judge_perm_sync(&rules, &id, Path::new("D:/repo/.git/config"), Access::Read);
        assert_eq!(v.rule_id.0, "git-dir");
        assert_eq!(v.action, Action::Block);
    }

    #[test]
    fn 快路径_普通_git_目录不算_git_目录() {
        let rules = snapshot();
        let id = harness_identity("C:/x/node.exe");
        // 名为 "git" 的普通目录（无前导点）不触发 .git 规则
        let v = judge_perm_sync(&rules, &id, Path::new("D:/repo/git/config"), Access::Read);
        assert_eq!(v.rule_id.0, "default-allow");
    }

    #[test]
    fn 快路径_豁免工具读_git_放行() {
        let rules = snapshot();
        let mut id = harness_identity("C:/Program Files/Git/cmd/git.exe");
        id.tool_exempt = Some("git".into());
        let v = judge_perm_sync(&rules, &id, Path::new("D:/repo/.git/objects/ab/cd"), Access::Read);
        assert_eq!(v.rule_id.0, "tool-exempt");
        assert_eq!(v.action, Action::Allow);
    }

    #[test]
    fn 快路径_豁免工具访问非豁免路径不豁免() {
        let rules = snapshot();
        let mut id = harness_identity("C:/Program Files/Git/cmd/git.exe");
        id.tool_exempt = Some("git".into());
        // git 读 .git 外的敏感文件：不享受豁免，走敏感文件规则
        let v = judge_perm_sync(&rules, &id, Path::new("D:/repo/.env"), Access::Read);
        assert_eq!(v.rule_id.0, "sensitive-read");
        assert_eq!(v.action, Action::Audit);
    }

    #[test]
    fn 快路径_敏感文件审计放行() {
        let rules = snapshot();
        let id = harness_identity("C:/x/node.exe");
        for p in ["D:/repo/.env", "D:/repo/.env.production", "D:/repo/id_rsa", "D:/x/cert.pem"] {
            let v = judge_perm_sync(&rules, &id, Path::new(p), Access::Read);
            assert_eq!(v.rule_id.0, "sensitive-read", "{p}");
            assert_eq!(v.action, Action::Audit);
        }
    }

    #[test]
    fn 快路径_白名单短路() {
        let mut cfg = RulesConfig::default();
        cfg.whitelist_paths = vec!["D:/safe/**".into()];
        let rules = RulesSnapshot::compile(&cfg).unwrap();
        let id = harness_identity("C:/x/node.exe");
        let v = judge_perm_sync(&rules, &id, Path::new("D:/safe/.git/config"), Access::Read);
        assert_eq!(v.rule_id.0, "whitelist");
    }

    #[test]
    fn 命令封堵_导出型命令命中() {
        let rules = snapshot();
        let hit = vec![
            vec!["C:/Program Files/Git/cmd/git.exe", "archive", "--format=zip", "HEAD"],
            vec!["git", "bundle", "create", "x.bundle", "--all"],
            vec!["git", "format-patch", "-1"],
            vec!["/usr/bin/tar", "czf", "out.tgz", "."],
            vec!["7z.exe", "a", "x.7z", "."],
        ];
        for argv in hit {
            let argv: Vec<OsString> = argv.into_iter().map(Into::into).collect();
            assert!(rules.match_blocked_command(&argv), "{argv:?}");
        }
        let miss: Vec<OsString> = vec!["C:/Program Files/Git/cmd/git.exe", "status"]
            .into_iter()
            .map(Into::into)
            .collect();
        assert!(!rules.match_blocked_command(&miss));
    }

    #[test]
    fn 归档产物后缀命中() {
        let rules = snapshot();
        for name in ["a.zip", "repo.tar.gz", "x.7z", "y.tgz", "z.zst"] {
            assert!(rules.match_archive(Path::new(name)), "{name}");
        }
        assert!(!rules.match_archive(Path::new("main.rs")));
    }

    #[test]
    fn 端点白名单_域名与_ip() {
        let rules = snapshot();
        assert!(rules.endpoint_allowed(Some("api.anthropic.com"), "1.2.3.4".parse().unwrap()));
        assert!(rules.endpoint_allowed(Some("api.github.com"), "1.2.3.4".parse().unwrap()));
        assert!(!rules.endpoint_allowed(Some("evil.example.com"), "1.2.3.4".parse().unwrap()));
        // DoH 退化：无域名时按 IP 判
        assert!(!rules.endpoint_allowed(None, "1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn 特征库_路径命中() {
        let rules = snapshot();
        assert_eq!(
            rules.match_harness(Path::new("C:/Users/u/app/node_modules/.bin/claude.exe")),
            Some("claude-code")
        );
        assert_eq!(rules.match_harness(Path::new("C:/Windows/system32/cmd.exe")), None);
    }
}
