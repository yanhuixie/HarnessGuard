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

/// 默认端点白名单（EndpointsConf 与 RulesConfig 的 Default 共用此单一来源）。
/// 语义：发往这些端点的上行不计入外传阈值——各 harness 官方模型 API 与常见
/// LLM router（2026-09 调查；官方文档优先，trae 国际域与腾讯国际 API 域来自
/// 社区逆向资料、未经官方确认）。裸域名精确匹配，`*` 通配子域（build_matcher
/// 与 endpoint_allowed）。各工具均无出厂自带的远程 MCP 服务器，故无 MCP 预设。
pub fn default_endpoints_allow() -> Vec<String> {
    [
        // Claude Code
        "api.anthropic.com",
        // codex：API key 模式 / ChatGPT 登录模式（后端与授权）
        "api.openai.com",
        "chatgpt.com",
        "auth.openai.com",
        // GitHub Copilot / Gemini
        "*.github.com",
        "*.googleapis.com",
        // zcode / autoclaw（智谱）：海外 / 大陆
        "api.z.ai",
        "open.bigmodel.cn",
        // cursor（官方企业网络文档）
        "*.cursor.sh",
        // codebuddy / workbuddy（腾讯）：大陆 / 国际
        "copilot.tencent.com",
        "*.codebuddy.cn",
        "*.codebuddy.ai",
        // qoder（阿里）：IDE 网关；订阅模型 API 国内 / 国际
        "*.qoder.sh",
        "coding.dashscope.aliyuncs.com",
        "coding-intl.dashscope.aliyuncs.com",
        // trae（字节）：大陆 / 国际
        "*.trae.com.cn",
        "*.trae.ai",
        "*.traeapi.us",
        // cline
        "api.cline.bot",
        // opencode：Zen 网关 / 模型目录
        "opencode.ai",
        "models.dev",
        // kilo code
        "api.kilo.ai",
        // 常见 LLM router
        "openrouter.ai",
        "api.siliconflow.cn",
        "api.siliconflow.com",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// 默认 harness 特征库（需求 §3.4 路径 glob；ProcessesConf 与 RulesConfig 的
/// Default 共用此单一来源）。匹配大小写不敏感（见 build_matcher），glob 用小写。
/// 覆盖各工具 CLI / IDE / 桌面形态；纯 VS Code 扩展形态（roo-code、cline/kilo-code
/// 扩展）无独立 exe，路径特征不可达。autoclaw/workbuddy 的 exe 名来自第三方
/// 资料（官方未文档化），待实机确认。
pub fn default_harness_features() -> Vec<HarnessFeature> {
    vec![
        HarnessFeature {
            name: "claude-code".into(),
            path_globs: vec!["**/claude*".into()],
        },
        HarnessFeature {
            name: "zcode".into(),
            path_globs: vec!["**/zcode*".into()],
        },
        HarnessFeature {
            name: "codex".into(),
            path_globs: vec!["**/codex*".into()],
        },
        HarnessFeature {
            name: "cursor".into(),
            path_globs: vec!["**/cursor*".into()],
        },
        HarnessFeature {
            name: "autoclaw".into(),
            path_globs: vec!["**/autoclaw*".into()],
        },
        HarnessFeature {
            name: "workbuddy".into(),
            path_globs: vec!["**/workbuddy*".into()],
        },
        HarnessFeature {
            name: "codebuddy".into(),
            path_globs: vec!["**/codebuddy*".into()],
        },
        HarnessFeature {
            name: "qoder".into(),
            path_globs: vec!["**/qoder*".into()],
        },
        HarnessFeature {
            name: "trae".into(),
            path_globs: vec!["**/trae*".into()],
        },
        HarnessFeature {
            name: "cline".into(),
            path_globs: vec!["**/cline*".into()],
        },
        HarnessFeature {
            name: "opencode".into(),
            path_globs: vec!["**/opencode*".into()],
        },
        HarnessFeature {
            name: "kilo-code".into(),
            path_globs: vec!["**/kilocode*".into()],
        },
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
    /// git-dir 注入面命中 Block 判定时是否连带杀进程（拍板记录 13）。
    /// 缺省 false：只出 Block 判定 + 通知——ETW 事后语义下杀仅止损，且
    /// 打包封堵与网络阈值两重兜底仍在，是否升级交给用户。
    #[serde(default)]
    pub git_dir_kill: bool,
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
            endpoints_allow: default_endpoints_allow(),
            git_dir_action: FileAction::Block,
            git_dir_kill: false,
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
    /// 目录型模式（如 ".git/**" 的 ".git"）预拆分为小写段序列：路径组件
    /// 序列中存在连续匹配段即视为目录内访问——单段（".git"）等价原组件
    /// 匹配，多段（".git/objects"）修复旧实现"组件 eq 永不命中"的静默失效。
    exempt_dirs: Vec<Vec<String>>,
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
    /// git-dir 注入面 Block 是否连带杀进程（拍板记录 13，缺省 false）
    pub git_dir_kill: bool,
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
        // git 豁免编译期兜底（拍板记录 13 前置防线）：配置中缺失 git 条目时
        // 注入内置豁免并告警——需求 §3.3 明文"否则 git status/commit 全被打断"，
        // 空豁免表几乎必是配置链路异常（实测教训：文件与运行时快照可能分裂），
        // 不允许软状态静默失去兜底。用户自定义 git 条目存在时以用户为准。
        let mut tool_exempt_cfg = cfg.tool_exempt.clone();
        if !tool_exempt_cfg
            .iter()
            .any(|t| t.exe.eq_ignore_ascii_case("git"))
        {
            tracing::warn!("tool_exempt 缺少 git 条目，已按需求 §3.3 注入内置豁免（.git/**）");
            tool_exempt_cfg.push(ToolExemptConf {
                exe: "git".into(),
                allow_paths: vec![".git/**".into()],
            });
        }

        let harness = cfg
            .harness
            .iter()
            .flat_map(|h| h.path_globs.iter().map(move |p| (p, h.name.clone())))
            .map(|(p, name)| Ok((build_matcher(p)?, name)))
            .collect::<Result<Vec<_>, RulesError>>()?;

        let tool_exempt = tool_exempt_cfg
            .iter()
            .map(|t| {
                // 目录型模式（后缀 "/**"）拆出来走段序列匹配，其余走完整路径 glob。
                let mut exempt_dirs = Vec::new();
                let mut plain = Vec::new();
                for p in &t.allow_paths {
                    if let Some(dir) = p.strip_suffix("/**") {
                        exempt_dirs.push(
                            dir.split('/')
                                .filter(|s| !s.is_empty())
                                .map(|s| s.to_ascii_lowercase())
                                .collect(),
                        );
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
            git_dir_kill: cfg.git_dir_kill,
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
    /// 目录型模式按段序列滑窗匹配（大小写不敏感），支持 ".git" 单段与
    /// ".git/objects" 等多段前缀；其余模式按完整路径 glob。
    fn tool_exempt_allows(&self, tool: &str, path: &Path) -> bool {
        let Some(t) = self
            .tool_exempt
            .iter()
            .find(|t| t.exe.eq_ignore_ascii_case(tool))
        else {
            return false;
        };
        let comps: Vec<String> = path
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
            .collect();
        for segs in &t.exempt_dirs {
            let n = segs.len();
            if n == 0 || comps.len() < n {
                continue;
            }
            if (0..=comps.len() - n).any(|i| comps[i..i + n] == segs[..]) {
                return true;
            }
        }
        t.allow_globs.is_match(norm(path))
    }

    /// 用户路径白名单（快路径规则 0 短路，需求 §4.3）。
    pub fn is_path_whitelisted(&self, path: &Path) -> bool {
        self.whitelist_paths.is_match(norm(path))
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

/// `.git` 触碰是否落入**注入面**（需求 §3.1，拍板记录 12）：
/// - `hooks/**`：读写皆注入——hook 是 git 操作时的任意命令执行点
///   （持久化/凭据劫持向量），正常 harness 工作流不触碰；
/// - `config` / `config.lock`：仅**写**为注入（core.fsmonitor/pager 等
///   配置项可注入执行）——读是 status/diff 必经路径，放行。
///
/// 其余（objects/refs/logs/HEAD/index/各类锁文件等）为工作流面：git
/// status/commit/checkout 的本职读写，harness 内置 git 库（如 ZCode）
/// 在进程内直接操作，一并拒会打断全部正常 git 工作流。
pub fn is_git_injection_touch(path: &Path, access: Access) -> bool {
    let mut comps = path.components();
    while let Some(c) = comps.next() {
        if !c
            .as_os_str()
            .to_str()
            .is_some_and(|s| s.eq_ignore_ascii_case(".git"))
        {
            continue;
        }
        let Some(first) = comps.next() else {
            return false;
        };
        let first = first.as_os_str().to_string_lossy().to_ascii_lowercase();
        if first == "hooks" {
            return true;
        }
        if (first == "config" || first == "config.lock") && access == Access::Write {
            return true;
        }
        return false;
    }
    false
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
/// 3. harness 进程（非豁免工具）触碰 `.git/**` 分面（需求 §3.1，拍板记录 12）：
///    注入面（hooks/**、config 写）→ 按 git_dir_action（默认 Block）；
///    工作流面（objects/refs/HEAD/锁文件等本职读写）→ Allow（取证由引擎
///    按监控根首见补 Audit）；
/// 4. 敏感文件命中 → Audit（放行不阻断，供取证与评分联动）；
/// 5. 默认 Allow。
///
/// 说明：规则 3 的分面依据——实机证实 harness（如 ZCode）内置 git 库在
/// 进程内直接读写 .git，"harness 不直写 .git、写走 git 工具豁免分支"的
/// 原假设不成立（拍板记录 12）；工作流面的窃取风险与"读工作区源码"同
/// 层级，由网络层阈值 + 导出命令封堵 + 归档产物三道兜底（需求 §3.1）。
pub fn judge_perm_sync(
    rules: &RulesSnapshot,
    id: &Identity,
    path: &Path,
    access: Access,
) -> Verdict {
    // 0. 用户白名单短路
    if rules.is_path_whitelisted(path) {
        return verdict(
            "whitelist",
            Action::Allow,
            format!("路径在用户白名单：{}", path.display()),
        );
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

    // 3. .git/** 分面（需求 §3.1：注入面阻断；工作流面放行，拍板记录 12）
    if under_git_dir(path) {
        if is_git_injection_touch(path, access) {
            let summary = format!(
                "[{}] {} 触碰 .git 注入面：{}",
                root.0,
                id.exe.display(),
                path.display()
            );
            return match rules.git_dir_action {
                FileAction::Block => verdict("git-dir", Action::Block, summary),
                FileAction::Audit => verdict("git-dir", Action::Audit, summary),
            };
        }
        return verdict(
            "git-dir-workflow",
            Action::Allow,
            format!(
                "[{}] {} 访问 .git 工作流面：{}",
                root.0,
                id.exe.display(),
                path.display()
            ),
        );
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
    fn 快路径_harness_触碰_git_注入面阻断() {
        let rules = snapshot();
        let id = harness_identity("C:/x/node.exe");
        // hooks 读写皆注入面
        for (p, a) in [
            ("D:/repo/.git/hooks/pre-commit", Access::Read),
            ("D:/repo/.git/hooks/pre-commit", Access::Write),
            ("D:/repo/.git/config", Access::Write),
            ("D:/repo/.git/config.lock", Access::Write),
        ] {
            let v = judge_perm_sync(&rules, &id, Path::new(p), a);
            assert_eq!(v.rule_id.0, "git-dir", "{p}");
            assert_eq!(v.action, Action::Block, "{p}");
        }
    }

    #[test]
    fn 快路径_harness_触碰_git_工作流面放行() {
        let rules = snapshot();
        let id = harness_identity("C:/x/node.exe");
        // config 读（status 必经）与 objects/HEAD/锁文件读写（commit 必经）
        // 均为工作流面（拍板记录 12：ZCode 内置 git 库进程内直写 .git）
        for (p, a) in [
            ("D:/repo/.git/config", Access::Read),
            (
                "D:/repo/.git/objects/1b/bdae00224f257a978f5c7ba86b123dc633642c",
                Access::Write,
            ),
            ("D:/repo/.git/HEAD.lock", Access::Write),
            ("D:/repo/.git/HEAD", Access::Read),
            ("D:/repo/.git/refs/heads/master", Access::Write),
            ("D:/repo/.git/index", Access::Write),
        ] {
            let v = judge_perm_sync(&rules, &id, Path::new(p), a);
            assert_eq!(v.rule_id.0, "git-dir-workflow", "{p}");
            assert_eq!(v.action, Action::Allow, "{p}");
        }
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
        let v = judge_perm_sync(
            &rules,
            &id,
            Path::new("D:/repo/.git/objects/ab/cd"),
            Access::Read,
        );
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
        for p in [
            "D:/repo/.env",
            "D:/repo/.env.production",
            "D:/repo/id_rsa",
            "D:/x/cert.pem",
        ] {
            let v = judge_perm_sync(&rules, &id, Path::new(p), Access::Read);
            assert_eq!(v.rule_id.0, "sensitive-read", "{p}");
            assert_eq!(v.action, Action::Audit);
        }
    }

    #[test]
    fn 快路径_白名单短路() {
        let cfg = RulesConfig {
            whitelist_paths: vec!["D:/safe/**".into()],
            ..Default::default()
        };
        let rules = RulesSnapshot::compile(&cfg).unwrap();
        let id = harness_identity("C:/x/node.exe");
        let v = judge_perm_sync(&rules, &id, Path::new("D:/safe/.git/config"), Access::Read);
        assert_eq!(v.rule_id.0, "whitelist");
    }

    #[test]
    fn 命令封堵_导出型命令命中() {
        let rules = snapshot();
        let hit = vec![
            vec![
                "C:/Program Files/Git/cmd/git.exe",
                "archive",
                "--format=zip",
                "HEAD",
            ],
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
        // 扩容后的通配条目：智谱大陆、cursor/trae 子域、LLM router
        assert!(rules.endpoint_allowed(Some("open.bigmodel.cn"), "1.2.3.4".parse().unwrap()));
        assert!(rules.endpoint_allowed(Some("api2.cursor.sh"), "1.2.3.4".parse().unwrap()));
        assert!(rules.endpoint_allowed(Some("api.trae.com.cn"), "1.2.3.4".parse().unwrap()));
        assert!(rules.endpoint_allowed(Some("api.siliconflow.cn"), "1.2.3.4".parse().unwrap()));
        // 通配不越界：根域本身与无关子域不得命中
        assert!(!rules.endpoint_allowed(Some("cursor.sh"), "1.2.3.4".parse().unwrap()));
        assert!(!rules.endpoint_allowed(Some("trae.com.cn.evil.com"), "1.2.3.4".parse().unwrap()));
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
        assert_eq!(
            rules.match_harness(Path::new("C:/Windows/system32/cmd.exe")),
            None
        );
    }

    /// 豁免编译期兜底（拍板记录 13 前置防线）：配置丢失 git 条目时，
    /// 快照仍持有内置 git 豁免——空豁免表不可能是合法运行态。
    #[test]
    fn 编译兜底_空豁免表注入内置_git_豁免() {
        // 模拟配置链路异常（缺段/写回丢失）
        let cfg = RulesConfig {
            tool_exempt: vec![],
            ..Default::default()
        };
        let rules = RulesSnapshot::compile(&cfg).unwrap();
        let mut id = harness_identity("C:/Program Files/Git/mingw64/bin/git.exe");
        id.tool_exempt = rules
            .match_tool_exempt(Path::new("C:/Program Files/Git/mingw64/bin/git.exe"))
            .map(String::from);
        assert_eq!(id.tool_exempt.as_deref(), Some("git"));
        let v = judge_perm_sync(
            &rules,
            &id,
            Path::new("D:/repo/.git/objects/ab/cd"),
            Access::Read,
        );
        assert_eq!(v.rule_id.0, "tool-exempt");
        assert_eq!(v.action, Action::Allow);
    }

    /// 用户自定义 git 条目存在时兜底不介入（以用户为准）
    #[test]
    fn 编译兜底_用户自定义条目优先() {
        let cfg = RulesConfig {
            tool_exempt: vec![ToolExemptConf {
                exe: "git".into(),
                allow_paths: vec![".git/objects/**".into()], // 用户收窄
            }],
            ..Default::default()
        };
        let rules = RulesSnapshot::compile(&cfg).unwrap();
        // 收窄生效：objects 内放行
        assert!(rules.tool_exempt_allows("git", Path::new("D:/repo/.git/objects/ab/cd")));
        // 收窄生效：objects 外（如 config）不再豁免
        assert!(!rules.tool_exempt_allows("git", Path::new("D:/repo/.git/config")));
    }

    /// git_dir_kill 默认 false（拍板记录 13：缺省不杀，处置交用户决定）
    #[test]
    fn 处置配置_git_dir_kill_缺省不杀() {
        let rules = snapshot();
        assert!(!rules.git_dir_kill);
        let cfg = RulesConfig {
            git_dir_kill: true,
            ..Default::default()
        };
        assert!(RulesSnapshot::compile(&cfg).unwrap().git_dir_kill);
    }
}
