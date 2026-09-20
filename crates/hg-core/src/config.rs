//! 配置文件（TOML，技术设计 §6）加载/保存/默认值，及到 [`RulesConfig`] 的转换。
//! 双通道：文件 + Web UI 均落盘为同一份（仅管理员可写由安装器/服务负责）。

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::rules::{FileAction, HarnessFeature, RulesConfig, ToolExemptConf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileConfig {
    #[serde(default)]
    pub network: NetworkConf,
    #[serde(default)]
    pub endpoints: EndpointsConf,
    #[serde(default)]
    pub files: FilesConf,
    #[serde(default)]
    pub commands: CommandsConf,
    #[serde(default)]
    pub processes: ProcessesConf,
    #[serde(default)]
    pub tool_exempt: Vec<ToolExemptConf>,
    #[serde(default)]
    pub storage: StorageConf,
    #[serde(default)]
    pub web: WebConf,
    #[serde(default)]
    pub file_audit: FileAuditConf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConf {
    pub upload_threshold_mb: u64,
    pub sensitive_escalation_divisor: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointsConf {
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesConf {
    pub git_dir_action: String,
    /// git-dir 注入面 Block 命中时是否杀进程（拍板记录 13，缺省 false）
    #[serde(default)]
    pub git_dir_kill: bool,
    pub archive_action: String,
    pub sensitive_patterns: Vec<String>,
    pub archive_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandsConf {
    pub blocked: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessesConf {
    pub harness: Vec<HarnessFeature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConf {
    pub retention_days: u32,
    pub max_disk_mb: u32,
    #[serde(default = "default_db_path")]
    pub db_path: String,
}

fn default_db_path() -> String {
    "harnessguard.db".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConf {
    pub bind: String,
}

/// Security 4663 文件审计通道（场景 A opt-in 备选；技术设计拍板记录 11）。
/// 启用端需系统侧配置（auditpol + SACL，经 enable-file-audit 子命令管理），
/// 本配置仅控制消费端。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileAuditConf {
    /// 消费开关（默认关：Security 通道订阅与系统审计策略均不启动）
    #[serde(default)]
    pub enabled: bool,
    /// 监听路径前缀（工作区绝对路径，如 D:/repo/.git；NT 路径归一后按
    /// 路径分量边界匹配，详见 hg-plat-win sec_audit 模块）
    #[serde(default)]
    pub watch_paths: Vec<String>,
}

impl Default for NetworkConf {
    fn default() -> Self {
        Self { upload_threshold_mb: 100, sensitive_escalation_divisor: 10 }
    }
}
impl Default for EndpointsConf {
    fn default() -> Self {
        Self { allow: crate::rules::default_endpoints_allow() }
    }
}
impl Default for FilesConf {
    fn default() -> Self {
        Self {
            git_dir_action: "block".into(),
            git_dir_kill: false,
            archive_action: "block".into(),
            sensitive_patterns: vec![
                ".env".into(), ".env.*".into(), "*_rsa".into(), "*.pem".into(), "*credentials*".into(),
            ],
            archive_patterns: vec![
                "*.zip".into(), "*.tar".into(), "*.tar.gz".into(), "*.tgz".into(), "*.7z".into(), "*.gz".into(), "*.zst".into(),
            ],
        }
    }
}
impl Default for CommandsConf {
    fn default() -> Self {
        Self {
            blocked: vec![
                "git archive*".into(),
                "git bundle*".into(),
                "git format-patch*".into(),
                "tar *".into(),
                "zip *".into(),
                "7z *".into(),
                "gzip *".into(),
                "zstd *".into(),
            ],
        }
    }
}
impl Default for ProcessesConf {
    fn default() -> Self {
        Self { harness: crate::rules::default_harness_features() }
    }
}
impl Default for StorageConf {
    fn default() -> Self {
        Self { retention_days: 30, max_disk_mb: 500, db_path: default_db_path() }
    }
}
impl Default for WebConf {
    fn default() -> Self {
        Self { bind: "127.0.0.1:8377".into() }
    }
}
impl Default for FileConfig {
    fn default() -> Self {
        Self {
            network: Default::default(),
            endpoints: Default::default(),
            files: Default::default(),
            commands: Default::default(),
            processes: Default::default(),
            tool_exempt: vec![ToolExemptConf {
                exe: "git".into(),
                allow_paths: vec![".git/**".into()],
            }],
            storage: Default::default(),
            web: Default::default(),
            file_audit: Default::default(),
        }
    }
}

impl FileConfig {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置失败：{}", path.display()))?;
        toml::from_str(&text).with_context(|| "解析 TOML 失败")
    }

    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        let text = self.render_toml(path);
        std::fs::write(path, text).with_context(|| format!("写配置失败：{}", path.display()))?;
        Ok(())
    }

    /// 内置默认配置文本（首次启动落盘，技术设计 §6）。
    /// 带中英双语注释的模板，值与 [`FileConfig::default`] 一致
    /// （单测 `默认模板与默认值一致` 防漂移）。
    pub fn default_toml() -> String {
        DEFAULT_CONFIG_TEMPLATE.to_string()
    }

    /// 渲染写盘文本：目标文件已存在且可解析时做注释保留式合并
    /// （toml_edit 逐键覆盖值，保留原注释与键序）；否则整体序列化。
    fn render_toml(&self, path: &std::path::Path) -> String {
        let plain = || toml::to_string_pretty(self).unwrap_or_default();
        let Ok(existing) = std::fs::read_to_string(path) else {
            return plain();
        };
        let mut doc: toml_edit::DocumentMut = match existing.parse() {
            Ok(d) => d,
            Err(_) => return plain(),
        };
        let Ok(new_text) = toml::to_string(self) else {
            return plain();
        };
        let Ok(new_doc) = new_text.parse::<toml_edit::DocumentMut>() else {
            return plain();
        };
        merge_tables(doc.as_table_mut(), new_doc.as_table());
        doc.to_string()
    }

    /// 配置 + DB 路径白名单 → 规则引擎配置（快照编译输入）。
    /// 非法动作字符串按默认 Block 处理并告警（宁严勿漏）。
    pub fn to_rules_config(&self, whitelist_paths: Vec<String>) -> RulesConfig {
        let parse_action = |s: &str| match s {
            "audit" => FileAction::Audit,
            "block" | _ => {
                if s != "block" {
                    tracing::warn!("非法动作字符串 {s:?}，按 block 处理");
                }
                FileAction::Block
            }
        };
        RulesConfig {
            upload_threshold_mb: self.network.upload_threshold_mb,
            sensitive_escalation_divisor: self.network.sensitive_escalation_divisor,
            endpoints_allow: self.endpoints.allow.clone(),
            git_dir_action: parse_action(&self.files.git_dir_action),
            git_dir_kill: self.files.git_dir_kill,
            archive_action: parse_action(&self.files.archive_action),
            sensitive_patterns: self.files.sensitive_patterns.clone(),
            archive_patterns: self.files.archive_patterns.clone(),
            blocked_commands: self.commands.blocked.clone(),
            harness: self.processes.harness.clone(),
            tool_exempt: self.tool_exempt.clone(),
            whitelist_paths,
        }
    }
}

/// 把 src 表的值逐键覆盖进 dst（保留 dst 的注释与键序）：
/// - 两边同为普通子表 → 递归合并；
/// - 两边同为表数组且条目数一致 → 逐条递归（保留每条目的注释）；
/// - 其余（标量/数组/表数组增删）→ 整体替换，替换前把旧项的行前注释
///   带给新项；dst 中 src 没有的键保留（用户手写的额外键不丢）。
fn merge_tables(dst: &mut toml_edit::Table, src: &toml_edit::Table) {
    for (key, new_item) in src.iter() {
        let recurse_table = matches!(
            (dst.get(key), new_item),
            (Some(toml_edit::Item::Table(_)), toml_edit::Item::Table(st)) if !st.is_dotted()
        );
        let recurse_aot = matches!(
            (dst.get(key), new_item),
            (Some(toml_edit::Item::ArrayOfTables(d)), toml_edit::Item::ArrayOfTables(s))
                if d.len() == s.len()
        );
        if recurse_table {
            if let (Some(toml_edit::Item::Table(dt)), toml_edit::Item::Table(st)) =
                (dst.get_mut(key), new_item)
            {
                merge_tables(dt, st);
            }
        } else if recurse_aot {
            if let (Some(toml_edit::Item::ArrayOfTables(dt)), toml_edit::Item::ArrayOfTables(st)) =
                (dst.get_mut(key), new_item)
            {
                for (d, s) in dt.iter_mut().zip(st.iter()) {
                    merge_tables(d, s);
                }
            }
        } else {
            let mut item = new_item.clone();
            if let Some(old) = dst.get(key) {
                copy_decor(&mut item, old);
            }
            // 行前注释挂在 Key 的 leaf_decor 上；insert() 会自动格式化并清掉
            // 旧 Key 装饰，须复制后经 insert_formatted 写回
            let mut new_key = toml_edit::Key::new(key);
            if let Some((old_key, _)) = dst.get_key_value(key) {
                *new_key.leaf_decor_mut() = old_key.leaf_decor().clone();
                *new_key.dotted_decor_mut() = old_key.dotted_decor().clone();
            }
            dst.insert_formatted(&new_key, item);
        }
    }
}

/// 整项替换时把旧项的注释装饰（行前注释/空行）带给新项，否则替换即丢注释。
fn copy_decor(new_item: &mut toml_edit::Item, old: &toml_edit::Item) {
    match (new_item, old) {
        (toml_edit::Item::Value(n), toml_edit::Item::Value(o)) => {
            *n.decor_mut() = o.decor().clone()
        }
        (toml_edit::Item::Table(n), toml_edit::Item::Table(o)) => {
            *n.decor_mut() = o.decor().clone()
        }
        _ => {}
    }
}

/// 内置默认配置模板（首次启动落盘）。中英双语注释面向最终用户；
/// 值必须与 [`FileConfig::default`] 一致，由单测防漂移。
const DEFAULT_CONFIG_TEMPLATE: &str = r##"# =====================================================================
# HarnessGuard 配置文件 / HarnessGuard configuration file
# 修改通道（双通道，同一份配置）/ edit channels (two channels, one file):
#   1. 直接编辑本文件：重启服务后生效 / edit directly: applies on restart
#   2. Web UI 设置页：保存即热生效 / Web UI settings: hot-reloaded on save
# =====================================================================

[network]
# 外传阈值（MB）：同一 harness 监控树对同一目标 IP 的累计上行字节超过
# 该值即判定为打包外传并阻断。
# Upload threshold (MB): cumulative upstream bytes from one harness tree to
# one destination IP beyond this is judged exfiltration and blocked.
upload_threshold_mb = 100
# 敏感降档系数：监控树读过敏感文件（files.sensitive_patterns）后，
# 上述阈值降为 1/N。
# Sensitive escalation divisor: once the tree has read sensitive files
# (files.sensitive_patterns), the threshold above shrinks to 1/N.
sensitive_escalation_divisor = 10

[endpoints]
# 端点白名单（域名 glob，支持 *）：发往这些端点的上行不计入外传阈值
# ——各 harness 的官方模型 API 与常见 LLM router（国内外端点均已覆盖）。
# 自建/私有模型网关请按此格式追加。
# Endpoint allowlist (domain globs, * supported): upstream traffic to these
# endpoints is exempt from the threshold — official model APIs of the
# monitored harnesses plus common LLM routers (mainland & overseas).
# Append self-hosted/private model gateways here.
allow = [
    # Claude Code
    "api.anthropic.com",
    # codex：API key 模式 / ChatGPT 登录模式（后端与授权）
    # codex: API-key mode / ChatGPT-login mode (backend & auth)
    "api.openai.com",
    "chatgpt.com",
    "auth.openai.com",
    # GitHub Copilot / Gemini
    "*.github.com",
    "*.googleapis.com",
    # zcode / autoclaw（智谱）：海外 / 大陆
    # zcode / autoclaw (Z.ai): overseas / mainland
    "api.z.ai",
    "open.bigmodel.cn",
    # cursor（官方企业网络文档）
    # cursor (official enterprise network docs)
    "*.cursor.sh",
    # codebuddy / workbuddy（腾讯）：大陆 / 国际
    # codebuddy / workbuddy (Tencent): mainland / international
    "copilot.tencent.com",
    "*.codebuddy.cn",
    "*.codebuddy.ai",
    # qoder（阿里）：IDE 网关；订阅模型 API 国内 / 国际
    # qoder (Alibaba): IDE gateway; coding-plan model API cn / intl
    "*.qoder.sh",
    "coding.dashscope.aliyuncs.com",
    "coding-intl.dashscope.aliyuncs.com",
    # trae（字节）：大陆 / 国际
    # trae (ByteDance): mainland / international
    "*.trae.com.cn",
    "*.trae.ai",
    "*.traeapi.us",
    # cline
    "api.cline.bot",
    # opencode：Zen 网关 / 模型目录
    # opencode: Zen gateway / model catalog
    "opencode.ai",
    "models.dev",
    # kilo code
    "api.kilo.ai",
    # 常见 LLM router / common LLM routers
    "openrouter.ai",
    "api.siliconflow.cn",
    "api.siliconflow.com",
]

[files]
# harness 进程触碰 .git 注入面（hooks/** 读写、config 写）的动作：
# block=阻断 | audit=仅告警。.git 其余内容（objects/refs/HEAD/锁文件等
# git 本职读写面）放行，仅按监控根首见记录取证线索。
# Action for harness processes touching the .git injection surface
# (hooks/** any access, config writes): block | audit. The rest of .git
# (objects/refs/HEAD/lock files - the normal git workflow surface) is
# allowed, with one first-seen forensic record per monitored root.
git_dir_action = "block"
# 上述注入面命中 block 判定后是否升级杀进程：false=只判定+通知（推荐，
# 打包封堵与网络阈值两重兜底仍在）；true=杀掉触碰进程。
# Whether a block verdict on the injection surface also kills the
# offending process: false = verdict + notification only (recommended;
# archive blocking and the network threshold still backstop it);
# true = kill the touching process.
git_dir_kill = false
# harness 进程创建打包文件（命中 archive_patterns）的动作：block | audit。
# Action for harness processes creating archives (matching archive_patterns):
# block | audit.
archive_action = "block"
# 敏感文件模式（glob）：读取即告警，并触发网络阈值降档（见 network 节）。
# Sensitive file globs: reading triggers an alert and threshold
# de-escalation (see the network section).
sensitive_patterns = [".env", ".env.*", "*_rsa", "*.pem", "*credentials*"]
# 打包文件模式（glob）。
# Archive file globs.
archive_patterns = ["*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.7z", "*.gz", "*.zst"]

[commands]
# 封堵命令（命令行前缀模式）：harness 树内进程的命令行命中即被终止。
# Blocked command prefixes: a matching command line inside a harness tree
# gets its process terminated.
blocked = ["git archive*", "git bundle*", "git format-patch*", "tar *", "zip *", "7z *", "gzip *", "zstd *"]

# harness 特征库：exe 完整路径命中任一 glob 即成为监控根，其全部子进程
# 继承监控身份（glob 大小写不敏感）。要监控新工具，按此格式追加条目即可。
# Harness signatures: an exe whose full path matches any glob becomes a
# monitored root and all its children inherit it (case-insensitive).
# Append entries below to monitor additional tools.
[[processes.harness]]
name = "claude-code"
path_globs = ["**/claude*"]

[[processes.harness]]
name = "zcode"
path_globs = ["**/zcode*"]

[[processes.harness]]
name = "codex"
path_globs = ["**/codex*"]

[[processes.harness]]
name = "cursor"
path_globs = ["**/cursor*"]

[[processes.harness]]
name = "autoclaw"
path_globs = ["**/autoclaw*"]

[[processes.harness]]
name = "workbuddy"
path_globs = ["**/workbuddy*"]

[[processes.harness]]
name = "codebuddy"
path_globs = ["**/codebuddy*"]

[[processes.harness]]
name = "qoder"
path_globs = ["**/qoder*"]

[[processes.harness]]
name = "trae"
path_globs = ["**/trae*"]

[[processes.harness]]
name = "cline"
path_globs = ["**/cline*"]

[[processes.harness]]
name = "opencode"
path_globs = ["**/opencode*"]

[[processes.harness]]
name = "kilo-code"
path_globs = ["**/kilocode*"]

# 工具豁免（身份矩阵）：命中 exe 名的进程仅允许访问所列路径模式，
# 越界访问回落为普通 harness 进程规则处置。
# Tool exemptions (identity matrix): a process whose exe matches may only
# touch the listed path patterns; anything beyond falls back to the plain
# harness rules.
[[tool_exempt]]
exe = "git"
allow_paths = [".git/**"]

[storage]
# 事件与判定记录的留存天数（每日清理任务删除更旧记录）。
# Retention days for events/verdicts (a daily cleanup deletes older rows).
retention_days = 30
# 数据库体积上限（MB）。预留项：当前版本清理仅按 retention_days 执行。
# Database size cap (MB). Reserved: cleanup currently honors retention_days only.
max_disk_mb = 500
# SQLite 数据库文件路径（相对路径锚定服务安装目录）。
# SQLite database path (relative paths anchor to the install directory).
db_path = "harnessguard.db"

[web]
# Web UI 监听地址：仅本机回环 + 启动随机 token 鉴权，请勿改为对外地址。
# Web UI bind: loopback-only, guarded by a random startup token; do not
# expose it externally.
bind = "127.0.0.1:8377"

[file_audit]
# Security 4663 文件审计通道（.git 读取检测的备选路径）。启用前需管理员
# 执行 `harnessguard enable-file-audit <目录>` 配置系统审计策略。
# Security 4663 file-audit channel (fallback for .git-read detection).
# Requires `harnessguard enable-file-audit <dir>` (admin) before enabling.
enabled = false
# 审计监听的绝对路径前缀（如 D:/repo/.git）。
# Absolute path prefixes to watch (e.g. D:/repo/.git).
watch_paths = []
"##;

#[cfg(test)]
mod tests {
    use super::*;

    /// 模板与 Default 的值必须一致（防止模板与结构体默认漂移）。
    #[test]
    fn 默认模板与默认值一致() {
        let parsed: FileConfig = toml::from_str(&FileConfig::default_toml())
            .expect("默认模板必须是合法 TOML");
        let a = toml::to_string_pretty(&parsed).unwrap();
        let b = toml::to_string_pretty(&FileConfig::default()).unwrap();
        assert_eq!(a, b, "默认模板与 FileConfig::default 值不一致");
    }

    /// save 必须保留文件里的注释（用户文档价值所在），且值正确写回。
    #[test]
    fn 保存保留注释且值正确() {
        let dir = std::env::temp_dir().join(format!("hg-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, FileConfig::default_toml()).unwrap();

        let mut cfg = FileConfig::load(&path).unwrap();
        cfg.network.upload_threshold_mb = 50;
        cfg.storage.retention_days = 7;
        let allow_len_before = cfg.endpoints.allow.len();
        cfg.endpoints.allow.pop();
        cfg.processes.harness[0].path_globs = vec!["**/my-claude*".into()];
        cfg.save(&path).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        // 行前注释保留（中文与英文各抽一条）
        assert!(text.contains("外传阈值（MB）"), "中文注释丢失");
        assert!(text.contains("Upload threshold (MB)"), "英文注释丢失");
        assert!(text.contains("harness 特征库"), "表数组区注释丢失");
        assert!(text.contains("Endpoint allowlist"), "端点区注释丢失");

        let re = FileConfig::load(&path).unwrap();
        assert_eq!(re.network.upload_threshold_mb, 50);
        assert_eq!(re.storage.retention_days, 7);
        assert_eq!(re.endpoints.allow.len(), allow_len_before - 1);
        assert_eq!(re.processes.harness.len(), 12);
        assert_eq!(re.processes.harness[0].path_globs, vec!["**/my-claude*"]);
        // 未改动项保持默认
        assert_eq!(re.web.bind, "127.0.0.1:8377");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// 文件不存在或损坏时回落到整体序列化（不 panic、能写盘）。
    #[test]
    fn 无既有文件时整体序列化() {
        let dir = std::env::temp_dir().join(format!("hg-cfg-new-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        FileConfig::default().save(&path).unwrap();
        let re = FileConfig::load(&path).unwrap();
        assert_eq!(re.network.upload_threshold_mb, 100);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 旧版配置兼容（拍板记录 13 回归）：缺 git_dir_kill 字段 → 默认不杀；
    /// 缺 [[tool_exempt]] 段（实测教训：文件与运行时豁免可能分裂）→
    /// to_rules_config + compile 后 git 豁免仍由编译期兜底保住。
    #[test]
    fn 旧版配置_缺新字段与豁免段_兜底生效() {
        // 完整旧版字段集（新字段 git_dir_kill 与 [[tool_exempt]] 段缺失）
        let legacy = r#"
[network]
upload_threshold_mb = 50
sensitive_escalation_divisor = 10

[files]
git_dir_action = "block"
archive_action = "block"
sensitive_patterns = [".env"]
archive_patterns = ["*.zip"]

[commands]
blocked = ["tar *"]

[[processes.harness]]
name = "zcode"
path_globs = ["**/zcode*"]

[storage]
retention_days = 30
max_disk_mb = 500

[web]
bind = "127.0.0.1:8377"
"#;
        let cfg: FileConfig = toml::from_str(legacy).expect("旧版配置必须可解析");
        assert!(!cfg.files.git_dir_kill, "缺省不得杀进程");
        assert!(cfg.tool_exempt.is_empty(), "本用例模拟豁免段丢失");
        let rules = crate::rules::RulesSnapshot::compile(&cfg.to_rules_config(vec![]))
            .expect("编译必须成功");
        assert!(!rules.git_dir_kill);
        // 编译期兜底：git 豁免在快照中存活（任意路径的 git.exe）
        assert_eq!(
            rules.match_tool_exempt(std::path::Path::new("C:/Program Files/Git/mingw64/bin/git.exe")),
            Some("git")
        );
    }
}
