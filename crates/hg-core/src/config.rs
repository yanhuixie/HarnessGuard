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

impl Default for NetworkConf {
    fn default() -> Self {
        Self { upload_threshold_mb: 100, sensitive_escalation_divisor: 10 }
    }
}
impl Default for EndpointsConf {
    fn default() -> Self {
        Self {
            allow: vec![
                "api.anthropic.com".into(),
                "api.openai.com".into(),
                "*.github.com".into(),
                "*.googleapis.com".into(),
            ],
        }
    }
}
impl Default for FilesConf {
    fn default() -> Self {
        Self {
            git_dir_action: "block".into(),
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
        Self {
            harness: vec![HarnessFeature {
                name: "claude-code".into(),
                path_globs: vec!["**/node_modules/.bin/claude*".into(), "**/claude*".into()],
            }],
        }
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
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text).with_context(|| format!("写配置失败：{}", path.display()))?;
        Ok(())
    }

    /// 内置默认配置文本（首次启动落盘，技术设计 §6）。
    pub fn default_toml() -> String {
        toml::to_string_pretty(&Self::default()).unwrap_or_default()
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
