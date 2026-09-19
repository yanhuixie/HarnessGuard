//! HarnessGuard 核心引擎（技术设计 §3）。
//!
//! 纯逻辑 crate：无平台 API、无 IO，可全量单测（技术设计 §1.2 原则 2）。

pub mod config;
pub mod conn_registry;
pub mod engine;
pub mod health;
pub mod proc_table;
pub mod rules;

pub use conn_registry::{ConnEntry, ConnRegistry, ConnSummary, TxSample};
pub use proc_table::ProcTable;
pub use config::FileConfig;
pub use engine::{Engine, EngineOutput};
pub use health::{EngineStats, SourceStats};
pub use rules::{judge_perm_sync, FileAction, HarnessFeature, RulesConfig, RulesSnapshot, ToolExemptConf};
