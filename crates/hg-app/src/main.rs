//! HarnessGuard 服务入口（技术设计 §2：配置加载、平台选择、组装装配）。
//!
//! 骨架阶段：验证 workspace 装配与依赖方向。M1 接入真实管线：
//! 配置加载 → 平台事件源/Enforcer 构造 → hg-core 引擎 → store/web/notify 装配
//! → 健康监控（技术设计 §9）。

use hg_core::rules::{RulesConfig, RulesSnapshot};

fn main() -> anyhow::Result<()> {
    let cfg = RulesConfig::default();
    let snapshot = RulesSnapshot::compile(&cfg)?;

    println!("HarnessGuard v{}（骨架模式，监控引擎未装配）", env!("CARGO_PKG_VERSION"));
    println!(
        "  规则快照编译完成：harness 特征 {} 组 / 封堵命令 {} 条 / 敏感模式 {} 个",
        cfg.harness.len(),
        cfg.blocked_commands.len(),
        cfg.sensitive_patterns.len()
    );
    println!(
        "  .git 访问策略 = {:?}，上行阈值 = {} MB",
        cfg.git_dir_action, cfg.upload_threshold_mb
    );
    println!(
        "  平台适配：{}；{}；{}",
        hg_plat_win::describe(),
        hg_plat_linux::describe(),
        hg_plat_macos::describe()
    );
    println!("  {}；{}", hg_notify::describe(), hg_web::describe());
    let _ = snapshot; // M1：经 arc-swap 挂载为可热替换快照
    Ok(())
}
