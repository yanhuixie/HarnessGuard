//! windows-service 服务宿主（技术设计 §2/§5.1：单特权系统服务 + 恢复策略；
//! M1 偏差表归位：控制台管理员模式 → SCM 宿主）。
//!
//! 实机状态：install/uninstall/启停/恢复策略/停机序列已于 2026-09-20 管理员
//! 实机验证全项通过（M4 第一批复验报告）；后续改动按需复验。
//! 服务模式日志：滚动文件（exe 目录 logs/，main 在 dispatch 前初始化——
//! M4 第二批 P1-8，Session 0 的 stderr 已丢弃）。
//!
//! 恢复策略：create_service 不覆盖 failure actions，安装时经 `sc.exe failure`
//! 配置三级重启（5s×3，等效 SCM Recovery 页）；binPath 由 launch_arguments
//! 自动拼装为 `"...\harnessguard.exe" service`。

use anyhow::Context;
use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub const SERVICE_NAME: &str = "HarnessGuard";

/// SCM 入口（binPath 形如 `"...\harnessguard.exe" service`）。
pub fn dispatch() -> anyhow::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| anyhow::anyhow!("SCM 调度启动失败：{e}"))
}

/// SCM 调度回调签名（裸入口，不接参——配置路径走服务工作目录/绝对约定）。
extern "system" fn ffi_service_main(_argc: u32, _argv: *mut *mut u16) {
    service_main();
}

fn service_main() {
    // SCM 服务默认 CWD 为 %WinDir%\System32——统一切到 exe 目录，使
    // config.toml / harnessguard.db 等相对路径锚定安装目录（评审修正：
    // 否则首次服务启动会在 System32 下建配置与库文件）
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())) {
        if let Err(e) = std::env::set_current_dir(&dir) {
            tracing::error!("[服务] 切换工作目录到 {} 失败：{e}", dir.display());
        }
    }
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                let _ = stop_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = match service_control_handler::register(SERVICE_NAME, event_handler) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("服务控制处理器注册失败：{e}");
            return;
        }
    };
    let handle = Arc::new(status_handle);
    // 状态时序（M4 待修清单 8）：先报 START_PENDING（wait_hint 30s）——run_server
    // 装配（配置/ETW/SQLite/Web 监听）有耗时，直接报 RUNNING 时初始化若超
    // wait_hint 会被 SCM 判超时；装配完成回调再报 RUNNING
    report_state(&handle, ServiceState::StartPending, 0, Duration::from_secs(30));
    tracing::info!("[服务] HarnessGuard 服务主体启动（SCM 宿主）");

    let on_ready = {
        let handle = handle.clone();
        Some(Box::new(move || {
            report_state(&handle, ServiceState::Running, 0, Duration::ZERO)
        }) as Box<dyn FnOnce() + Send>)
    };
    if let Err(e) = crate::run_server(Some(stop_rx), on_ready) {
        tracing::error!("[服务] 服务主体退出（失败）：{e:#}");
        report_state(&handle, ServiceState::Stopped, 1, Duration::ZERO);
        return;
    }
    report_state(&handle, ServiceState::Stopped, 0, Duration::ZERO);
}

/// 状态上报（Interrogate 由 SCM 隐式支持，无需（也无位）声明）。
fn report_state(
    handle: &ServiceStatusHandle,
    state: ServiceState,
    code: u32,
    wait_hint: Duration,
) {
    let st = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint,
        process_id: None,
    };
    if let Err(e) = handle.set_service_status(st) {
        tracing::error!("服务状态上报失败（{state:?}）：{e}");
    }
}

/// 一键安装（需管理员提权；M4 验收：全新机器单命令到防护生效 ≤5 分钟人工步骤）。
///
/// 流程：① 前置检查（提权 / Web 端口未占用 / BFE 运行——WFP 封禁依赖）
/// ② 配置生成（exe 目录缺省 config.toml 落盘默认配置）③ 自保护 ACL（§8.2）
/// ④ 服务安装——已存在则版本化升级（停服 + binPath 更新，config/db 保留）
/// ⑤ 恢复策略 + 启动 + 等待 RUNNING + 生效提示。
pub fn install() -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let exe_dir = exe.parent().map(|d| d.to_path_buf());
    let version = env!("CARGO_PKG_VERSION");

    preflight(exe_dir.as_deref())?;

    // 配置生成：服务 CWD 锚定 exe 目录（service_main 切换），缺省则落默认配置
    if let Some(dir) = &exe_dir {
        let cfg_path = dir.join("config.toml");
        if !cfg_path.exists() {
            std::fs::write(&cfg_path, hg_core::FileConfig::default_toml())
                .with_context(|| format!("写入默认配置失败：{}", cfg_path.display()))?;
            println!("已生成默认配置：{}", cfg_path.display());
        }
    }

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
    )?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("HarnessGuard（AI harness 行为防护）"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart, // 开机自启
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.clone(),
        // SCM 以 main 参数传入（非 service_main 参数）——对应 `service` 子命令
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None, // LocalSystem（特权服务，需求 §6.1）
        account_password: None,
    };
    // 版本化升级：服务已存在（1073）时停服 + 更新 binPath，config/db 保留
    let service = match manager.create_service(&info, ServiceAccess::ALL_ACCESS) {
        Ok(s) => {
            println!("服务已创建（v{version}，LocalSystem 自启动）");
            s
        }
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1073) => {
            println!("检测到既有服务，执行升级（配置与数据库保留）……");
            let service = manager.open_service(
                SERVICE_NAME,
                ServiceAccess::ALL_ACCESS | ServiceAccess::QUERY_STATUS,
            )?;
            if let Ok(old) = service.query_config() {
                println!(
                    "  旧 binPath：{}\n  新 binPath：{}",
                    old.executable_path.display(),
                    exe.display()
                );
            }
            stop_and_wait(&service)?;
            service.change_config(&info)?;
            println!("服务配置已更新到 v{version}");
            service
        }
        Err(e) => return Err(e.into()),
    };
    service.set_description("ETW 事件源 + 规则引擎 + 处置（需求 §6.1 单特权服务）")?;

    // 自保护 ACL（§8.2 / 待修 11）：对已存在的三件套应用（含刚生成的 config；
    // 首次启动新建的 db/token 由服务启动自检覆盖）
    if let Some(dir) = &exe_dir {
        for name in ["config.toml", "harnessguard.db", "web-token.txt"] {
            let p = dir.join(name);
            if p.exists() {
                match hg_plat_win::acl::protect_file(&p) {
                    Ok(()) => println!("已应用保护 ACL（仅 SYSTEM/Administrators）：{}", p.display()),
                    Err(e) => println!("保护 ACL 应用失败（{}）：{e:#}", p.display()),
                }
            }
        }
    }

    // 恢复策略（需求 §6.3/技术设计 §8.2）：三级重启，计数 24h 重置
    let out = std::process::Command::new("sc")
        .args([
            "failure", SERVICE_NAME,
            "reset=", "86400",
            "actions=", "restart/5000/restart/5000/restart/5000",
        ])
        .output()?;
    if !out.status.success() {
        anyhow::bail!("恢复策略配置失败：{}", String::from_utf8_lossy(&out.stderr));
    }

    // 启动并等待 RUNNING（一键到"防护生效"）
    service.start(&[OsString::from("service")])?;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let st = service.query_status()?;
        if st.current_state == ServiceState::Running {
            println!("服务已启动（RUNNING）——防护生效");
            break;
        }
        if std::time::Instant::now() > deadline {
            println!("警告：15s 内未达 RUNNING（当前 {:?}），请查 logs/ 或 sc query {SERVICE_NAME}", st.current_state);
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    if let Some(dir) = &exe_dir {
        println!("Web UI：http://127.0.0.1:8377/（token 见 {}）", dir.join("web-token.txt").display());
        println!("日志：{}", dir.join("logs").display());
    }
    println!("可选：文件审计通道（场景 A 加强，系统侵入性 opt-in）：harnessguard enable-file-audit <工作区/.git>");
    Ok(())
}

/// 前置检查：提权 / 端口可绑 / BFE 运行。BFE 未运行仅告警（netsh 降级路径
/// 存在，WFP 为封禁主路径）；提权与端口冲突直接失败（无法继续）。
fn preflight(exe_dir: Option<&std::path::Path>) -> anyhow::Result<()> {
    // ① 提权：安装改 SCM 与 DACL，未提权必失败——显式报错优于半途失败
    if !is_elevated() {
        anyhow::bail!("未以管理员提权运行（服务安装/ACL/BFE 检查均需要）");
    }
    // ② 端口：读实际配置的 bind（缺省默认），试绑后立即释放
    let bind = exe_dir
        .map(|d| d.join("config.toml"))
        .filter(|p| p.exists())
        .and_then(|p| hg_core::FileConfig::load(&p).ok())
        .map(|c| c.web.bind)
        .unwrap_or_else(|| "127.0.0.1:8377".to_string());
    match std::net::TcpListener::bind(&bind) {
        Ok(_) => println!("前置检查：端口 {bind} 可绑定"),
        Err(e) => anyhow::bail!(
            "前置检查失败：Web 端口 {bind} 被占用（{e}）——排查：netstat -ano | findstr :{}，或修改 config.toml [web] bind",
            bind.rsplit(':').next().unwrap_or("8377")
        ),
    }
    // ③ BFE：WFP 封禁依赖（未运行仅告警——netsh 降级路径存在）
    let bfe = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .and_then(|m| m.open_service("BFE", ServiceAccess::QUERY_STATUS))
        .and_then(|s| s.query_status());
    match bfe {
        Ok(st) if st.current_state == ServiceState::Running => {
            println!("前置检查：BFE（Base Filtering Engine）运行中——WFP 封禁可用")
        }
        _ => println!("警告：BFE 服务未运行，WFP 封禁将降级为 netsh（可后续启动 bfe 服务）"),
    }
    Ok(())
}

/// 当前进程令牌是否提权（TokenElevation；UAC 分离令牌下未提权即 false）。
/// Win32 API 经 hg-plat-win 转发（hg-app 不直接依赖 windows crate——分层纪律）。
fn is_elevated() -> bool {
    hg_plat_win::is_elevated()
}

/// 停服并轮询至 Stopped（升级/卸载共用；运行中删除/改 binPath 只标记不生效）。
fn stop_and_wait(service: &windows_service::service::Service) -> anyhow::Result<()> {
    let status = service.query_status()?;
    if status.current_state == ServiceState::Stopped {
        return Ok(());
    }
    if status.current_state != ServiceState::StopPending {
        service.stop()?;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if service.query_status()?.current_state == ServiceState::Stopped {
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            anyhow::bail!("等待服务停止超时（30s），请手动停止后重试");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// 卸载服务（需管理员）：停服（轮询至 Stopped）→ 删除服务 → 残留清理。
/// 数据文件处置策略（如实披露）：web-token.txt 为凭据材料自动删除；
/// config.toml / harnessguard.db / logs 含审计数据，**保留**由用户决定；
/// [file_audit] 启用时的系统侧残留（auditpol + SACL）提示用 disable-file-audit
/// 回退——系统级策略不由卸载静默清除。
pub fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service =
        manager.open_service(SERVICE_NAME, ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?;
    // 运行中先停（运行中删除只标记，不移除）；轮询至 Stopped——原固定 sleep 2s
    // 在停机序列超过 2s 时仍会撞上"只标记"路径（M4 待修清单 9）
    stop_and_wait(&service)?;
    service.delete()?;
    println!("服务已卸载");

    // 残留清理（exe 目录侧）
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())) {
        let token = dir.join("web-token.txt");
        if token.exists() {
            match std::fs::remove_file(&token) {
                Ok(()) => println!("已删除凭据文件：{}", token.display()),
                Err(e) => println!("警告：web-token.txt 删除失败（{}）：{e}", token.display()),
            }
        }
        for name in ["config.toml", "harnessguard.db", "logs"] {
            let p = dir.join(name);
            if p.exists() {
                println!("保留（含配置/审计数据，可手工删除）：{}", p.display());
            }
        }
        // file_audit 系统侧残留提示（auditpol + SACL 不随卸载静默清除）
        let cfg = hg_core::FileConfig::load(&dir.join("config.toml")).ok();
        if cfg.is_some_and(|c| c.file_audit.enabled) {
            println!(
                "提醒：文件审计通道仍启用（auditpol + SACL 为系统级配置）——回退执行：harnessguard disable-file-audit <目录>"
            );
        }
    }
    Ok(())
}
