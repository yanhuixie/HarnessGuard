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

/// 安装服务（需管理员）：LocalSystem 自启动 + `service` 启动参数 + 三级失败重启。
/// 已于 2026-09-20 实机验证（M4 第一批复验报告）；升级重装前先 uninstall。
pub fn install() -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let exe_dir = exe.parent().map(|d| d.to_path_buf());
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
        executable_path: exe,
        // SCM 以 main 参数传入（非 service_main 参数）——对应 `service` 子命令
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None, // LocalSystem（特权服务，需求 §6.1）
        account_password: None,
    };
    let service = manager.create_service(&info, ServiceAccess::ALL_ACCESS)?;
    service.set_description("ETW 事件源 + 规则引擎 + 处置（需求 §6.1 单特权服务）")?;

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
    // 自保护 ACL（§8.2 / 待修 11）：安装时对已存在的三件套应用保护 DACL；
    // 安装后首次启动新建的文件（config/db/token 生成时机不同）由服务启动
    // 自检覆盖（run_server 服务模式）
    if let Some(dir) = exe_dir {
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
    println!("服务已安装（LocalSystem 自启动，失败三级重启）");
    println!("启动：sc start {SERVICE_NAME}（需管理员）");
    Ok(())
}

/// 卸载服务（需管理员，先停后删）。已于 2026-09-20 实机验证（复验报告）。
pub fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service =
        manager.open_service(SERVICE_NAME, ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?;
    // 运行中先停（运行中删除只标记，不移除）；轮询至 Stopped——原固定 sleep 2s
    // 在停机序列超过 2s 时仍会撞上"只标记"路径（M4 待修清单 9）
    let status = service.query_status()?;
    if status.current_state != ServiceState::Stopped {
        service.stop()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            if std::time::Instant::now() > deadline {
                anyhow::bail!("等待服务停止超时（30s），请手动停止后重试卸载");
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    service.delete()?;
    println!("服务已卸载");
    Ok(())
}
