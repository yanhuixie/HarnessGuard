//! Windows 平台适配（技术设计 §5.1，选型按 M0 spike 报告校准）。
//!
//! 模块：
//! - [`etw_source`]：ETW 事件源（进程/文件/网络 kernel flags + Dns-Client GUID）
//! - [`enforcer`]：杀进程 / 断连接 / 临时封 IP
//! - [`notify`]：OS 通知会话桥（WTS + CreateProcessAsUser 一次性 Toast 代理）
//! - [`runkey`]：注册表 RunKey/RunOnce 持久化轮询（M1 范围）
//! - [`bootstrap`]：启动补扫描（Toolhelp32 快照）
//! - [`ntpath`]：NT 设备路径转盘符路径
//! - [`peb`]：PEB 命令行读取（内核 ETW 无命令行的降级链）
//! - [`lru`]：FileObject 缓存的 O(1) LRU 封顶（M4 场景 A 缓解）
//! - [`probe`]：unknown Create 事件的同对象句柄探测补名（M4 场景 A 缓解）
//! - [`estats`]：GetPerTcpConnectionEStats 轮询补连接字节计数（M4 场景 C 补充路径）
//! - [`wfp`]：用户态 WFP 临时封禁（M4 偏差归位，netsh 为降级兜底）
//! - [`sec_audit`]：Security 通道 4663 文件审计消费（场景 A opt-in 备选通道，M4 第二批）
//! - [`audit_setup`]：上述通道的系统侧启用/停用（auditpol + SACL，opt-in）
//! - [`acl`]：自保护 DACL（§8.2：配置/库/token 仅 SYSTEM/Administrators）

pub mod acl;
pub mod audit_setup;
pub mod bootstrap;
pub mod enforcer;
pub mod estats;
pub mod etw_source;
pub mod lru;
pub mod ntpath;
pub mod notify;
pub mod peb;
pub mod probe;
pub mod runkey;
pub mod sec_audit;
pub mod wfp;

pub use enforcer::WinEnforcer;
pub use etw_source::{EtwInner, EtwSource, SourceStats};
pub use notify::WinNotifier;

pub fn describe() -> &'static str {
    "hg-plat-win：ETW 事件源 + 杀进程/断连接/封 IP 处置（M1）"
}

/// 当前进程令牌是否提权（TokenElevation；安装器前置检查用，M4 第二批）。
pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = HANDLE(std::ptr::null_mut());
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elev = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        let r = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        );
        let _ = CloseHandle(token);
        r.is_ok() && elev.TokenIsElevated != 0
    }
}

/// 停机序列用：显式回收本服务的三个 ETW 会话（强杀进程不会自动停会话，
/// 残留会话导致二次启动 0 事件——M1 实测教训；技术设计 §9.3）。
pub fn stop_etw_sessions() {
    for s in ["HarnessGuard", "HarnessGuardDns", "HarnessGuardSched"] {
        let _ = ferrisetw::trace::stop_trace_by_name(s);
    }
}
