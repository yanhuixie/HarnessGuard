//! Windows 通知会话桥（技术设计 §8.1）：
//! 服务在会话 0（或控制台管理员）→ 枚举活跃会话 → WTSQueryUserToken +
//! CreateProcessAsUser 拉起一次性 PowerShell 代理弹 Toast（-EncodedCommand 免引号地狱）。
//! 非 SYSTEM 上下文（控制台演示模式）WTSQueryUserToken 会失败 → 直接在本会话弹
//! （同一用户桌面）。兜底 msg.exe 弹窗。M4 服务化后走完整 WTS 路径。

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::RemoteDesktop::{
    WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSQueryUserToken, WTS_SESSION_INFOW,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, CREATE_DEFAULT_ERROR_MODE, CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};

pub struct WinNotifier {
    /// 通知失败计数（UI 状态披露：通知不可达≠保护失效，技术设计 §12）
    pub failures: std::sync::atomic::AtomicU64,
}

impl WinNotifier {
    pub fn new() -> Self {
        Self { failures: std::sync::atomic::AtomicU64::new(0) }
    }

    pub fn notify(&self, title: &str, body: &str) {
        if self.try_sessions(title, body) {
            return;
        }
        // 控制台/非 SYSTEM：当前会话直接弹（同一用户桌面）
        if spawn_common(None, title, body) {
            return;
        }
        let n = self.failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        tracing::error!("OS 通知投递失败（累计 {n} 次），UI 红色横幅兜底");
    }

    /// SYSTEM 下遍历活跃会话逐个投递；返回是否至少成功一次。
    fn try_sessions(&self, title: &str, body: &str) -> bool {
        unsafe {
            let mut buf: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
            let mut count = 0u32;
            if WTSEnumerateSessionsW(None, 0, 1, &mut buf, &mut count).is_err() {
                return false;
            }
            let mut any = false;
            let sessions = std::slice::from_raw_parts(buf, count as usize);
            for s in sessions {
                if s.State == WTSActive {
                    let mut token = HANDLE::default();
                    if WTSQueryUserToken(s.SessionId, &mut token).is_ok() {
                        any |= spawn_common(Some(token), title, body);
                        let _ = CloseHandle(token);
                    }
                }
            }
            WTSFreeMemory(buf as *mut core::ffi::c_void);
            any
        }
    }
}

impl Default for WinNotifier {
    fn default() -> Self {
        Self::new()
    }
}

fn spawn_common(token: Option<HANDLE>, title: &str, body: &str) -> bool {
    let ps = build_toast_command(title, body);
    let mut cmd: Vec<u16> = ps.encode_utf16().chain(std::iter::once(0)).collect();
    let desktop: Vec<u16> = "winsta0\\default\0".encode_utf16().collect();
    unsafe {
        let mut env: *mut core::ffi::c_void = std::ptr::null_mut();
        let have_env = token
            .map(|t| CreateEnvironmentBlock(&mut env, Some(t), false).is_ok())
            .unwrap_or(false);
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(desktop.as_ptr() as *mut _),
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        let app: Vec<u16> =
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\0"
                .encode_utf16()
                .collect();
        let r = CreateProcessAsUserW(
            token,
            PCWSTR(app.as_ptr()),
            Some(PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_DEFAULT_ERROR_MODE,
            if have_env { Some(env as *const core::ffi::c_void) } else { None },
            PCWSTR::null(),
            &si,
            &mut pi,
        );
        if have_env {
            let _ = DestroyEnvironmentBlock(env);
        }
        if r.is_ok() {
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
            true
        } else {
            msg_fallback(token, title, body)
        }
    }
}

fn msg_fallback(token: Option<HANDLE>, title: &str, body: &str) -> bool {
    let text = format!("msg * /time 30 [HarnessGuard] {title} {body}");
    let mut cmd: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        let app: Vec<u16> = "C:\\Windows\\System32\\msg.exe\0".encode_utf16().collect();
        let r = CreateProcessAsUserW(
            token,
            PCWSTR(app.as_ptr()),
            Some(PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW | CREATE_DEFAULT_ERROR_MODE,
            None,
            PCWSTR::null(),
            &si,
            &mut pi,
        );
        if r.is_ok() {
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
        }
        r.is_ok()
    }
}

/// Toast 一次性代理命令（-EncodedCommand：UTF-16LE base64，规避引号转义）。
fn build_toast_command(title: &str, body: &str) -> String {
    let xml = format!(
        "<toast><visual><binding template=\"ToastText02\"><text id=\"1\">{title}</text><text id=\"2\">{body}</text></binding></visual></toast>"
    );
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue';\
         [Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]|Out-Null;\
         $x=[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]::New();\
         $x.LoadXml('{xml}');\
         [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}}\\WindowsPowerShell\\v1.0\\powershell.exe').Show([Windows.UI.Notifications.ToastNotification]::New($x))"
    );
    let b64 = base64_utf16le(&script);
    format!("-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {b64}")
}

fn base64_utf16le(s: &str) -> String {
    // 简易 base64（无第三方依赖）
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = s.encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}
