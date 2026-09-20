//! unknown Create 事件的同对象自查打开探测（M1 报告缺口 1 缓解第二步）。
//!
//! M1 实测：cmd/certutil/tar burst 打开的 Create 事件 ~99% 等不到 Name 事件，
//! pending 重试全部落空。缓解路径：按 ETW 事件携带的 FileObject（内核对象地址），
//! 在创建进程的句柄表中查找同一对象的句柄，复制进本进程后查询文件名。
//!
//! 与任务/M1 原文「拿句柄后 NtQueryInformationFile」的偏差：以
//! GetFinalPathNameByHandleW 等价落地（内部即 NtQueryInformationFile 查询链 +
//! 卷设备名解析），直接产出与现有 nt_to_win32 管线同构的盘符路径（已登记 M4 报告）。
//!
//! 代价与限流：NtQuerySystemInformation(SystemExtendedHandleInformation) 为全系统
//! 句柄快照（数 ms 级），仅对监控树内 unknown Create 触发，且最小间隔限流
//! （[`PROBE_MIN_INTERVAL`]）；探测失败的 FileObject 进失败表不再重试（burst 中
//! Create→Close 极快，句柄已关是主要 miss 原因，重试无意义）。
//!
//! 未运行时验证（需管理员实机），待 M4 复验。

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// 探测最小间隔（全系统句柄快照成本控制；burst 期间主动降频）
pub const PROBE_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_millis(150);

// ntdll 直调：NtQuerySystemInformation / NtDuplicateObject（文档化导出，
// windows crate 未包装 SystemExtendedHandleInformation 类，此处按 SDK 布局声明）
#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(
        class: u32,
        buf: *mut core::ffi::c_void,
        len: u32,
        ret_len: *mut u32,
    ) -> i32;
    fn NtDuplicateObject(
        src_proc: HANDLE,
        src_handle: HANDLE,
        dst_proc: HANDLE,
        out: *mut HANDLE,
        desired_access: u32,
        attributes: u32,
        options: u32,
    ) -> i32;
}

/// SystemExtendedHandleInformation（Winternl.h 未公开类号，系统工具广泛使用）
const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 0x40;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
/// x64 布局：Object(8) + UniqueProcessId(8) + HandleValue(8) + GrantedAccess(4)
/// + CreatorBackTraceIndex(2) + ObjectTypeIndex(2) + HandleAttributes(4) + Reserved(4)
const HANDLE_ENTRY_SIZE: usize = 40;
/// 按源句柄既有权限复制（第一批实证可命中的方式）
const DUPLICATE_SAME_ACCESS: u32 = 2;

/// 探测决策（纯函数，单测覆盖）：仅 Create/Read 事件（实机复验修正：cmd `type`
/// 等读路径的首个事件常是 Read（op=67）而非 Create，仅限 Create 会漏掉全部读
/// 场景——场景 A 的 .git 读取正是此路径）、该 FileObject 未探测失败过、
/// 距上次探测超过限流间隔，三者同时满足才发起。
pub(crate) fn probe_allowed(op_file: bool, already_failed: bool, interval_elapsed: bool) -> bool {
    op_file && !already_failed && interval_elapsed
}

/// 对 (pid, FileObject) 探测文件名：句柄表检索 → NtDuplicateObject →
/// GetFinalPathNameByHandleW。任一步失败返回 None（调用方登记失败表）。
pub(crate) fn probe_file_name(pid: u32, file_object: u64) -> Option<String> {
    unsafe {
        let hproc = OpenProcess(
            PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid,
        )
        .ok();
        if hproc.is_none() {
            tracing::debug!("[probe] OpenProcess({pid}) 失败（复验诊断）");
        }
        let hproc = hproc?;
        let r = probe_with_handle(hproc, pid, file_object);
        let _ = CloseHandle(hproc);
        r
    }
}

unsafe fn probe_with_handle(hproc: HANDLE, pid: u32, file_object: u64) -> Option<String> {
    // 1. 全系统句柄快照（grow-retry；上限 64MB 防御异常返回值）
    let mut buf: Vec<u8> = Vec::with_capacity(1 << 20);
    let mut need = 0u32;
    loop {
        let st = NtQuerySystemInformation(
            SYSTEM_EXTENDED_HANDLE_INFORMATION,
            buf.as_mut_ptr() as *mut _,
            buf.len() as u32,
            &mut need,
        );
        if st >= 0 {
            break;
        }
        if st != STATUS_INFO_LENGTH_MISMATCH
            || need == 0
            || (need as usize) > 64 * 1024 * 1024
            || buf.len() >= 64 * 1024 * 1024
        {
            tracing::debug!("[probe] 句柄快照失败 st={st:#x} need={need}（复验诊断）");
            return None;
        }
        let next = (need as usize).max(buf.len() * 2).min(64 * 1024 * 1024);
        buf.resize(next, 0);
    }
    if buf.len() < 16 {
        return None;
    }
    let n = *(buf.as_ptr() as *const usize);
    let base = 16; // NumberOfHandles(8) + Reserved(8)
                   // 条目数来自内核返回的缓冲首字段：异常值经 checked_mul/checked_add 防回绕
                   // 越过长度检查（M4 待修清单 1），溢出视同检索失败
    let Some(total) = n
        .checked_mul(HANDLE_ENTRY_SIZE)
        .and_then(|x| x.checked_add(base))
    else {
        return None;
    };
    if total > buf.len() {
        return None;
    }
    // 2. 找创建进程内同对象句柄（可能多条——任意一条即可）
    let mut found: Option<HANDLE> = None;
    for i in 0..n {
        let e = buf.as_ptr().add(base + i * HANDLE_ENTRY_SIZE);
        let obj = *(e as *const u64);
        let owner = *(e.add(8) as *const u64);
        if obj == file_object && owner as u32 == pid {
            found = Some(HANDLE(*(e.add(16) as *const u64) as *mut _));
            break;
        }
    }
    let Some(src) = found else {
        tracing::debug!("[probe] pid={pid} obj={file_object:x} 句柄表无匹配（复验诊断：句柄已关或对象地址不符）");
        return None;
    };
    // 3. 复制进本进程 → 4. 查询最终路径（含卷解析，等价 NtQueryInformationFile 链）。
    // 复制方式实机定案（M4 第二批复验）：DUPLICATE_SAME_ACCESS——跨进程显式请求
    // 源句柄掩码之外的权限会被拒（FILE_READ_ATTRIBUTES 显式请求实测
    // STATUS_ACCESS_DENIED=0xC0000022，源句柄 GrantedAccess 不含 0x80 时必败，
    // certutil 场景两轮 0 命中）；同权限复制保留源的读掩码
    // （GENERIC_READ 映射含 FILE_READ_ATTRIBUTES），GetFinalPathNameByHandleW 可用
    let mut dup = HANDLE(std::ptr::null_mut());
    let st = NtDuplicateObject(
        hproc,
        src,
        GetCurrentProcess(),
        &mut dup,
        0,
        0,
        DUPLICATE_SAME_ACCESS,
    );
    if st < 0 {
        tracing::debug!("[probe] NtDuplicateObject st={st:#x}（复验诊断）");
        return None;
    }
    let name = final_path(dup);
    if name.is_none() {
        tracing::debug!(
            "[probe] GetFinalPathNameByHandleW 失败 gle={}（复验诊断）",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        );
    }
    let _ = CloseHandle(dup);
    name
}

unsafe fn final_path(h: HANDLE) -> Option<String> {
    use windows::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, GETFINALPATHNAMEBYHANDLE_FLAGS,
    };
    let mut buf = [0u16; 1024];
    let n = GetFinalPathNameByHandleW(h, &mut buf, GETFINALPATHNAMEBYHANDLE_FLAGS(0));
    if n == 0 || n as usize > buf.len() {
        return None;
    }
    let s = String::from_utf16_lossy(&buf[..n as usize]);
    // "\\?\C:\dir\file" → 正斜杠形式（与 nt_to_win32 管线输出同构）；
    // 非 DOS 路径（如设备映射）原样返回仍可参与规则匹配（两分支处理一致，
    // 原 if/else 同代码冗余已删——M4 待修清单 7）
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    Some(s.replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 探测决策_三条件缺一不可() {
        assert!(
            probe_allowed(true, false, true),
            "Create/Read+未失败+间隔到 → 探测"
        );
        assert!(
            !probe_allowed(false, false, true),
            "Write 等其他 opcode 不探测"
        );
        assert!(
            !probe_allowed(true, true, true),
            "失败过的 FileObject 不重试"
        );
        assert!(!probe_allowed(true, false, false), "限流间隔未到不探测");
    }

    #[test]
    fn 限流常量为百毫秒级() {
        // 防止未来误改成 0（等于无限流，burst 会打满回调线程）
        assert!(PROBE_MIN_INTERVAL >= std::time::Duration::from_millis(100));
        assert!(PROBE_MIN_INTERVAL <= std::time::Duration::from_millis(1000));
    }

    /// FFI 探测链在无句柄匹配的进程上返回空（不 panic、不死循环）。
    /// 本测试以当前进程 + 伪造 FileObject 地址触发快照+检索路径（管理员以外
    /// 权限查句柄表受限，仅验证安全返回）。
    #[test]
    fn 探测_无匹配对象安全返回空() {
        // 0 是内核空指针占位，任何真实 FileObject 都非 0 → 检索必然 miss
        assert!(probe_file_name(std::process::id(), 0).is_none());
    }
}
