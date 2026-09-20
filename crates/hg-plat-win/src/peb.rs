//! 读目标进程 PEB 的 CommandLine + 进程创建时间（M0 校准项：内核 ETW 不提供命令行，
//! 降级链第一级：SYSTEM/管理员读 PEB；失败由调用方置空并披露）。

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

/// 返回 (cmdline, start_time_filetime, cwd)。任一步失败对应项为空/0——按设计
/// "显式失败"原则，调用方负责记录可见性缺口。
pub fn query_process(pid: u32) -> (Vec<OsString>, u64, PathBuf) {
    let start = process_start_time(pid);
    let (cmdline, cwd) = read_params(pid).unwrap_or_default();
    (cmdline, start, cwd)
}

fn open(pid: u32) -> Option<HANDLE> {
    unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok() }
}

/// 进程创建时间（FILETIME u64）。进程已退出或无权限 → 0（竞态容忍，调用方披露）。
pub fn process_start_time(pid: u32) -> u64 {
    let Some(h) = open(pid) else { return 0 };
    let mut creation = windows::Win32::Foundation::FILETIME::default();
    let mut exit_t = windows::Win32::Foundation::FILETIME::default();
    let mut kernel = windows::Win32::Foundation::FILETIME::default();
    let mut user = windows::Win32::Foundation::FILETIME::default();
    let r = unsafe {
        windows::Win32::System::Threading::GetProcessTimes(
            h,
            &mut creation,
            &mut exit_t,
            &mut kernel,
            &mut user,
        )
    };
    unsafe {
        let _ = CloseHandle(h);
    };
    if r.is_ok() {
        ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64
    } else {
        0
    }
}

// PEB / RTL_USER_PROCESS_PARAMETERS 偏移（架构相关，双架构 macOS 同理需注意——
// 此处为 Windows x64/x86；aarch64-windows 与 x64 同偏移）
#[cfg(target_pointer_width = "64")]
const PEB_PROCESS_PARAMETERS: usize = 0x20;
#[cfg(target_pointer_width = "64")]
const PARAMS_COMMAND_LINE: usize = 0x70;
#[cfg(target_pointer_width = "64")]
const PARAMS_CURRENT_DIR: usize = 0x38;
#[cfg(target_pointer_width = "32")]
const PEB_PROCESS_PARAMETERS: usize = 0x10;
#[cfg(target_pointer_width = "32")]
const PARAMS_COMMAND_LINE: usize = 0x40;
#[cfg(target_pointer_width = "32")]
const PARAMS_CURRENT_DIR: usize = 0x24;

fn read_params(pid: u32) -> Option<(Vec<OsString>, PathBuf)> {
    let h = open(pid)?;
    unsafe {
        let mut pbi = PROCESS_BASIC_INFORMATION::default();
        let status = NtQueryInformationProcess(
            h,
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut(),
        );
        if status.0 != 0 {
            let _ = CloseHandle(h);
            return None;
        }
        let peb = pbi.PebBaseAddress as usize;
        let mut params: usize = 0;
        if ReadProcessMemory(
            h,
            (peb + PEB_PROCESS_PARAMETERS) as *const core::ffi::c_void,
            &mut params as *mut usize as *mut core::ffi::c_void,
            std::mem::size_of::<usize>(),
            None,
        )
        .is_err()
            || params == 0
        {
            let _ = CloseHandle(h);
            return None;
        }
        // RTL_USER_PROCESS_PARAMETERS 的 CurrentDirectory（UNICODE_STRING + Handle）
        // 与 CommandLine（UNICODE_STRING）
        #[repr(C)]
        struct UniStr {
            len: u16,
            _max: u16,
            _pad: u16,
            buf: usize,
        }
        let read_unistr = |off: usize| -> Option<OsString> {
            let mut us = UniStr {
                len: 0,
                _max: 0,
                _pad: 0,
                buf: 0,
            };
            if ReadProcessMemory(
                h,
                (params + off) as *const core::ffi::c_void,
                &mut us as *mut UniStr as *mut core::ffi::c_void,
                std::mem::size_of::<UniStr>(),
                None,
            )
            .is_err()
                || us.buf == 0
                || us.len == 0
            {
                return None;
            }
            let n = (us.len as usize) / 2;
            let mut buf = vec![0u16; n];
            if ReadProcessMemory(
                h,
                us.buf as *const core::ffi::c_void,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                us.len as usize,
                None,
            )
            .is_err()
            {
                return None;
            }
            Some(OsString::from_wide(&buf))
        };
        let cmdline = read_unistr(PARAMS_COMMAND_LINE)
            .map(|s| split_cmdline(&s))
            .unwrap_or_default();
        let cwd = read_unistr(PARAMS_CURRENT_DIR)
            .map(|s| PathBuf::from(s.to_string_lossy().trim_end_matches('\\').to_string()))
            .unwrap_or_default();
        let _ = CloseHandle(h);
        Some((cmdline, cwd))
    }
}

/// 简易命令行切分（空白分隔，支持双引号内空格）。PEB 读取拿到的是原始命令行串。
fn split_cmdline(raw: &OsString) -> Vec<OsString> {
    let s = raw.to_string_lossy();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for ch in s.chars() {
        match ch {
            '"' => in_quote = !in_quote,
            c if c.is_whitespace() && !in_quote => {
                if !cur.is_empty() {
                    out.push(OsString::from(cur.clone()));
                    cur.clear();
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(OsString::from(cur));
    }
    out
}
