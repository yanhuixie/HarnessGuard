//! 持久化检测（M1 范围：注册表 RunKey/RunOnce 轮询快照对比）。
//! 设计 §5.1 原文含 TaskScheduler ETW 日志；M1 以轮询过渡（无法归因发起进程，
//! 显式披露），M4 加固补 ETW 归因。计划任务检测 M4（schtasks 快照对比同思路）。

use std::sync::Arc;
use std::time::Duration;

use hg_model::{PersistenceKind, RawEvent};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_USERS, KEY_READ,
};

use crate::etw_source::EtwInner;

const POLL: Duration = Duration::from_secs(30);

struct RunEntry {
    sid: String,
    name: String,
    value: String,
}

pub fn spawn_runkey_poll(inner: Arc<EtwInner>) {
    std::thread::spawn(move || {
        let mut prev = snapshot();
        loop {
            std::thread::sleep(POLL);
            let cur = snapshot();
            for e in &cur {
                if !prev.iter().any(|p| key_of(p) == key_of(e)) {
                    tracing::warn!(
                        "[持久化] 新增 RunKey：HKU\\{}\\...\\Run\\{} = {}",
                        e.sid,
                        e.name,
                        e.value
                    );
                    inner.emit(RawEvent::Persistence {
                        pid: 0, // 轮询无法归因发起进程（M1 已知缺口，M4 补 ETW 归因）
                        kind: PersistenceKind::RunKey,
                        detail: format!(
                            "HKU\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{} = {}",
                            e.sid, e.name, e.value
                        ),
                    });
                }
            }
            prev = cur;
        }
    });
}

fn key_of(e: &RunEntry) -> String {
    format!("{}|{}|{}", e.sid, e.name, e.value)
}

fn to_w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn snapshot() -> Vec<RunEntry> {
    let mut out = Vec::new();
    unsafe {
        let empty = to_w("");
        let mut users = HKEY(std::ptr::null_mut());
        let rc = RegOpenKeyExW(
            HKEY_USERS,
            PCWSTR(empty.as_ptr()),
            None,
            KEY_READ,
            &mut users,
        );
        if rc != ERROR_SUCCESS {
            return out;
        }
        let mut idx: u32 = 0;
        loop {
            let mut name = [0u16; 256];
            let mut len = name.len() as u32;
            let r = RegEnumKeyExW(
                users,
                idx,
                Some(windows::core::PWSTR(name.as_mut_ptr())),
                &mut len,
                None,
                None,
                None,
                None,
            );
            if r == ERROR_NO_MORE_ITEMS {
                break;
            }
            if r != ERROR_SUCCESS {
                idx += 1;
                continue;
            }
            let sid = String::from_utf16_lossy(&name[..len as usize]);
            if !sid.contains('-') || sid.ends_with("_Classes") {
                idx += 1;
                continue;
            }
            for sub in ["Run", "RunOnce"] {
                let path = format!("{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\{sub}");
                let path_w = to_w(&path);
                let mut hk = HKEY(std::ptr::null_mut());
                let rc =
                    RegOpenKeyExW(HKEY_USERS, PCWSTR(path_w.as_ptr()), None, KEY_READ, &mut hk);
                if rc != ERROR_SUCCESS {
                    continue;
                }
                let mut vi: u32 = 0;
                loop {
                    let mut vname = [0u16; 512];
                    let mut vlen = vname.len() as u32;
                    let mut data = [0u8; 4096];
                    let mut dlen = data.len() as u32;
                    let rv = RegEnumValueW(
                        hk,
                        vi,
                        Some(windows::core::PWSTR(vname.as_mut_ptr())),
                        &mut vlen,
                        None,
                        None,
                        Some(data.as_mut_ptr()),
                        Some(&mut dlen),
                    );
                    if rv == ERROR_NO_MORE_ITEMS {
                        break;
                    }
                    if rv != ERROR_SUCCESS {
                        vi += 1;
                        continue;
                    }
                    let vn = String::from_utf16_lossy(&vname[..vlen as usize]);
                    let words: Vec<u16> = data[..dlen as usize]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .take_while(|&w| w != 0)
                        .collect();
                    let dv = String::from_utf16_lossy(&words);
                    out.push(RunEntry {
                        sid: sid.clone(),
                        name: vn,
                        value: dv,
                    });
                    vi += 1;
                }
                let _ = RegCloseKey(hk);
            }
            idx += 1;
        }
        let _ = RegCloseKey(users);
    }
    out
}
