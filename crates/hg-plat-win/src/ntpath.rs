//! NT 设备路径 → 盘符路径转换（M0 spike 校准项：ETW 给出 `\Device\HarddiskVolume3\...`）。

use std::path::PathBuf;
use std::sync::OnceLock;

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

/// 设备路径前缀表（`\Device\HarddiskVolume3` → `C:`），按前缀长度降序匹配。
static DEVICE_MAP: OnceLock<Vec<(String, String)>> = OnceLock::new();

pub fn nt_to_win32(nt_path: &str) -> PathBuf {
    let map = DEVICE_MAP.get_or_init(build_device_map);
    let norm = nt_path.replace('\\', "/");
    for (dev, drive) in map {
        let dev_norm = dev.replace('\\', "/");
        if norm.len() > dev_norm.len()
            && norm[..dev_norm.len()].eq_ignore_ascii_case(&dev_norm)
            && norm.as_bytes()[dev_norm.len()] == b'/'
        {
            let rest = &norm[dev_norm.len()..];
            return PathBuf::from(format!("{drive}{rest}"));
        }
    }
    PathBuf::from(nt_path)
}

fn build_device_map() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for c in b'A'..=b'Z' {
        let drive = format!("{}:", c as char);
        let mut buf = [0u16; 512];
        let name_w: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let n = unsafe { QueryDosDeviceW(PCWSTR(name_w.as_ptr()), Some(&mut buf)) };
        if n > 0 {
            let dev: String = buf[..n as usize - 1]
                .iter()
                .filter(|&&ch| ch != 0)
                .map(|&ch| ch as u8 as char)
                .collect();
            if !dev.is_empty() {
                out.push((dev, drive));
            }
        }
    }
    // 长前缀优先（如 HarddiskVolume10 先于 HarddiskVolume1）
    out.sort_by_key(|e| std::cmp::Reverse(e.0.len()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 非设备路径原样返回() {
        let p = nt_to_win32("C:/Windows/system32/cmd.exe");
        assert_eq!(p, PathBuf::from("C:/Windows/system32/cmd.exe"));
    }
}
