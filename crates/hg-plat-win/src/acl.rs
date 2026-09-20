//! 自保护 DACL（技术设计 §8.2；M4 待修清单 11 前半）：config.toml /
//! harnessguard.db / web-token.txt 置为仅 SYSTEM/Administrators 完全控制
//! （受保护 DACL，切断父目录继承），防非管理员用户或被攻陷的 harness 进程
//! 直接改配置、注入白名单或读 Web token。
//!
//! 应用时机：install 时对已存在文件应用；服务启动自检（未保护则告警并自愈
//! 应用，覆盖安装后首次启动新建的文件——web-token.txt 每次服务启动重写，
//! 亦由此覆盖）。控制台模式不启用（调试形态）。
//!
//! 验证级：编译级 + apply/check 往返单测（本机非提权进程对自建临时文件可设
//! DACL——文件 owner 恒有隐式 WRITE_DAC）；LocalSystem 服务下的部署形态
//! 待实机复验。

use std::path::Path;

use anyhow::{bail, Result};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
    EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SET_ACCESS, TRUSTEE_W,
    TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP,
};
use windows::Win32::Security::{
    EqualSid, GetAce, GetAclInformation, AclSizeInformation, ACCESS_ALLOWED_ACE,
    ACE_HEADER, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, NO_INHERITANCE,
    PROTECTED_DACL_SECURITY_INFORMATION, PSID, PSECURITY_DESCRIPTOR,
};

/// ACE 类型 0 = ACCESS_ALLOWED_ACE（winnt.h；windows crate 该常量在
/// Win32_System_SystemServices feature，为一个字节值引整个 feature 不值）
const ACE_TYPE_ALLOWED: u8 = 0;
/// AceFlags 位 0x10 = INHERITED_ACE（继承来的 ACE：非本工具产物，且会随
/// 父目录 ACL 放宽自动传播——按未保护处理；评审 M-3）
const ACE_FLAG_INHERITED: u8 = 0x10;

/// 文件完全控制（读写删改 ACL）
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
/// LocalSystem 账户
pub const SID_SYSTEM: &str = "S-1-5-18";
/// BUILTIN\Administrators
pub const SID_ADMINS: &str = "S-1-5-32-544";
/// Everyone（单测还原用；SET_ACCESS 语义下与生产无交集）
pub const SID_EVERYONE: &str = "S-1-1-0";

/// 以指定受托者列表替换式重设文件 DACL（受保护：切断父目录继承）。
/// SET_ACCESS 语义：同受托者旧 ACE 替换，其余保留合并。
pub fn apply_dacl(path: &Path, sids: &[(&str, u32)]) -> Result<()> {
    let path_w: Vec<u16> = wide(&path.display().to_string());
    unsafe {
        let mut entries: Vec<EXPLICIT_ACCESS_W> = Vec::with_capacity(sids.len());
        let mut sid_ptrs: Vec<PSID> = Vec::with_capacity(sids.len());
        for (sid_str, mask) in sids {
            let Some(sid) = sid_from_str(sid_str) else {
                // 先释放已转换的 SID 再报错（防泄漏——评审 L-3）
                for p in sid_ptrs {
                    let _ = LocalFree(Some(HLOCAL(p.0.cast())));
                }
                bail!("SID 构造失败：{sid_str}");
            };
            sid_ptrs.push(sid);
            entries.push(EXPLICIT_ACCESS_W {
                grfAccessPermissions: *mask,
                grfAccessMode: SET_ACCESS,
                grfInheritance: NO_INHERITANCE,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: std::ptr::null_mut(),
                    MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                    ptstrName: PWSTR(sid.0.cast()),
                },
            });
        }
        let mut newacl: *mut ACL = std::ptr::null_mut();
        let rc = SetEntriesInAclW(Some(&entries), None, &mut newacl);
        for p in sid_ptrs {
            let _ = LocalFree(Some(HLOCAL(p.0.cast())));
        }
        if rc.0 != 0 {
            bail!("DACL 构造失败（win32 error {}）", rc.0);
        }
        let rc2 = SetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(newacl),
            None,
        );
        let _ = LocalFree(Some(HLOCAL(newacl.cast())));
        if rc2.0 != 0 {
            bail!("DACL 写入失败（win32 error {}）：{}", rc2.0, path.display());
        }
    }
    Ok(())
}

/// 自保护：仅 SYSTEM + Administrators 完全控制。
pub fn protect_file(path: &Path) -> Result<()> {
    apply_dacl(path, &[(SID_SYSTEM, FILE_ALL_ACCESS), (SID_ADMINS, FILE_ALL_ACCESS)])
}

/// 自检：DACL 是否"仅 SYSTEM/Administrators 可写"——存在允许型 ACE 授予其他
/// 受托者，或混入非允许型 ACE（拒绝/审计——非本工具产物），或无 DACL（继承
/// 父目录），均判未保护。文件不存在返回 Ok(false)（调用方跳过）。
pub fn check_protected(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let path_w = wide(&path.display().to_string());
    unsafe {
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        let rc = GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        );
        if rc.0 != 0 {
            bail!("读取 DACL 失败（win32 error {}）：{}", rc.0, path.display());
        }
        let ok = dacl_is_protected(dacl);
        let _ = LocalFree(Some(HLOCAL(sd.0.cast())));
        Ok(ok)
    }
}

/// 服务启动自检（§8.2）：列出的文件存在且未保护 → 告警并自愈应用。
/// 覆盖 install 后首次启动新建的文件（config/db/token 各自生成时机不同）。
pub fn startup_selfcheck(files: &[std::path::PathBuf]) {
    for p in files {
        match check_protected(p) {
            Ok(true) => {}
            Ok(false) if !p.exists() => {} // 尚未生成，下次启动覆盖
            Ok(false) => {
                tracing::warn!(
                    "[自保护] {} 未受保护，应用 DACL（仅 SYSTEM/Administrators）",
                    p.display()
                );
                if let Err(e) = protect_file(p) {
                    tracing::error!("[自保护] DACL 应用失败（{}）：{e:#}", p.display());
                }
            }
            Err(e) => tracing::error!("[自保护] 检查失败（{}）：{e:#}", p.display()),
        }
    }
}

/// DACL 判定：所有允许型 ACE 的受托者均须为 SYSTEM/Administrators 且至少
/// 其一在场（protect_file 保证双受托者；此处校验"无外泄面"）。
unsafe fn dacl_is_protected(dacl: *mut ACL) -> bool {
    if dacl.is_null() {
        return false;
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    if GetAclInformation(
        dacl,
        &mut info as *mut _ as *mut core::ffi::c_void,
        std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
        AclSizeInformation,
    )
    .is_err()
    {
        return false;
    }
    let Some(sys) = sid_from_str(SID_SYSTEM) else { return false };
    let Some(admins) = sid_from_str(SID_ADMINS) else {
        let _ = LocalFree(Some(HLOCAL(sys.0.cast())));
        return false;
    };
    let mut saw_trusted = false;
    for i in 0..info.AceCount {
        let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
        if GetAce(dacl, i, &mut ace).is_err() || ace.is_null() {
            saw_trusted = false;
            break;
        }
        let header = &*(ace as *const ACE_HEADER);
        if header.AceType != ACE_TYPE_ALLOWED || header.AceFlags & ACE_FLAG_INHERITED != 0 {
            // 拒绝/审计/复合 ACE 或继承 ACE：非本工具产物（protect_file 产出
            // 受保护 DACL，不继承不混合）——按未保护处理（fail-closed）
            saw_trusted = false;
            break;
        }
        let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
        let sid = PSID((&allowed.SidStart as *const u32).cast_mut().cast());
        // EqualSid：相等返回 Ok(())，不等/版本不匹配返回 Err
        let is_sys = EqualSid(sid, sys).is_ok();
        let is_adm = EqualSid(sid, admins).is_ok();
        if !is_sys && !is_adm {
            saw_trusted = false; // 外来受托者的允许 ACE：未保护
            break;
        }
        saw_trusted = true;
    }
    let _ = LocalFree(Some(HLOCAL(sys.0.cast())));
    let _ = LocalFree(Some(HLOCAL(admins.0.cast())));
    saw_trusted
}

unsafe fn sid_from_str(s: &str) -> Option<PSID> {
    let w = wide(s);
    let mut sid = PSID(std::ptr::null_mut());
    ConvertStringSidToSidW(PCWSTR(w.as_ptr()), &mut sid).ok().map(|_| sid)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// apply/check 往返：默认继承 DACL 与 Everyone DACL 均未保护；
    /// protect 后保护成立；还原后失效（owner 恒有隐式 WRITE_DAC，非提权可设）。
    #[test]
    fn dac保护往返() {
        let dir = std::env::temp_dir().join("hg-acl-test");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("t.txt");
        std::fs::write(&f, "x").unwrap();
        assert!(!check_protected(&f).unwrap(), "默认继承 DACL 未保护");
        apply_dacl(&f, &[(SID_EVERYONE, FILE_ALL_ACCESS)]).unwrap();
        assert!(!check_protected(&f).unwrap(), "Everyone 允许 ACE 未保护");
        protect_file(&f).unwrap();
        assert!(check_protected(&f).unwrap(), "仅 SYSTEM/Admins → 保护成立");
        // 还原以便清理（验证 DACL 可再次改写）
        apply_dacl(&f, &[(SID_EVERYONE, FILE_ALL_ACCESS)]).unwrap();
        assert!(!check_protected(&f).unwrap(), "还原后未保护");
        std::fs::remove_file(&f).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn 不存在文件按未保护跳过() {
        assert!(!check_protected(Path::new("Z:/definitely/not/exist")).unwrap());
    }
}
