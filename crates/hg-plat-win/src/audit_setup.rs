//! Security 4663 文件审计通道的系统侧启用/停用（auditpol + SACL；opt-in，
//! 技术设计拍板记录 11）。由 `enable-file-audit` / `disable-file-audit` 子命令
//! 调用，需管理员：auditpol 改审计策略需 SeSecurityPrivilege（或审计策略对象
//! 写权限），SACL 写入（SetNamedSecurityInfoW 带 SACL_SECURITY_INFORMATION）
//! 需已启用的 SeSecurityPrivilege。
//!
//! 启用 = ① auditpol 开 File System 成功审计（子类别用 GUID 形式，免本地化
//! 名称差异）② 目标目录追加 Everyone 审计 ACE（FILE_GENERIC_READ|WRITE，
//! 子容器与子对象继承）③ 更新 config.toml [file_audit]。停用对称。
//!
//! 系统代价（如实披露）：SACL 命中后每次访问产生 4663（伴随 4656/4658），
//! Security 日志增长量级取决于 watch 目录访问频率——watch 应收敛到 .git 级
//! 目录而非盘根。停用只撤销本工具写入的 Everyone 审计 ACE 与子类别开关，
//! 系统原有审计配置若被覆盖请以 `auditpol /backup` 预留底自行核对。
//!
//! 验证级：编译级 + 路径归一/配置更新单测；auditpol/SACL 系统效果待实机复验。

use std::path::Path;

use anyhow::{bail, Context, Result};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
    EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS, SE_FILE_OBJECT,
    SET_AUDIT_SUCCESS, TRUSTEE_W, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP,
};
use windows::Win32::Security::{ACL, PSID, SACL_SECURITY_INFORMATION, SUB_CONTAINERS_AND_OBJECTS_INHERIT};
use windows::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};

/// Everyone SID（审计 ACE 主体：审计所有访问者；判定/豁免由引擎侧规则负责，
/// SACL 不做身份筛选）
const EVERYONE_SID: &str = "S-1-1-0";
/// 审计子类别 "File System" 的 GUID（本地化无关；auditpol /set /subcategory:
/// {GUID} 形式，MSDN Audit File System 文档）
const FILE_SYSTEM_SUBCATALOG_GUID: &str = "{0CCE9216-69AE-11D9-BED3-505054503030}";

/// 启用文件审计（需管理员）：auditpol + SACL + 配置。
pub fn enable_file_audit(path: &Path, config_path: &Path) -> Result<()> {
    let dir = canonical_dir(path)?;
    auditpol_set(true)?;
    apply_audit_ace(&dir, true).with_context(|| format!("SACL 配置失败：{}", dir.display()))?;
    let cfg = config_update(config_path, &dir.display().to_string(), true)?;
    println!("文件审计已启用：{}", dir.display());
    println!(
        "config.toml [file_audit] enabled={}，watch_paths={:?}",
        cfg.file_audit.enabled, cfg.file_audit.watch_paths
    );
    println!("重启 HarnessGuard 后消费端生效（服务：sc stop HarnessGuard && sc start HarnessGuard）");
    Ok(())
}

/// 停用文件审计（需管理员）：对称回退。watch_paths 清空后消费开关一并关闭。
pub fn disable_file_audit(path: &Path, config_path: &Path) -> Result<()> {
    let dir = canonical_dir(path)?;
    apply_audit_ace(&dir, false).with_context(|| format!("SACL 撤销失败：{}", dir.display()))?;
    auditpol_set(false)?;
    let cfg = config_update(config_path, &dir.display().to_string(), false)?;
    println!("文件审计已停用：{}", dir.display());
    println!(
        "config.toml [file_audit] enabled={}，watch_paths={:?}",
        cfg.file_audit.enabled, cfg.file_audit.watch_paths
    );
    Ok(())
}

/// 归一到绝对原生路径（fs::canonicalize 的 \\?\ 前缀剥除；目录不存在报错）。
fn canonical_dir(path: &Path) -> Result<std::path::PathBuf> {
    let c = std::fs::canonicalize(path).with_context(|| format!("路径不存在：{}", path.display()))?;
    let s = c.display().to_string();
    Ok(std::path::PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s)))
}

/// auditpol 开/关 File System 成功审计（子类别 GUID 形式，免本地化差异）。
fn auditpol_set(enable: bool) -> Result<()> {
    let state = if enable { "enable" } else { "disable" };
    let out = std::process::Command::new("auditpol")
        .args(["/set", &format!("/subcategory:{FILE_SYSTEM_SUBCATALOG_GUID}"), &format!("/success:{state}")])
        .output()
        .context("启动 auditpol 失败（需管理员）")?;
    if !out.status.success() {
        bail!("auditpol 设置失败：{}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

/// 审计 ACE 构造（add=SET_AUDIT_SUCCESS 追加 / del=REVOKE_ACCESS 撤销）。
/// 读+写全审计：场景 A 规则既含读取（.git）也含写入（敏感文件创建）。
fn audit_ea(sid: PSID, add: bool) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
        grfAccessMode: if add { SET_AUDIT_SUCCESS } else { REVOKE_ACCESS },
        grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: PWSTR(sid.0.cast()),
        },
    }
}

/// 对目录合并/撤销 Everyone 审计 ACE（读现有 SACL → SetEntriesInAclW 合并 →
/// SetNamedSecurityInfoW 写回）。幂等：SET_AUDIT_SUCCESS 对已存在的同 trustee
/// ACE 为合并语义；REVOKE_ACCESS 对不存在条目不报错。
fn apply_audit_ace(dir: &Path, add: bool) -> Result<()> {
    let path_w: Vec<u16> = dir.display().to_string().encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let sid_w: Vec<u16> = EVERYONE_SID.encode_utf16().chain(std::iter::once(0)).collect();
        let mut everyone = PSID(std::ptr::null_mut());
        ConvertStringSidToSidW(PCWSTR(sid_w.as_ptr()), &mut everyone)
            .context("Everyone SID 构造失败")?;

        let mut sacl: *mut ACL = std::ptr::null_mut();
        let mut sd = windows::Win32::Security::PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        let rc = GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            SACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            Some(&mut sacl),
            &mut sd,
        );
        if rc.0 != 0 {
            LocalFree(Some(HLOCAL(everyone.0.cast())));
            bail!("读取 SACL 失败（win32 error {}）", rc.0);
        }
        let old: Option<*const ACL> = if sacl.is_null() { None } else { Some(sacl) };
        let mut newacl: *mut ACL = std::ptr::null_mut();
        let rc2 = SetEntriesInAclW(Some(&[audit_ea(everyone, add)]), old, &mut newacl);
        // sd 持有 sacl 指向的内存：SetEntriesInAclW 已消费完旧表，先释放再写回
        let _ = LocalFree(Some(HLOCAL(sd.0.cast())));
        let _ = LocalFree(Some(HLOCAL(everyone.0.cast())));
        if rc2.0 != 0 {
            bail!("SACL 合并失败（win32 error {}）", rc2.0);
        }
        let rc3 = SetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            SACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            Some(newacl),
        );
        let _ = LocalFree(Some(HLOCAL(newacl.cast())));
        if rc3.0 != 0 {
            bail!("SACL 写回失败（win32 error {}）", rc3.0);
        }
    }
    Ok(())
}

/// 更新 config.toml [file_audit]（大小写不敏感去重；disable 清空后关开关）。
fn config_update(config_path: &Path, dir: &str, enable: bool) -> Result<hg_core::FileConfig> {
    let mut cfg = if config_path.exists() {
        hg_core::FileConfig::load(config_path)?
    } else {
        hg_core::FileConfig::default()
    };
    if enable {
        if !cfg.file_audit.watch_paths.iter().any(|p| p.eq_ignore_ascii_case(dir)) {
            cfg.file_audit.watch_paths.push(dir.to_string());
        }
        cfg.file_audit.enabled = true;
    } else {
        cfg.file_audit.watch_paths.retain(|p| !p.eq_ignore_ascii_case(dir));
        if cfg.file_audit.watch_paths.is_empty() {
            cfg.file_audit.enabled = false;
        }
    }
    cfg.save(config_path)?;
    Ok(cfg)
}

/// 供 main 侧选择的配置路径：CWD 优先，缺省退回 exe 目录（服务安装形态）。
pub fn cli_config_path() -> std::path::PathBuf {
    let cwd = std::path::PathBuf::from("config.toml");
    if cwd.exists() {
        return cwd;
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("config.toml")))
        .filter(|p| p.exists())
        .unwrap_or(cwd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 路径归一_前缀剥除与不存在报错() {
        let dir = canonical_dir(std::path::Path::new(".")).unwrap();
        assert!(!dir.display().to_string().starts_with(r"\\?\"));
        assert!(canonical_dir(std::path::Path::new("Z:/definitely/not/exist")).is_err());
    }

    #[test]
    fn 配置更新_启用去重与停用回退() {
        let tmp = std::env::temp_dir().join("hg-audit-setup-test.toml");
        let _ = std::fs::remove_file(&tmp);
        let dir = r"D:\repo\.git";
        // 启用两次同路径：去重
        config_update(&tmp, dir, true).unwrap();
        let cfg = config_update(&tmp, dir, true).unwrap();
        assert!(cfg.file_audit.enabled);
        assert_eq!(cfg.file_audit.watch_paths, vec![dir.to_string()]);
        // 重复落盘可再加载（round-trip）
        let re = hg_core::FileConfig::load(&tmp).unwrap();
        assert!(re.file_audit.enabled && re.file_audit.watch_paths.len() == 1);
        // 停用：路径移除且开关关闭
        let cfg2 = config_update(&tmp, dir, false).unwrap();
        assert!(!cfg2.file_audit.enabled && cfg2.file_audit.watch_paths.is_empty());
        let _ = std::fs::remove_file(&tmp);
    }

    /// ACE 构造的纯字段断言（FFI 生效待实机；此处锚定权限/模式/继承位）。
    #[test]
    fn 审计ace构造_权限模式与继承() {
        let ea_add = audit_ea(PSID(std::ptr::null_mut()), true);
        assert_eq!(ea_add.grfAccessPermissions, FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0);
        assert_eq!(ea_add.grfAccessMode, SET_AUDIT_SUCCESS);
        assert_eq!(ea_add.grfInheritance, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
        assert_eq!(ea_add.Trustee.TrusteeForm, TRUSTEE_IS_SID);
        let ea_del = audit_ea(PSID(std::ptr::null_mut()), false);
        assert_eq!(ea_del.grfAccessMode, REVOKE_ACCESS);
        // 字段类型经结构体构造已在编译期对齐（ACCESS_MODE/ACE_FLAGS），无需额外断言
    }
}
