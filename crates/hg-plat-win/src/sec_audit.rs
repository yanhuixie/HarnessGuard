//! Security 通道 4663 文件审计消费（场景 A 主路径候选；M4 第二批 P1-5 评估落地）。
//!
//! 背景（M4 复验定案 3）：句柄探测对短命句柄无效（ETW 投递延迟 > 句柄存活期），
//! 内核 FileIo 的 Name 关联在 burst 下 ~99% unknown——场景 A（.git 读取判定）需要
//! 备选通道。评估结论（技术设计拍板记录 11）：
//! - ETW 直连 Security-Auditing provider（{54849625-…}）为 undocumented 技巧
//!   （仅 SYSTEM、搭 OS 的 EventLog-Security 会话，krabsetw 实证），不作主路径；
//! - 本模块采用文档化的 EvtSubscribe push 订阅（winevt）：Security 通道 +
//!   XPath 过滤 EventID=4663，管理员/Event Log Readers 权限，实时回调；
//! - 启用端（auditpol 开 File System 成功审计 + 目标目录 SACL）侵入系统级
//!   审计策略，须显式 opt-in（`enable-file-audit` 子命令管理生命周期），
//!   不进"一键安装"默认路径（M4 验收 ≤5 分钟人工步骤不受累）。
//!
//! 事件流：4663（Object Access）→ XML 渲染 → 解析 ObjectName/ProcessId/AccessMask
//! → watch_paths 前缀过滤 → NT 路径归一 → FileOpen 事件经 EtwInner 入引擎
//! （与 ETW 文件管线同构，引擎判定链复用，含监控树早过滤）。
//!
//! 验证级：编译级 + 解析/过滤纯函数单测；运行时效果待实机复验
//! （需 auditpol + SACL + 管理员，见 enable-file-audit）。

use std::sync::Arc;

use windows::core::PCWSTR;
use windows::Win32::System::EventLog::{
    EvtRender, EvtRenderEventXml, EvtSubscribe, EvtSubscribeToFutureEvents, EVT_HANDLE,
    EVT_SUBSCRIBE_NOTIFY_ACTION,
};

use crate::etw_source::{EtwInner, FILE_OP_READ, FILE_OP_WRITE};
use crate::ntpath::nt_to_win32;

/// FILE_WRITE_DATA(0x2) | GENERIC_WRITE(0x40000000)：任一写位即按写访问处理，
/// 其余（读/删除等）按读——场景 A 规则（.git 读取）以读为主
const WRITE_MASK: u32 = 0x0000_0002 | 0x4000_0000;

/// 订阅上下文（EvtSubscribe 回调经裸指针携带；进程生命周期持有，不释放）
struct SecAuditCtx {
    inner: Arc<EtwInner>,
    /// 监听路径前缀（已归一：小写、正斜杠、无尾斜杠）
    watch: Vec<String>,
}

/// 启动 Security 4663 订阅线程（由 hg-app 装配，仅 [file_audit].enabled 时调用）。
pub fn spawn_sec_audit(inner: Arc<EtwInner>, watch_paths: Vec<String>) {
    if watch_paths.is_empty() {
        tracing::warn!("[file-audit] watch_paths 为空，4663 订阅不启动（配置见 config.toml [file_audit]）");
        return;
    }
    let watch: Vec<String> = watch_paths
        .iter()
        .map(|p| normalize_watch(p))
        .filter(|p| !p.is_empty())
        .collect();
    std::thread::Builder::new()
        .name("sec-audit".into())
        .spawn(move || {
            // 裸指针须在线程闭包内构造（跨线程移动裸指针不 Send）
            let ctx =
                Box::into_raw(Box::new(SecAuditCtx { inner, watch })) as *const core::ffi::c_void;
            let channel: Vec<u16> = "Security".encode_utf16().chain(std::iter::once(0)).collect();
            let query: Vec<u16> = "*[System[EventID=4663]]"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let sub = unsafe {
                EvtSubscribe(
                    None,
                    None,
                    PCWSTR(channel.as_ptr()),
                    PCWSTR(query.as_ptr()),
                    None,
                    Some(ctx),
                    Some(on_event),
                    EvtSubscribeToFutureEvents.0 as u32,
                )
            };
            match sub {
                Ok(_handle) => {
                    tracing::info!("[file-audit] Security 4663 订阅已建立（push 模式，未来事件）");
                    // 订阅句柄与回调上下文随线程常驻（停机时进程退出回收）
                    loop {
                        std::thread::park();
                    }
                }
                Err(e) => {
                    tracing::error!("[file-audit] Security 订阅失败（需管理员或 Event Log Readers）：{e}");
                }
            }
        })
        .expect("spawn sec-audit");
}

/// EvtSubscribe push 回调（EventLog 服务线程上下文；处理须非阻塞——emit 为
/// try_send，慢消费走通道满丢弃计数，技术设计 §9.2）。
unsafe extern "system" fn on_event(
    _action: EVT_SUBSCRIBE_NOTIFY_ACTION,
    context: *const core::ffi::c_void,
    event: EVT_HANDLE,
) -> u32 {
    let ctx = &*(context as *const SecAuditCtx);
    if let Some(xml) = render_xml(event) {
        handle_4663(ctx, &xml);
    }
    0 // ERROR_SUCCESS
}

/// 渲染事件为 XML（两段 grow-retry；EvtRender 的 bufferused 单位为字节）。
unsafe fn render_xml(event: EVT_HANDLE) -> Option<String> {
    let mut needed = 0u32;
    let _ = EvtRender(
        None,
        event,
        EvtRenderEventXml.0 as u32,
        0,
        None,
        &mut needed,
        std::ptr::null_mut(),
    );
    if needed == 0 || needed > 4 * 1024 * 1024 {
        return None;
    }
    let mut buf = vec![0u16; needed as usize / 2 + 1];
    let mut used = 0u32;
    EvtRender(
        None,
        event,
        EvtRenderEventXml.0 as u32,
        needed,
        Some(buf.as_mut_ptr().cast()),
        &mut used,
        std::ptr::null_mut(),
    )
    .ok()?;
    Some(String::from_utf16_lossy(&buf[..used as usize / 2]))
}

/// 4663 事件处理：解析 → 前缀过滤 → 复用 ETW 文件管线入引擎。
fn handle_4663(ctx: &SecAuditCtx, xml: &str) {
    let Some((pid, op, path)) = parse_4663(xml) else { return };
    let path_str = path.display().to_string().to_lowercase().replace('\\', "/");
    if !ctx.watch.iter().any(|w| path_watch_hit(&path_str, w)) {
        return;
    }
    ctx.inner.emit_file_event(pid, op, &path.display().to_string());
    tracing::debug!("[file-audit] 4663 pid={pid} op={op} {path_str}");
}

/// 路径前缀命中（分量边界：`watch` 须等于路径或为其祖先目录——
/// `d:/r/.git` 不命中 `d:/r/.git-backup/x`，朴素字符串前缀会误命中）。
fn path_watch_hit(path: &str, watch: &str) -> bool {
    path == watch || path.starts_with(&format!("{watch}/"))
}

/// 解析 4663 XML 的 (pid, opcode, NT 路径)。ProcessId/AccessMask 为 0x 前缀十六进制。
fn parse_4663(xml: &str) -> Option<(u32, u8, std::path::PathBuf)> {
    let pid = u32::from_str_radix(xml_field(xml, "ProcessId")?.trim_start_matches("0x"), 16).ok()?;
    let obj = xml_field(xml, "ObjectName")?;
    if pid == 0 || obj.is_empty() {
        return None;
    }
    let mask = u32::from_str_radix(
        xml_field(xml, "AccessMask").unwrap_or_default().trim_start_matches("0x"),
        16,
    )
    .unwrap_or(0);
    let op = if mask & WRITE_MASK != 0 { FILE_OP_WRITE } else { FILE_OP_READ };
    Some((pid, op, nt_to_win32(&obj)))
}

/// 从事件 XML 提取 `<Data Name="xxx">值</Data>`（最小实现：固定 schema 子串
/// 定位 + 实体解码，避免引入 XML 依赖；单测覆盖）。
pub(crate) fn xml_field(xml: &str, name: &str) -> Option<String> {
    let pat = format!("<Data Name=\"{name}\">");
    let start = xml.find(&pat)? + pat.len();
    let end = xml[start..].find("</Data>")? + start;
    Some(xml_decode(&xml[start..end]))
}

/// 五个预定义 XML 实体解码（文件名中 `&` 合法出现，必须处理）。
fn xml_decode(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&") // 最后处理：防双重解码（"&amp;lt;" → "&lt;" 而非 "<"）
}

/// 监听前缀归一：小写、正斜杠、去尾斜杠。
fn normalize_watch(p: &str) -> String {
    p.replace('\\', "/").trim_end_matches('/').to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<Event><System><EventID>4663</EventID></System><EventData>\
<Data Name="SubjectUserSid">S-1-5-18</Data>\
<Data Name="ObjectName">\Device\HarddiskVolume4\work\repo\.git\config</Data>\
<Data Name="ProcessId">0x1a2b</Data>\
<Data Name="AccessMask">0x2</Data>\
</EventData></Event>"#;

    #[test]
    fn xml字段提取与实体解码() {
        assert_eq!(xml_field(SAMPLE, "ObjectName").unwrap(), r"\Device\HarddiskVolume4\work\repo\.git\config");
        assert_eq!(xml_field(SAMPLE, "ProcessId").unwrap(), "0x1a2b");
        // 实体解码（含双重解码防护：&amp;lt; 不得变成 <）
        let xml = r#"<Data Name="ObjectName">C:/a &amp; b/&amp;lt;x&gt;</Data>"#;
        assert_eq!(xml_field(xml, "ObjectName").unwrap(), "C:/a & b/&lt;x>");
        // 字段缺失返回 None
        assert!(xml_field(SAMPLE, "NotExist").is_none());
    }

    #[test]
    fn 解析4663_十六进制与访问掩码() {
        let (pid, op, path) = parse_4663(SAMPLE).unwrap();
        assert_eq!(pid, 0x1a2b);
        assert_eq!(op, FILE_OP_WRITE, "AccessMask=0x2（写）");
        let nt = path.display().to_string();
        assert!(nt.contains(".git"), "NT 路径已归一（设备名无映射时原样）：{nt}");
        // 读掩码（0x1）→ Read；缺失 AccessMask 容错按读
        let read_xml = SAMPLE.replace("0x2</Data>", "0x1</Data>");
        assert_eq!(parse_4663(&read_xml).unwrap().1, FILE_OP_READ);
        let no_mask = SAMPLE.replace(r#"<Data Name="AccessMask">0x2</Data>"#, "");
        assert_eq!(parse_4663(&no_mask).unwrap().1, FILE_OP_READ);
        // 缺 ProcessId → None
        assert!(parse_4663(r#"<EventData></EventData>"#).is_none());
    }

    #[test]
    fn 监听前缀归一() {
        assert_eq!(normalize_watch(r"D:\Work\Repo\.git\"), "d:/work/repo/.git");
        assert_eq!(normalize_watch("D:/x/.git"), "d:/x/.git");
    }

    /// 前缀过滤矩阵（纯逻辑；watch 与已归一路径均为小写正斜杠）。
    #[test]
    fn 前缀过滤矩阵() {
        let watch = normalize_watch(r"D:\work\repo\.git");
        let hit = |p: &str| path_watch_hit(p, &watch);
        assert!(hit("d:/work/repo/.git"), "目录本身命中（SACL 在目录上时 4663 亦上报目录访问）");
        assert!(hit("d:/work/repo/.git/config"));
        assert!(hit("d:/work/repo/.git/objects/ab/cdef"));
        assert!(!hit("d:/work/repo/.git-backup/config"), "分量边界：不误命中同名前缀目录");
        assert!(!hit("d:/other/.git/config"));
        assert!(!hit("d:/work/repo"));
    }
}
