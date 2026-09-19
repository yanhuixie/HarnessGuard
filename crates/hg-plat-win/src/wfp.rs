//! WFP 用户态封禁（技术设计 §5.1 原文：`FwpmFilterAdd0` 子层 BLOCK + TTL 过期；
//! M1 偏差表归位项——netsh 临时规则过渡至此替换）。
//!
//! 实现：**动态会话**（FWPM_SESSION_FLAG_DYNAMIC）——过滤器随会话句柄存活，
//! 会话关闭或进程退出即自动消失，无需显式删除（比 netsh TTL 删规则更稳：
//! 进程崩溃不残留规则）。自有子层（固定 GUID）一次装配，已存在时幂等容忍。
//!
//! 失败兜底：BFE 服务不可用等场景回落 netsh 临时规则（M1 行为），不留处置空档。
//! **编译级验证，未运行时验证（需管理员实机 + WFP 子层装配复验）**，M4 报告披露。

use std::net::IpAddr;
use std::time::Duration;

use windows::core::{w, GUID, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmSubLayerAdd0, FWP_ACTION_BLOCK,
    FWP_EMPTY, FWP_MATCH_EQUAL, FWPM_SESSION_FLAG_DYNAMIC, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWPM_ACTION0, FWPM_ACTION0_0,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION0,
    FWPM_SUBLAYER0, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_VALUE0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

/// HarnessGuard 自有子层 GUID（固定值：跨封禁复用；已存在时容忍 ALREADY_EXISTS）
const SUBLAYER_GUID: GUID = GUID::from_u128(0x9d3f1a4c62be4f0a9c853a71e0d2b8f4);

/// 阻断指定远端 IP 的出站连接，`ttl` 到期后解封。
///
/// 调用约定：在独立线程内运行（含 `ttl` 睡眠）；返回 Ok 时解封已完成，
/// 返回 Err 表示 WFP 链路失败（调用方回落 netsh）。
pub fn block_endpoint_wfp(ip: IpAddr, ttl: Duration) -> anyhow::Result<()> {
    unsafe {
        // 1. 动态会话：句柄关闭/进程退出 → 过滤器自动移除
        let sess = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let mut engine = HANDLE(std::ptr::null_mut());
        let rc = FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, Some(&sess), &mut engine);
        if rc != 0 {
            anyhow::bail!("FwpmEngineOpen0 rc={rc:#x}（BFE 未运行？）");
        }
        let r = block_with_engine(engine, ip, ttl);
        // 引擎句柄关闭即解封（动态会话语义）
        let _ = FwpmEngineClose0(engine);
        r
    }
}

unsafe fn block_with_engine(engine: HANDLE, ip: IpAddr, ttl: Duration) -> anyhow::Result<()> {
    // 2. 子层装配（幂等：已存在容忍；WFP 只读复制显示名，静态宽字符足够）
    let sub = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_GUID,
        displayData: FWPM_DISPLAY_DATA0 {
            name: PWSTR(w!("HarnessGuard 封禁子层").as_ptr() as *mut _),
            description: PWSTR::null(),
        },
        ..Default::default()
    };
    let rc = FwpmSubLayerAdd0(engine, &sub, None);
    if rc != 0 && rc != windows::Win32::Foundation::FWP_E_ALREADY_EXISTS.0 as u32 {
        anyhow::bail!("FwpmSubLayerAdd0 rc={rc:#x}");
    }

    // 3. 过滤器：ALE_AUTH_CONNECT（出站连接授权层）+ 远端地址精确匹配 + BLOCK。
    //    地址结构须存活至 FwpmFilterAdd0 返回（API 只读复制），故为局部变量。
    let mut v4 = FWP_V4_ADDR_AND_MASK { addr: 0, mask: u32::MAX };
    let mut v6 = FWP_V6_ADDR_AND_MASK { addr: [0; 16], prefixLength: 128 };
    let (layer, cond) = match ip {
        IpAddr::V4(a) => {
            v4.addr = u32::from(a);
            (
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWP_CONDITION_VALUE0 {
                    r#type: FWP_V4_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: &mut v4 },
                },
            )
        }
        IpAddr::V6(a) => {
            v6.addr = a.octets();
            (
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                FWP_CONDITION_VALUE0 {
                    r#type: FWP_V6_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 { v6AddrMask: &mut v6 },
                },
            )
        }
    };
    let conds = [FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: cond,
    }];
    let filter = FWPM_FILTER0 {
        layerKey: layer,
        subLayerKey: SUBLAYER_GUID,
        displayData: FWPM_DISPLAY_DATA0 {
            name: PWSTR(w!("HarnessGuard 临时封禁").as_ptr() as *mut _),
            description: PWSTR::null(),
        },
        numFilterConditions: conds.len() as u32,
        filterCondition: conds.as_ptr() as *mut _,
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            // 非 callout 动作：filterType 置零 GUID（SDK 约定）
            Anonymous: FWPM_ACTION0_0 { filterType: GUID::from_u128(0) },
        },
        weight: FWP_VALUE0 { r#type: FWP_EMPTY, ..Default::default() },
        ..Default::default()
    };
    let mut filter_id = 0u64;
    let rc = FwpmFilterAdd0(engine, &filter, None, Some(&mut filter_id));
    if rc != 0 {
        anyhow::bail!("FwpmFilterAdd0 rc={rc:#x}");
    }
    tracing::info!("[wfp] 过滤器 id={filter_id} 已装（{ip} 出站阻断，动态会话）");

    // 4. TTL 到期自然返回 → 调用方关闭引擎句柄 → 过滤器随之消失
    std::thread::sleep(ttl);
    tracing::info!("[wfp] 过滤器 id={filter_id} TTL 到期解封");
    Ok(())
}
