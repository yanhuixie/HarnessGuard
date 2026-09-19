//! Windows 处置动作（技术设计 §5.1）：
//! - 杀进程：OpenProcess + TerminateProcess（校验 start_time 防 pid 复用）；
//! - 断连接：SetTcpEntry（v4）。**v6 的 SetTcp6Entry 是文档幻影**：M4 实测
//!   （Win10 26100）SDK 头文件无声明、iphlpapi.lib 无符号、DLL 导出表无此名，
//!   无法直调——v6 连接级断开超出用户态文档化 API 能力，由引擎侧 Kill
//!   （socket 随进程关闭）+ 封 IP（netsh/WFP 均支持 v6）兜底；MIB_TCP6ROW
//!   行构造保留（单测覆盖布局，供平台补齐或 NSI 未公开接口评估时复用）。
//!   已登记技术设计「设计拍板记录」第 9 条。
//! - 封 IP：`netsh advfirewall` 临时出站规则 + TTL 到期移除。
//!   设计原文为用户态 WFP（FwpmFilterAdd0）；M1 以 netsh 过渡（同一防火墙栈，
//!   免 BFE 子层装配），M4 换 FwpmFilterAdd——偏差已显式登记于 M1 报告。

use std::net::IpAddr;
use std::time::Duration;

use hg_model::{Pid, StartTime, TcpQuad};
use hg_platform::Enforcer;

const MIB_TCP_STATE_DELETE_TCB: u32 = 12;

/// MIB 约定：端口以网络字节序存放于 DWORD 低 16 位，高 16 位为 0
/// （评审修正：原 (port as u32).swap_bytes() 把端口放进了高 16 位——该构造空档
/// 曾长期无单测掩盖此 bug，M4 抽为纯函数补测，见 M1 报告缺口 2）。
pub(crate) fn net_port(p: u16) -> u32 {
    (((p & 0xff) as u32) << 8) | ((p >> 8) as u32)
}

/// TCP 四元组 → `MIB_TCPROW_LH`（IPv4 断连接行）。纯函数无 IO，供单测覆盖
/// 端口字节序与字段完整性。地址按网络序内存布局（小端机器上 u32 值为八位组反转）。
pub(crate) fn build_tcp_row_v4(
    quad: &TcpQuad,
) -> anyhow::Result<windows::Win32::NetworkManagement::IpHelper::MIB_TCPROW_LH> {
    use windows::Win32::NetworkManagement::IpHelper::{MIB_TCPROW_LH, MIB_TCPROW_LH_0};
    let (l, r) = match (quad.local.ip(), quad.remote.ip()) {
        (std::net::IpAddr::V4(l), std::net::IpAddr::V4(r)) => (l, r),
        _ => anyhow::bail!("v4 行构造收到非 IPv4 四元组：{} -> {}", quad.local, quad.remote),
    };
    Ok(MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 { dwState: MIB_TCP_STATE_DELETE_TCB },
        dwLocalAddr: u32::from(l).swap_bytes(),
        dwLocalPort: net_port(quad.local.port()),
        dwRemoteAddr: u32::from(r).swap_bytes(),
        dwRemotePort: net_port(quad.remote.port()),
    })
}

/// TCP 四元组 → `MIB_TCP6ROW`（IPv6 断连接行）。纯函数无 IO，供单测覆盖。
/// scope id 恒 0：std `SocketAddr` 不携带 zone id，链路本地（fe80::/10）会因
/// scope 不匹配而失败——受控限制，外联监控目标为全局单播，不受影响。
pub(crate) fn build_tcp_row_v6(
    quad: &TcpQuad,
) -> anyhow::Result<windows::Win32::NetworkManagement::IpHelper::MIB_TCP6ROW> {
    use windows::Win32::NetworkManagement::IpHelper::{MIB_TCP6ROW, MIB_TCP_STATE_DELETE_TCB as ST_DELETE};
    use windows::Win32::Networking::WinSock::{IN6_ADDR, IN6_ADDR_0};
    let (l, r) = match (quad.local.ip(), quad.remote.ip()) {
        (IpAddr::V6(l), IpAddr::V6(r)) => (l, r),
        _ => anyhow::bail!("v6 行构造收到非 IPv6 四元组：{} -> {}", quad.local, quad.remote),
    };
    Ok(MIB_TCP6ROW {
        State: ST_DELETE,
        LocalAddr: IN6_ADDR { u: IN6_ADDR_0 { Byte: l.octets() } },
        dwLocalScopeId: 0,
        dwLocalPort: net_port(quad.local.port()),
        RemoteAddr: IN6_ADDR { u: IN6_ADDR_0 { Byte: r.octets() } },
        dwRemoteScopeId: 0,
        dwRemotePort: net_port(quad.remote.port()),
    })
}

#[derive(Default)]
pub struct WinEnforcer;

impl WinEnforcer {
    pub fn new() -> Self {
        Self
    }
}

impl Enforcer for WinEnforcer {
    fn kill_process(&self, pid: Pid, start_time: StartTime) -> anyhow::Result<()> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            GetProcessTimes, OpenProcess, TerminateProcess, PROCESS_QUERY_INFORMATION,
            PROCESS_TERMINATE,
        };
        unsafe {
            let h = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE,
                false,
                pid,
            )?;
            // pid + start_time 双匹配，防复用误杀（技术设计 §3.1）
            let mut create = windows::Win32::Foundation::FILETIME::default();
            let mut exit_t = windows::Win32::Foundation::FILETIME::default();
            let mut k = windows::Win32::Foundation::FILETIME::default();
            let mut u = windows::Win32::Foundation::FILETIME::default();
            let ok = GetProcessTimes(h, &mut create, &mut exit_t, &mut k, &mut u);
            let create_u64 =
                ((create.dwHighDateTime as u64) << 32) | create.dwLowDateTime as u64;
            if !ok.is_ok() {
                let _ = CloseHandle(h);
                anyhow::bail!("pid {pid} GetProcessTimes 失败，拒绝无校验处置");
            }
            if start_time.0 != 0 && create_u64 != start_time.0 {
                let _ = CloseHandle(h);
                anyhow::bail!("pid {pid} 已被复用（start_time 不匹配），跳过处置");
            }
            let r = TerminateProcess(h, 1);
            let _ = CloseHandle(h);
            r.map_err(|e| anyhow::anyhow!("TerminateProcess({pid}): {e}"))
        }
    }

    fn drop_tcp(&self, quad: TcpQuad) -> anyhow::Result<()> {
        use windows::Win32::NetworkManagement::IpHelper::SetTcpEntry;
        // IPv4 行构造为纯函数（单测覆盖字节序/字段完整性），失败路径统一 rc!=0
        // 报错（87=参数/连接已不存在，与 M1 行为一致）
        let rc = match (quad.local.ip(), quad.remote.ip()) {
            (IpAddr::V4(_), IpAddr::V4(_)) => {
                let row = build_tcp_row_v4(&quad)?;
                unsafe { SetTcpEntry(&row) }
            }
            (IpAddr::V6(_), IpAddr::V6(_)) => {
                // 行构造先行：校验 v6 四元组形状并保持与单测同构；随后显式报错
                // ——见文件头「文档幻影」说明（设计拍板记录第 9 条）
                let _row = build_tcp_row_v6(&quad)?;
                anyhow::bail!(
                    "IPv6 连接级断开无用户态 API：SetTcp6Entry 为文档幻影（头文件/导入库/DLL 导出均无，M4 实测）；本连接已由 Kill/封 IP 路径兜底"
                )
            }
            _ => anyhow::bail!("混合协议四元组（v4/v6 不一致）：{} -> {}", quad.local, quad.remote),
        };
        if rc == 0 {
            Ok(())
        } else {
            anyhow::bail!("SetTcpEntry 失败 rc={rc}（87=参数/连接已不存在）")
        }
    }

    fn block_endpoint_temporary(&self, ip: IpAddr, ttl: Duration) -> anyhow::Result<()> {
        // 回环不封禁（会切断本机服务通信），只做连接级处置
        if ip.is_loopback() {
            tracing::warn!("block_ip 跳过回环地址 {ip}");
            return Ok(());
        }
        let rule = format!("HarnessGuard-block-{}", ip.to_string().replace(':', "-"));
        std::thread::spawn(move || {
            let add = std::process::Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={rule}"),
                    "dir=out", "action=block",
                    &format!("remoteip={ip}"),
                ])
                .output();
            match add {
                Ok(o) if o.status.success() => {}
                e => tracing::error!("netsh 添加封禁规则失败: {e:?}"),
            }
            std::thread::sleep(ttl);
            let del = std::process::Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule", &format!("name={rule}")])
                .output();
            if let Ok(o) = &del {
                if !o.status.success() {
                    tracing::error!("netsh 移除封禁规则失败: {}", String::from_utf8_lossy(&o.stderr));
                }
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn quad_v4(la: [u8; 4], lp: u16, ra: [u8; 4], rp: u16) -> TcpQuad {
        TcpQuad {
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(la)), lp),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ra)), rp),
        }
    }

    /// 端口字节序：8080=0x1F90 → 网络序内存 [0x1F,0x90] → DWORD 低 16 位 0x901F；
    /// 高 16 位必须为 0（历史 bug：swap_bytes(u32) 把端口放进高 16 位）。
    #[test]
    fn v4_行构造_端口网络序且低位存放() {
        let row =
            build_tcp_row_v4(&quad_v4([192, 168, 1, 10], 8080, [1, 2, 3, 4], 443)).unwrap();
        assert_eq!(row.dwLocalPort, 0x0000_901F, "本地端口 8080 应编码为低 16 位 0x901F");
        assert_eq!(row.dwRemotePort, 0x0000_BB01, "远端端口 443(0x01BB) 应编码为 0xBB01");
    }

    #[test]
    fn v4_行构造_端口边界值() {
        let zero = build_tcp_row_v4(&quad_v4([10, 0, 0, 1], 0, [10, 0, 0, 2], 65535)).unwrap();
        assert_eq!(zero.dwLocalPort, 0);
        assert_eq!(zero.dwRemotePort, 0xFFFF);
    }

    /// 地址按网络序内存布局断言（to_le_bytes 即逐字节内存视角），并核全部 5 个字段，
    /// 防本地/远端串位与状态遗漏。
    #[test]
    fn v4_行构造_地址网络序与字段完整性() {
        let row =
            build_tcp_row_v4(&quad_v4([192, 168, 1, 10], 8080, [1, 2, 3, 4], 443)).unwrap();
        assert_eq!(row.dwLocalAddr.to_le_bytes(), [192, 168, 1, 10]);
        assert_eq!(row.dwRemoteAddr.to_le_bytes(), [1, 2, 3, 4]);
        assert_eq!(unsafe { row.Anonymous.dwState }, MIB_TCP_STATE_DELETE_TCB);
    }

    #[test]
    fn v4_行构造_混合或v6四元组应报错() {
        let mixed = TcpQuad {
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            remote: SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 1),
        };
        assert!(build_tcp_row_v4(&mixed).is_err());
    }

    fn quad_v6(l: std::net::Ipv6Addr, lp: u16, r: std::net::Ipv6Addr, rp: u16) -> TcpQuad {
        TcpQuad {
            local: SocketAddr::new(IpAddr::V6(l), lp),
            remote: SocketAddr::new(IpAddr::V6(r), rp),
        }
    }

    /// IPv6 quad：地址八位组原样入 IN6_ADDR（本就是网络序内存布局），本地/远端
    /// 互不串位；端口编码同 v4 约定（低 16 位、网络序）。
    #[test]
    fn v6_行构造_地址八位组与端口网络序() {
        let l = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let r = std::net::Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let row = build_tcp_row_v6(&quad_v6(l, 49152, r, 853)).unwrap();
        assert_eq!(unsafe { row.LocalAddr.u.Byte }, l.octets());
        assert_eq!(unsafe { row.RemoteAddr.u.Byte }, r.octets());
        assert_eq!(row.dwLocalPort, 0x0000_00C0, "49152(0xC000) → 低 16 位 0x00C0");
        assert_eq!(row.dwRemotePort, 0x0000_5503, "853(0x0355) → 低 16 位 0x5503");
    }

    #[test]
    fn v6_行构造_字段完整性() {
        let row = build_tcp_row_v6(&quad_v6(
            std::net::Ipv6Addr::LOCALHOST,
            1,
            std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
            2,
        ))
        .unwrap();
        assert_eq!(row.State.0, 12, "状态须为 MIB_TCP_STATE_DELETE_TCB");
        assert_eq!(row.dwLocalScopeId, 0);
        assert_eq!(row.dwRemoteScopeId, 0);
    }

    #[test]
    fn v6_行构造_非v6四元组应报错() {
        assert!(build_tcp_row_v6(&quad_v4([1, 2, 3, 4], 1, [5, 6, 7, 8], 2)).is_err());
    }

    /// kill 对已退出 pid 的错误路径：OpenProcess 对无存活引用的已退出 pid 失败，
    /// kill_process 必须返回 Err——禁止把失败伪装成成功（M1 缺口 3 的回归测试）。
    /// 说明：测试窗口内 pid 复用理论上存在但概率可忽略；若复现为活进程则本测试失败暴露。
    #[test]
    fn kill_对已退出pid_报错而非伪成功() {
        let mut child = std::process::Command::new("cmd")
            .args(["/c", "exit"])
            .spawn()
            .expect("spawn cmd 失败");
        let pid = child.id();
        let _ = child.wait();
        let r = WinEnforcer::new().kill_process(pid, StartTime(0));
        assert!(r.is_err(), "对已退出 pid {pid} 的 kill 应返回 Err，实际 Ok");
    }
}
