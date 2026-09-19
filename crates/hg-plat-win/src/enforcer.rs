//! Windows 处置动作（技术设计 §5.1）：
//! - 杀进程：OpenProcess + TerminateProcess（校验 start_time 防 pid 复用）；
//! - 断连接：SetTcpEntry（MIB_TCP_STATE_DELETE_TCB）。IPv6 的 SetTcp6Entry 在
//!   windows crate 0.61 未导出——M1 显式不支持并报错（演示为 IPv4），M4 直调 iphlpapi 补；
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
        if matches!(
            (quad.local.ip(), quad.remote.ip()),
            (std::net::IpAddr::V6(_), _) | (_, std::net::IpAddr::V6(_))
        ) {
            anyhow::bail!("IPv6 断连接（SetTcp6Entry）在 windows 0.61 未导出，M4 补直调 iphlpapi")
        }
        let row = build_tcp_row_v4(&quad)?;
        let rc = unsafe { SetTcpEntry(&row) };
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
