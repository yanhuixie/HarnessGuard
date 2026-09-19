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
        let (IpAddr::V4(l), IpAddr::V4(r)) = (quad.local.ip(), quad.remote.ip()) else {
            anyhow::bail!("IPv6 断连接（SetTcp6Entry）在 windows 0.61 未导出，M4 补直调 iphlpapi")
        };
        use windows::Win32::NetworkManagement::IpHelper::{
            SetTcpEntry, MIB_TCPROW_LH, MIB_TCPROW_LH_0,
        };
        // MIB 约定：地址与端口均为网络字节序，端口占 DWORD 低 16 位
        // （评审修正：原 (port as u32).swap_bytes() 把端口放进了高 16 位）
        let net_port = |p: u16| -> u32 { (((p & 0xff) as u32) << 8) | ((p >> 8) as u32) };
        let row = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 { dwState: MIB_TCP_STATE_DELETE_TCB },
            dwLocalAddr: u32::from(l).swap_bytes(),
            dwLocalPort: net_port(quad.local.port()),
            dwRemoteAddr: u32::from(r).swap_bytes(),
            dwRemotePort: net_port(quad.remote.port()),
        };
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
