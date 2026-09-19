// 未编译验证：待 macOS 环境确认（技术任务硬约束 3/4）。
//! macOS 处置（技术设计 §5.3，事后秒级）：
//! - 杀进程：kill(SIGKILL) + start_time 校验（sysctl kinfo_proc p_starttime）；
//! - 断连接：`tcpdrop <laddr> <lport> <raddr> <rport>`（四元组掐连接，设计选型）；
//! - 封 IP：pfctl 表 + 规则（`harnessguard` 锚点，TTL 由用户态到期删表项）。

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use hg_model::{Pid, StartTime, TcpQuad};
use hg_platform::Enforcer;

const PF_ANCHOR: &str = "harnessguard";

#[derive(Default)]
pub struct MacEnforcer;

impl MacEnforcer {
    pub fn new() -> Self {
        Self
    }
}

impl Enforcer for MacEnforcer {
    fn kill_process(&self, pid: Pid, start_time: StartTime) -> anyhow::Result<()> {
        let current = kinfo_starttime(pid);
        if start_time.0 != 0 && current.is_some() && current != Some(start_time.0) {
            anyhow::bail!("pid {pid} 已被复用（start_time 不匹配），跳过处置");
        }
        let rc = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        if rc != 0 {
            anyhow::bail!("kill({pid}) errno={}", std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
        Ok(())
    }

    fn drop_tcp(&self, quad: TcpQuad) -> anyhow::Result<()> {
        let out = std::process::Command::new("tcpdrop")
            .args([
                quad.local.ip().to_string(),
                quad.local.port().to_string(),
                quad.remote.ip().to_string(),
                quad.remote.port().to_string(),
            ])
            .output()?;
        if !out.status.success() {
            anyhow::bail!("tcpdrop 失败: {}", String::from_utf8_lossy(&out.stderr));
        }
        Ok(())
    }

    fn block_endpoint_temporary(&self, ip: IpAddr, ttl: Duration) -> anyhow::Result<()> {
        if ip.is_loopback() {
            tracing::warn!("block_ip 跳过回环地址 {ip}");
            return Ok(());
        }
        // pf 锚点 + 表（安装器预置 /etc/pf.anchors/harnessguard；未预置时即时创建）
        let anchor_file = format!("/etc/pf.anchors/{PF_ANCHOR}");
        if !std::path::Path::new(&anchor_file).exists() {
            std::fs::write(&anchor_file, format!("table <{PF_ANCHOR}> persist\0"))?;
            let _ = std::process::Command::new("pfctl")
                .args(["-a", PF_ANCHOR, "-f", &anchor_file])
                .output();
        }
        let out = std::process::Command::new("pfctl")
            .args(["-a", PF_ANCHOR, "-t", PF_ANCHOR, "-T", "add", &ip.to_string()])
            .output()?;
        if !out.status.success() {
            anyhow::bail!("pfctl add 失败: {}", String::from_utf8_lossy(&out.stderr));
        }
        // TTL 到期删表项（双架构线程语义一致）
        std::thread::spawn(move || {
            std::thread::sleep(ttl);
            let _ = std::process::Command::new("pfctl")
                .args(["-a", PF_ANCHOR, "-t", PF_ANCHOR, "-T", "delete", &ip.to_string()])
                .output();
        });
        Ok(())
    }
}

/// sysctl kern.proc.pid → p_starttime（秒级，Unix epoch；与事件源归一时基在 M3 统一）。
fn kinfo_starttime(pid: Pid) -> Option<u64> {
    #[repr(C)]
    #[derive(Default)]
    struct KInfoProc {
        /// struct extern_proc 前 15 个指针字段 + p_starttime（tv_sec, tv_usec）
        _opaque: [u64; 15],
        start_sec: u64,
        start_usec: u64,
    }
    let name: [libc::c_int; 4] = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid as libc::c_int];
    let mut kp = KInfoProc::default();
    let mut len = std::mem::size_of::<KInfoProc>();
    let rc = unsafe {
        libc::sysctl(
            name.as_ptr(), 4,
            &mut kp as *mut _ as *mut core::ffi::c_void, &mut len,
            std::ptr::null(), 0,
        )
    };
    if rc != 0 {
        return None;
    }
    Some(kp.start_sec)
}

#[allow(dead_code)]
fn now_secs() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
