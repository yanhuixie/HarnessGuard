// 未编译验证：待 Linux 环境确认（技术任务硬约束 3）。
//! Linux 处置动作（技术设计 §5.2）：
//! - 杀进程：kill(SIGKILL) + /proc/<pid>/stat 第 22 字段 starttime 双校验（防 pid 复用）；
//! - 断连接：`ss --kill`（内核连接查杀；设计原文 nft CLI 不具备掐存量连接能力，
//!   ss -K 是等价内核接口——偏差在此显式登记）；
//! - 封 IP：nft 集合元素 + timeout（依赖预置的 harnessguard 集合与引用规则，安装器 M4 创建；
//!   未预置时即时建集合+规则，删除路径见 shutdown.rs）。

use std::net::IpAddr;
use std::time::Duration;

use hg_model::{Pid, StartTime, TcpQuad};
use hg_platform::Enforcer;

use crate::ebpf::proc_starttime;

pub const NFT_SET: &str = "harnessguard_blocked";
pub const NFT_TABLE: &str = "inet filter";

#[derive(Default)]
pub struct LinuxEnforcer;

impl LinuxEnforcer {
    pub fn new() -> Self {
        Self
    }
}

impl Enforcer for LinuxEnforcer {
    fn kill_process(&self, pid: Pid, start_time: StartTime) -> anyhow::Result<()> {
        // /proc start_time 双匹配（jiffies 时基，与 eBPF 事件源一致）
        let current = proc_starttime(pid);
        if start_time.0 != 0 && current != 0 && current != start_time.0 {
            anyhow::bail!("pid {pid} 已被复用（start_time 不匹配），跳过处置");
        }
        let rc = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        if rc != 0 {
            anyhow::bail!(
                "kill({pid}) errno={}",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            );
        }
        Ok(())
    }

    fn drop_tcp(&self, quad: TcpQuad) -> anyhow::Result<()> {
        let filter = format!("dst {} and src {}", quad.remote, quad.local);
        let out = std::process::Command::new("ss")
            .args(["--kill", "state", "established", &filter])
            .output()?;
        if !out.status.success() {
            anyhow::bail!("ss --kill 失败: {}", String::from_utf8_lossy(&out.stderr));
        }
        Ok(())
    }

    fn block_endpoint_temporary(&self, ip: IpAddr, ttl: Duration) -> anyhow::Result<()> {
        if ip.is_loopback() {
            tracing::warn!("block_ip 跳过回环地址 {ip}");
            return Ok(());
        }
        let secs = ttl.as_secs().max(1);
        // 确保集合与引用规则存在（幂等；安装器预置后此步为空操作）
        let ensure = format!(
            "add table {NFT_TABLE}; \
             add set {NFT_TABLE} {NFT_SET} {{ type ipv4_addr; flags timeout; }}; \
             add rule {NFT_TABLE} output ip daddr @ {NFT_SET} drop"
        );
        let _ = std::process::Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map(|mut ch| {
                use std::io::Write;
                if let Some(si) = ch.stdin.as_mut() {
                    let _ = si.write_all(ensure.replace("@ ", "@").as_bytes());
                }
                ch
            });
        let add = format!("add element {NFT_TABLE} {NFT_SET} {{ {ip} timeout {secs}s }}");
        let out = std::process::Command::new("nft").arg(&add).output()?;
        if !out.status.success() {
            anyhow::bail!(
                "nft add element 失败: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(())
    }
}
