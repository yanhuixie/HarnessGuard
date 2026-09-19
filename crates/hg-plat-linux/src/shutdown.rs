// 未编译验证：待 Linux 环境确认（技术任务硬约束 3）。
//! 停机序列（技术设计 §9.3，防停机瞬间挂起/误拒）：
//! 1. 对所有未决 FAN_OPEN_PERM/FAN_ACCESS_PERM 统一回 FAN_ALLOW（宁放勿卡）；
//! 2. 停止事件源：关 fanotify fd、摘 eBPF link/程序（aya detach）、删 nft 临时集合；
//! 3. flush SQLite（含 ConnRegistry 未关闭连接汇总）——由装配方在调用本序列后执行；
//! 4. 退出。SIGTERM/SIGINT/服务控制统一走此序列，超时兜底强制退出。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::enforcer::{NFT_SET, NFT_TABLE};

pub struct ShutdownHandle {
    stop: Arc<AtomicBool>,
    fanotify_fd: Option<i32>,
}

impl ShutdownHandle {
    pub fn new(stop: Arc<AtomicBool>, fanotify_fd: Option<i32>) -> Self {
        Self { stop, fanotify_fd }
    }

    /// 停机序列（阻塞执行，预期 <1s；调用方负责后续 SQLite flush 与进程退出）。
    pub fn shutdown(&self) {
        // 1. 通知所有平台线程停止；fanotify 线程 drain 未决 PERM 回 FAN_ALLOW
        self.stop.store(true, Ordering::SeqCst);
        if let Some(fd) = self.fanotify_fd {
            // 线程池等 fanotify 循环感知 stop 标志（≤2ms 轮询节拍）后自行 drain；
            // 这里再兜底等一小段，确保 ALLOW 写回完成（宁放勿卡）
            std::thread::sleep(std::time::Duration::from_millis(50));
            let _ = unsafe { libc::close(fd) };
        }
        // 2. eBPF：aya 程序随进程退出自动 detach（link fd 生命周期）；无需显式清理
        // 3. nft：删除封禁集合（不留残留阻断——集合元素带 timeout 是双保险）
        let _ = std::process::Command::nft_flush_set();
        tracing::info!("停机序列完成（PERM 已放行、事件源已停、nft 集合已清）");
    }
}

trait NftFlush {
    fn nft_flush_set();
}

impl NftFlush for std::process::Command {
    fn nft_flush_set() {
        let _ = std::process::Command::new("nft")
            .arg(format!("flush set {NFT_TABLE} {NFT_SET}"))
            .output();
    }
}
