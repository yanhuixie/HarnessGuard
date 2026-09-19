//! Windows 平台适配（技术设计 §5.1）。
//!
//! 计划落地的能力（当前骨架仅描述职责，实现随 M0 spike / M1 端到端进入）：
//! - 事件源：ferrisetw 消费 ETW Kernel-Process / Kernel-File / Kernel-Network /
//!   Dns-Client / TaskScheduler-Operational；FileObject→Name 关联缓存；
//! - 处置：TerminateProcess（校验 start_time）/ SetTcpEntry+SetTcp6Entry（断连接）/
//!   FwpmFilterAdd0 子层 BLOCK + TTL（封 IP，无需驱动）；
//! - 宿主：windows-service 服务封装 + 恢复策略；
//! - 通知会话桥：WTSEnumerateSessions → WTSQueryUserToken → CreateProcessAsUser
//!   拉起一次性 Toast 代理（技术设计 §8.1）。

pub fn describe() -> &'static str {
    "hg-plat-win：ETW 事件源 + 杀进程/断连接/WFP 封禁处置（M0 spike → M1 端到端）"
}
