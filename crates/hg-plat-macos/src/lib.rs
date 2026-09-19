//! macOS 平台适配（技术设计 §5.3）。
//!
//! 计划落地的能力（实际代码随第五步/M3 预写进入，全部
//! `#[cfg(target_os = "macos")]` 门控）：
//! - 进程/文件事件：手写 /dev/auditpipe（AUDITPIPE_SET_PRESELECT_MODE ioctl
//!   预选 EX/FC 类 + BSM token 解析）——全项目最大自研点；降级 FSEvents +
//!   sysctl kinfo_proc 轮询（显式告警漏短命进程）；
//! - 网络归因：libpcap（BPF 设备）按五元组累计上行，pid 归因 proc_pidinfo/fd 扫描；
//! - DNS：libpcap BPF 过滤 port 53；
//! - 持久化：FSEvents 监控 LaunchAgents / LaunchDaemons 目录；
//! - 处置：tcpdrop 四元组掐连接、pfctl 封 IP、kill（事后秒级，需求 §5 能力阶梯）；
//! - 通知会话桥：per-user LaunchAgent 轻量代理监听 unix domain socket。
//!
//! 双架构注意（硬约束 4）：Intel（x86_64）与 Apple Silicon（aarch64）发布各自
//! 原生二进制；auditpipe/BSM 的 FFI 类型按两架构 ABI 校验，禁止假设仅单架构
//! 可用的方案；架构相关差异写入实现处注释。
//!
// 未编译验证：本 crate 实际 macOS 实现待 macOS 环境确认；当前为骨架占位，
// Windows 构建只编译下方跨平台占位内容。

pub fn describe() -> &'static str {
    "hg-plat-macos：auditpipe + libpcap + tcpdrop/pf 处置（M3，仅编写不编译）"
}
