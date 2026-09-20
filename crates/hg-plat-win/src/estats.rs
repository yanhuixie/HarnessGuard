//! 场景 C 字节计数补充路径（技术设计 §5.1"per-send bytes"；定位按 M4 复验定案修正）。
//!
//! **主路径是 ETW send 事件**（复验实证：树内 curl POST 8MB 产生 99 条 send 事件
//! 累计 5.0MB，端到端支撑阈值判定与处置）；本模块为连接级 send 事件缺失时的
//! best-effort 补充：对已登记的监控连接，按 1s 周期读内核 per-connection estats
//! 的 DataBytesOut 累计值（GetPerTcpConnectionEStats），差分出增量后以
//! `RawEvent::ConnTx` 补喂引擎（与 ETW send 事件同通道，ConnRegistry 无感知差异）。
//!
//! 本机降级（复验定案 2）：Win 26100 实测 `SetPerTcpConnectionEStats` 即
//! rc=50（ERROR_NOT_SUPPORTED），estats Data 集合整体不可用。处理：Set 失败的
//! 连接标记"estats 不可用"并**跳过后续轮询**（不逐秒空调用刷 rc 日志）。
//! 标记清理由逐轮收敛完成：被降级的连接走 Skip 路径后**看不到 Gone**
//! （ETW disconnect 侧移除 monitored_quads 时本线程不可达），因此每轮按
//! monitored_quads 快照收敛三张私有表（sampler/gate）——同四元组复用的新连接
//! 在旧条目被收敛清掉后会重新尝试一次。字节计数不受影响（send 事件为主路径）。
//! Linux/macOS 无此路径。
//!
//! 机制（M4 第一批沿用）：
//! - 首见连接 SetPerTcpConnectionEStats 开启 Data 类采集（每连接一次）；
//! - 计数器回退（复用/重置）时本轮丢弃并以新值重建基线，不伪造负增量；
//! - 行查不到（ERROR_NOT_FOUND=1168）→ 从轮询表移除（ETW disconnect 侧幂等）。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use hg_model::{ConnId, RawEvent};

use crate::etw_source::EtwInner;

/// 轮询周期：阈值检测延迟上限（需求 §5"秒级掐断"）
const POLL: Duration = Duration::from_secs(1);

/// 单连接本轮动作（[`EstatsGate::plan`] 输出）。
enum PollPlan {
    /// 跳过：Set 失败已降级（本机 NOT_SUPPORTED 场景），不再空调用
    Skip,
    /// 首见：先 Set 开启采集再 Get
    EnableAndRead,
    /// 采集已开启：直接 Get
    Read,
}

/// 轮询门控（纯逻辑，单测覆盖）：每连接的采集开启状态与降级标记。
#[derive(Default)]
struct EstatsGate {
    /// 已开启 Data 采集（Set 成功）的连接
    enabled: std::collections::HashSet<u64>,
    /// Set 失败被降级（跳过后续轮询）的连接
    unavailable: std::collections::HashSet<u64>,
}

impl EstatsGate {
    fn plan(&self, conn: u64) -> PollPlan {
        if self.unavailable.contains(&conn) {
            PollPlan::Skip
        } else if self.enabled.contains(&conn) {
            PollPlan::Read
        } else {
            PollPlan::EnableAndRead
        }
    }

    /// Set 开启失败：降级跳过（告警一次，后续轮询静默跳过）。
    fn on_set_failed(&mut self, conn: u64) {
        self.enabled.remove(&conn);
        self.unavailable.insert(conn);
    }

    /// 成功读到字节：标记采集已开启。
    fn on_read_ok(&mut self, conn: u64) {
        self.enabled.insert(conn);
    }

    /// 连接消失（ERROR_NOT_FOUND）：清全部标记（四元组复用的新连接重新走首见路径）。
    fn on_gone(&mut self, conn: u64) {
        self.enabled.remove(&conn);
        self.unavailable.remove(&conn);
    }

    /// Get 暂时失败：保留登记下轮重试（Set 可能未生效，下轮重新开启）。
    fn on_transient(&mut self, conn: u64) {
        self.enabled.remove(&conn);
    }

    /// 逐轮收敛：按 monitored_quads 快照清理已消失连接的全部标记。
    /// 被降级（Skip）的连接永远走不到 Gone 分支，disconnect 侧的移除事件
    /// 对本线程不可达——不收敛则 unavailable 无界增长（评审 M1）。
    fn retain_live(&mut self, live: &std::collections::HashSet<u64>) {
        self.enabled.retain(|k| live.contains(k));
        self.unavailable.retain(|k| live.contains(k));
    }
}

/// 累计值差分器（纯逻辑，单测覆盖）。
#[derive(Default)]
struct EstatsSampler {
    /// conn_id → 上次采样到的 DataBytesOut 累计值
    last: HashMap<u64, u64>,
}

impl EstatsSampler {
    /// 采样一轮：首见（建基线）/回退（重置重基准）返回 None；正常增长返回增量。
    fn on_sample(&mut self, conn: u64, cumulative: u64) -> Option<u64> {
        match self.last.insert(conn, cumulative) {
            Some(prev) if cumulative >= prev => Some(cumulative - prev),
            // prev > cumulative：计数器重置（连接复用/采集被关）——本轮只重建基线
            Some(_) => None,
            None => None, // 首见：建基线，不产生增量
        }
    }

    /// 连接移除（disconnect / 行查不到 / 降级）时清理基线，防泄漏。
    fn forget(&mut self, conn: u64) {
        self.last.remove(&conn);
    }

    /// 逐轮收敛：按 monitored_quads 快照清理已消失连接的基线
    /// （disconnect 侧移除对本线程不可达，否则 last 无界增长——评审 M3）。
    fn retain_live(&mut self, live: &std::collections::HashSet<u64>) {
        self.last.retain(|k, _| live.contains(k));
    }
}

/// 启动 estats 轮询线程（由 hg-app 装配，紧随 ETW 源之后）。
pub fn spawn_estats_poll(inner: std::sync::Arc<EtwInner>) {
    std::thread::Builder::new()
        .name("estats-poll".into())
        .spawn(move || {
            let mut sampler = EstatsSampler::default();
            let mut gate = EstatsGate::default();
            tracing::info!("estats 轮询已启动（周期 {POLL:?}，场景 C 补充路径；主路径为 ETW send 事件）");
            loop {
                std::thread::sleep(POLL);
                // 快照后释放分片锁：estats 系统调用不在锁内执行
                let quads: Vec<(u64, SocketAddr, SocketAddr)> = inner
                    .monitored_quads
                    .iter()
                    .map(|e| (*e.key(), e.value().0, e.value().1))
                    .collect();
                // 收敛清理（评审 M1/M3）：ETW disconnect 侧移除的连接对 Skip
                // 路径不可达，按快照收敛三张私有表，防无界增长；四元组复用的
                // 新连接在旧标记被清掉后重新走首见路径
                let live: std::collections::HashSet<u64> =
                    quads.iter().map(|(c, _, _)| *c).collect();
                gate.retain_live(&live);
                sampler.retain_live(&live);
                for (conn, local, remote) in quads {
                    let enable_first = match gate.plan(conn) {
                        PollPlan::Skip => continue,
                        PollPlan::EnableAndRead => true,
                        PollPlan::Read => false,
                    };
                    match read_bytes_out(&local, &remote, enable_first) {
                        ReadOutcome::Bytes(bytes) => {
                            gate.on_read_ok(conn);
                            if let Some(delta) = sampler.on_sample(conn, bytes) {
                                if delta > 0 {
                                    tracing::debug!("[conn-estats] conn={conn:016x} +{delta}B（轮询补计）");
                                    inner.emit(RawEvent::ConnTx {
                                        conn_id: ConnId(conn),
                                        bytes_out_delta: delta,
                                    });
                                }
                            }
                        }
                        ReadOutcome::Gone => {
                            // 连接已不存在：清轮询状态（disconnect 事件侧也会移除，幂等）
                            gate.on_gone(conn);
                            sampler.forget(conn);
                            inner.monitored_quads.remove(&conn);
                        }
                        ReadOutcome::Transient => gate.on_transient(conn),
                        ReadOutcome::SetFailed(rc) => {
                            // 本机降级（复验定案 2）：Set 失败 → 标记该连接不可用，
                            // 跳过后续轮询；每连接仅此一次告警，不逐秒刷 rc 日志
                            tracing::warn!(
                                "[conn-estats] conn={conn:016x} Set rc={rc}：estats 不可用，该连接跳过后续轮询（字节计数主路径为 ETW send 事件）"
                            );
                            gate.on_set_failed(conn);
                            sampler.forget(conn);
                        }
                    }
                }
            }
        })
        .expect("spawn estats-poll");
}

/// 读取结果：正常字节值 / 连接已消失（移除登记）/ 暂时性错误（保留登记，rc 已记日志）/
/// Set 开启失败（降级该连接）。
enum ReadOutcome {
    Bytes(u64),
    /// ERROR_NOT_FOUND：连接已不存在（表项移除）
    Gone,
    /// 其他 rc（参数/缓冲等）：保留登记下轮重试，避免瞬时错误误杀活跃连接
    Transient,
    /// Set 开启采集失败：该连接 estats 不可用（本机 NOT_SUPPORTED 场景），
    /// 采集未开启时 Get 无意义，不再调用
    SetFailed(u32),
}

/// 读一条连接的 DataBytesOut 累计值；`enable_first` 时先开启 Data 采集。
fn read_bytes_out(local: &SocketAddr, remote: &SocketAddr, enable_first: bool) -> ReadOutcome {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetPerTcp6ConnectionEStats, GetPerTcpConnectionEStats, MIB_TCP_STATE_ESTAB,
        SetPerTcp6ConnectionEStats, SetPerTcpConnectionEStats, TcpConnectionEstatsData,
    };
    // TCP_ESTATS_DATA_RW_v1 { BOOLEAN EnableCollection }；
    // ROD v1（评审修正：4 字段 24 字节）：DataBytesOut(8) + DataBytesIn(8)
    // + DataSegsOut(4) + DataSegsIn(4)——短缓冲会被内核按版本校验拒绝
    let rw_enable = [1u8];
    let mut rod = [0u8; 24];
    unsafe {
        match (local.ip(), remote.ip()) {
            (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_)) => {
                let quad = hg_model::TcpQuad { local: *local, remote: *remote };
                let Ok(row) = crate::enforcer::build_tcp_row_v4(&quad, MIB_TCP_STATE_ESTAB.0 as u32)
                else {
                    return ReadOutcome::Transient;
                };
                if enable_first {
                    let src = SetPerTcpConnectionEStats(&row, TcpConnectionEstatsData, &rw_enable, 1, 0);
                    if src != 0 {
                        // 复验定案 2：本机 Set 即 rc=50（NOT_SUPPORTED）——采集未开启，
                        // Get 无意义，降级该连接（调用方标记后跳过后续轮询）
                        return ReadOutcome::SetFailed(src);
                    }
                }
                let rc = GetPerTcpConnectionEStats(
                    &row,
                    TcpConnectionEstatsData,
                    None, 0,
                    None, 0,
                    Some(&mut rod), 1,
                );
                estats_out(rc, &rod)
            }
            (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_)) => {
                let quad = hg_model::TcpQuad { local: *local, remote: *remote };
                let Ok(row) = crate::enforcer::build_tcp_row_v6(&quad, MIB_TCP_STATE_ESTAB)
                else {
                    return ReadOutcome::Transient;
                };
                if enable_first {
                    let src = SetPerTcp6ConnectionEStats(&row, TcpConnectionEstatsData, &rw_enable, 1, 0);
                    if src != 0 {
                        return ReadOutcome::SetFailed(src);
                    }
                }
                let rc = GetPerTcp6ConnectionEStats(
                    &row,
                    TcpConnectionEstatsData,
                    None, 0,
                    None, 0,
                    Some(&mut rod), 1,
                );
                estats_out(rc, &rod)
            }
            _ => ReadOutcome::Gone,
        }
    }
}

/// 返回值统一解析：NO_ERROR=0 取 ROD 首字段；ERROR_NOT_FOUND(1168) 视为连接
/// 消失；其余 rc 记日志保留（下轮重试），防止系统性错误把活跃连接批量误删。
unsafe fn estats_out(rc: u32, rod: &[u8; 24]) -> ReadOutcome {
    if rc == 0 {
        return ReadOutcome::Bytes(u64::from_le_bytes(rod[..8].try_into().unwrap()));
    }
    if rc == 1168 {
        return ReadOutcome::Gone;
    }
    tracing::debug!("[conn-estats] Get rc={rc}（非 NOT_FOUND，保留登记下轮重试）");
    ReadOutcome::Transient
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 首见采样建基线不产生增量() {
        let mut s = EstatsSampler::default();
        assert_eq!(s.on_sample(1, 1000), None);
        assert_eq!(s.on_sample(2, 0), None);
    }

    #[test]
    fn 累计增长差分出增量() {
        let mut s = EstatsSampler::default();
        s.on_sample(1, 1000);
        assert_eq!(s.on_sample(1, 1500), Some(500));
        assert_eq!(s.on_sample(1, 8_000_000), Some(7_998_500));
    }

    #[test]
    fn 零增量返回零() {
        let mut s = EstatsSampler::default();
        s.on_sample(1, 1000);
        assert_eq!(s.on_sample(1, 1000), Some(0));
    }

    #[test]
    fn 计数器回退不伪造负增量并重建基线() {
        let mut s = EstatsSampler::default();
        s.on_sample(1, 5000);
        assert_eq!(s.on_sample(1, 100), None, "回退轮不产生增量");
        assert_eq!(s.on_sample(1, 300), Some(200), "回退后以新基线继续差分");
    }

    #[test]
    fn forget清理基线() {
        let mut s = EstatsSampler::default();
        s.on_sample(1, 1000);
        s.forget(1);
        // 再次出现视作首见：重建基线而非差分出巨额增量
        assert_eq!(s.on_sample(1, 999_999), None);
    }

    #[test]
    fn 门控_首见走开启后读_成功后直接读() {
        let mut g = EstatsGate::default();
        assert!(matches!(g.plan(1), PollPlan::EnableAndRead));
        g.on_read_ok(1);
        assert!(matches!(g.plan(1), PollPlan::Read));
    }

    #[test]
    fn 门控_set失败降级跳过() {
        let mut g = EstatsGate::default();
        g.on_set_failed(1);
        assert!(matches!(g.plan(1), PollPlan::Skip), "降级连接不再轮询");
        // 其他连接不受影响
        assert!(matches!(g.plan(2), PollPlan::EnableAndRead));
    }

    #[test]
    fn 门控_连接移除清降级标记_复用重试一次() {
        let mut g = EstatsGate::default();
        g.on_set_failed(1);
        g.on_gone(1);
        assert!(matches!(g.plan(1), PollPlan::EnableAndRead), "四元组复用的新连接重新尝试");
    }

    #[test]
    fn 门控_get暂时失败回到开启路径但不降级() {
        let mut g = EstatsGate::default();
        g.on_read_ok(1);
        g.on_transient(1);
        assert!(matches!(g.plan(1), PollPlan::EnableAndRead), "Set 重开而非直接读");
        assert!(!matches!(g.plan(1), PollPlan::Skip), "暂时性失败不降级");
    }

    #[test]
    fn 门控_逐轮收敛清理已消失连接() {
        let mut g = EstatsGate::default();
        g.on_set_failed(1); // Skip 路径：看不到 Gone，只能靠收敛清标记
        g.on_read_ok(2);
        g.on_set_failed(3);
        let live: std::collections::HashSet<u64> = [2u64, 3u64].into_iter().collect();
        g.retain_live(&live);
        assert!(matches!(g.plan(1), PollPlan::EnableAndRead), "已消失连接的降级标记被清，复用重试");
        assert!(matches!(g.plan(2), PollPlan::Read), "存活连接不受影响");
        assert!(matches!(g.plan(3), PollPlan::Skip), "存活且降级的连接保持 Skip");
    }

    #[test]
    fn 采样器_逐轮收敛清理已消失连接基线() {
        let mut s = EstatsSampler::default();
        s.on_sample(1, 1000);
        s.on_sample(2, 500);
        let live: std::collections::HashSet<u64> = [2u64].into_iter().collect();
        s.retain_live(&live);
        s.on_sample(1, 2000); // 已被收敛：视作首见重建基线
        assert_eq!(s.on_sample(1, 3000), Some(1000));
    }
}
