//! 场景 C 字节计数替代路径（M1 报告缺口 2；技术设计 §5.1"per-send bytes"在
//! 本机内核采样态下不可用——45s 全系统仅 106 条 send 事件，累计字节无法达阈值）。
//!
//! 机制：对已登记的监控连接，按 1s 周期读内核 per-connection estats 的
//! DataBytesOut 累计值（GetPerTcpConnectionEStats），差分出增量后以
//! `RawEvent::ConnTx` 补喂引擎（与 ETW send 事件同通道，ConnRegistry 无感知差异）：
//! - 首见连接 SetPerTcpConnectionEStats 开启 Data 类采集（每连接一次）；
//! - 计数器回退（复用/重置）时本轮丢弃并以新值重建基线，不伪造负增量；
//! - 行查不到（rc!=0，连接已关）→ 从轮询表移除（ETW disconnect 侧幂等）。
//!
//! v4/v6 双栈（GetPerTcp(6)ConnectionEStats 均由 windows 0.61 导出）。
//! 未运行时验证（需管理员实机），待 M4 复验。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use hg_model::{ConnId, RawEvent};

use crate::etw_source::EtwInner;

/// 轮询周期：阈值检测延迟上限（需求 §5"秒级掐断"）
const POLL: Duration = Duration::from_secs(1);

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

    /// 连接移除（disconnect / 行查不到）时清理基线，防泄漏。
    fn forget(&mut self, conn: u64) {
        self.last.remove(&conn);
    }
}

/// 启动 estats 轮询线程（由 hg-app 装配，紧随 ETW 源之后）。
pub fn spawn_estats_poll(inner: std::sync::Arc<EtwInner>) {
    std::thread::Builder::new()
        .name("estats-poll".into())
        .spawn(move || {
            let mut sampler = EstatsSampler::default();
            let mut enabled: std::collections::HashSet<u64> = std::collections::HashSet::new();
            tracing::info!("estats 轮询已启动（周期 {:?}，场景 C 字节计数替代路径）", POLL);
            loop {
                std::thread::sleep(POLL);
                // 快照后释放分片锁：estats 系统调用不在锁内执行
                let quads: Vec<(u64, SocketAddr, SocketAddr)> = inner
                    .monitored_quads
                    .iter()
                    .map(|e| (*e.key(), e.value().0, e.value().1))
                    .collect();
                for (conn, local, remote) in quads {
                    match read_bytes_out(&local, &remote, !enabled.contains(&conn)) {
                        ReadOutcome::Bytes(bytes) => {
                            enabled.insert(conn);
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
                            enabled.remove(&conn);
                            sampler.forget(conn);
                            inner.monitored_quads.remove(&conn);
                        }
                        ReadOutcome::Transient => {
                            // 保留登记（含首次 Set 失败的场景），下轮重试
                            enabled.remove(&conn); // Set 可能未生效，下轮重新开启采集
                        }
                    }
                }
            }
        })
        .expect("spawn estats-poll");
}

/// 读取结果：正常字节值 / 连接已消失（移除登记）/ 暂时性错误（保留登记，rc 已记日志）。
enum ReadOutcome {
    Bytes(u64),
    /// ERROR_NOT_FOUND：连接已不存在（表项移除）
    Gone,
    /// 其他 rc（参数/缓冲等）：保留登记下轮重试，避免瞬时错误误杀活跃连接
    Transient,
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
                        // 实机复验：Get 全败 rc=50（NOT_SUPPORTED）疑因 Set 开启失败，
                        // 记录返回值定位根因（estats Data 集合须采集开启后才可读）
                        tracing::debug!("[conn-estats] Set(v4) rc={src}（Data 采集开启失败）");
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
                        tracing::debug!("[conn-estats] Set(v6) rc={src}（Data 采集开启失败）");
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
}
