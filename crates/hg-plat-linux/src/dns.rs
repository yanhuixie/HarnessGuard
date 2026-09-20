// 未编译验证：待 Linux 环境确认（技术任务硬约束 3）。
//! DNS 观测（技术设计 §5.2）：AF_PACKET 抓 UDP:53（明文 DNS）。
//! DoH/DoT 下域名→IP 关联失效，端点判定退化按 IP（需求 §1.2 已声明）。
//! 解析为最小实现：header + question qname + answer A/AAAA。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hg_model::{Envelope, RawEvent, Timestamp};
use tokio::sync::mpsc;

pub struct DnsSource {
    tx: mpsc::Sender<Envelope>,
    base: std::time::Instant,
}

impl DnsSource {
    pub fn new(tx: mpsc::Sender<Envelope>) -> Self {
        Self {
            tx,
            base: std::time::Instant::now(),
        }
    }

    fn now(&self) -> Timestamp {
        Timestamp(self.base.elapsed().as_millis() as u64)
    }

    /// 在指定接口（或 Any）上嗅探 UDP:53。需要 root。
    pub fn run(&self, ifindex: u32) -> anyhow::Result<()> {
        // AF_PACKET(SOCK_RAW) + htons(ETH_P_ALL)；按接口绑定（0=Any）
        const SOCK_RAW: libc::c_int = 3;
        const SOCK_NONBLOCK: libc::c_int = 0o4000;
        const SOCK_CLOEXEC: libc::c_int = 0o2000000;
        let proto = u16::to_be(3u16) as libc::c_int; // ETH_P_ALL 网络序
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                proto,
            )
        };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "AF_PACKET socket 失败 errno={}",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            ));
        }
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = proto as u16;
        sll.sll_ifindex = ifindex as i32;
        let rc = unsafe {
            libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if rc != 0 {
            unsafe { libc::close(fd) };
            return Err(anyhow::anyhow!(
                "AF_PACKET bind 失败 errno={}",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            ));
        }
        let mut buf = [0u8; 65536];
        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if e == libc::EAGAIN {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                if e == libc::EINTR {
                    continue;
                }
                tracing::error!("AF_PACKET read errno={e}");
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
            // Ethernet(14) + IPv4(20)/IPv6(40) + UDP(8) + DNS
            if let Some((payload, _)) = parse_eth_udp_port53(&buf[..n as usize]) {
                if let Some((qname, answers, is_response)) = parse_dns(payload) {
                    if is_response {
                        // pid 归因：DNS 由 stub resolver（systemd-resolved）代发，
                        // 精确 pid 需 conntrack 关联——M2 校准项；暂 0（引擎容忍）
                        let _ = self.tx.try_send(Envelope::new(
                            self.now(),
                            RawEvent::DnsQuery {
                                pid: 0,
                                qname,
                                answers,
                            },
                        ));
                    }
                }
            }
        }
    }
}

/// 以太网帧 → UDP 且 src/dst 端口为 53 → 返回（载荷, 方向）。
fn parse_eth_udp_port53(frame: &[u8]) -> Option<(&[u8], bool)> {
    if frame.len() < 14 + 20 + 8 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let (ip_off, is_v4) = match ethertype {
        0x0800 => (14, true),
        0x86DD => (14, false),
        _ => return None,
    };
    let ihl_size = if is_v4 {
        ((frame[ip_off] & 0x0f) as usize) * 4
    } else {
        40
    };
    let udp = ip_off + ihl_size;
    if frame.len() < udp + 8 {
        return None;
    }
    let sport = u16::from_be_bytes([frame[udp], frame[udp + 1]]);
    let dport = u16::from_be_bytes([frame[udp + 2], frame[udp + 3]]);
    let is_response = sport == 53;
    if sport != 53 && dport != 53 {
        return None;
    }
    let len = u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]) as usize;
    let payload_start = udp + 8;
    let payload_end = (payload_start + len.saturating_sub(8)).min(frame.len());
    Some((&frame[payload_start..payload_end], is_response))
}

fn parse_dns(p: &[u8]) -> Option<(String, Vec<IpAddr>, bool)> {
    if p.len() < 12 {
        return None;
    }
    let qr = p[2] & 0x80 != 0;
    let qdcount = u16::from_be_bytes([p[4], p[5]]) as usize;
    let ancount = u16::from_be_bytes([p[6], p[7]]) as usize;
    let mut off = 12usize;
    // 跳过 question 区并取 qname（不处理压缩指针——query 区指针只指向自身之前，安全）
    let mut qname = String::new();
    for _ in 0..qdcount {
        loop {
            let l = *p.get(off)? as usize;
            off += 1;
            if l == 0 {
                break;
            }
            if l & 0xC0 != 0 {
                return None; // 指针（异常路径，容忍丢弃）
            }
            let seg = p.get(off..off + l)?;
            if !qname.is_empty() {
                qname.push('.');
            }
            qname.push_str(&String::from_utf8_lossy(seg));
            off += l;
        }
        off += 4; // qtype + qclass
    }
    let mut answers = Vec::new();
    for _ in 0..ancount {
        // name（可能压缩指针）
        let l = *p.get(off)? as usize;
        off += 1;
        if l & 0xC0 != 0 {
            off += 1; // 指针两字节
        } else {
            // 非指针 name 逐标签
            let mut ll = l;
            while ll != 0 {
                off += ll;
                ll = *p.get(off)? as usize;
                off += 1;
            }
        }
        let rtype = u16::from_be_bytes([*p.get(off)?, *p.get(off + 1)?]);
        let rdlen = u16::from_be_bytes([*p.get(off + 8)?, *p.get(off + 9)?]) as usize;
        let rd = off + 10;
        match rtype {
            1 if rdlen == 4 => {
                let o = p.get(rd..rd + 4)?;
                answers.push(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])));
            }
            28 if rdlen == 16 => {
                let o = p.get(rd..rd + 16)?;
                let mut a = [0u8; 16];
                a.copy_from_slice(o);
                answers.push(IpAddr::V6(Ipv6Addr::from(a)));
            }
            _ => {}
        }
        off = rd + rdlen;
    }
    Some((qname, answers, qr))
}
