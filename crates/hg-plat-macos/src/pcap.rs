// 未编译验证：待 macOS 环境确认（技术任务硬约束 3/4）。
//! libpcap 网络事件源（技术设计 §5.3）：BPF 设备（root）按五元组累计上行 + 抓 UDP:53。
//! FFI 直连系统 libpcap.dylib（无第三方 binding 依赖）；双架构 ABI 一致。
//! pid 归因：lsof -nP -i4TCP -Fpcn 定期采样（进程×连接对）——M3 校准项；
//! 精确路径（proc_pidinfo + fd 扫描）为升级项。

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hg_model::{ConnId, Envelope, Pid, Proto, RawEvent, StartTime, Timestamp};
use tokio::sync::mpsc;

// libpcap FFI
#[allow(non_camel_case_types)]
type pcap_t = *mut core::ffi::c_void;
type bpf_u_int32 = u32;

#[repr(C)]
struct pcap_pkthdr {
    ts: libc::timeval,
    caplen: bpf_u_int32,
    len: bpf_u_int32,
}

extern "C" {
    fn pcap_open_live(
        device: *const libc::c_char,
        snaplen: libc::c_int,
        promisc: libc::c_int,
        to_ms: libc::c_int,
        errbuf: *mut libc::c_char,
    ) -> pcap_t;
    fn pcap_setdirection(p: pcap_t, d: libc::c_int) -> libc::c_int; // 1=PCAP_D_IN（仅收方向）
    fn pcap_compile(
        p: pcap_t,
        fp: *mut core::ffi::c_void,
        str_: *const libc::c_char,
        optimize: libc::c_int,
        netmask: bpf_u_int32,
    ) -> libc::c_int;
    fn pcap_setfilter(p: pcap_t, fp: *mut core::ffi::c_void) -> libc::c_int;
    fn pcap_next_ex(p: pcap_t, hdr: *mut *mut pcap_pkthdr, data: *mut *const u8) -> libc::c_int;
    fn pcap_close(p: pcap_t);
}

/// 连接累计表：五元组 → 上行字节（内存完成判定，不依赖 SQLite）。
pub struct PcapSource {
    tx: mpsc::Sender<Envelope>,
    base: std::time::Instant,
    /// quad → pid 采样（lsof 周期刷新）；Arc 使刷新线程可不借用 self 运行
    quad_pid: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), Pid>>>,
    emitted: dashmap_like::DashSetU64,
}

// 极简 DashSet 替身（macOS 侧不引 dashmap 依赖；M3 首编时可换）
mod dashmap_like {
    use std::sync::Mutex;
    pub struct DashSetU64(Mutex<std::collections::HashSet<u64>>);
    impl DashSetU64 {
        pub fn new() -> Self {
            Self(Mutex::new(std::collections::HashSet::new()))
        }
        pub fn insert(&self, v: u64) -> bool {
            self.0.lock().unwrap().insert(v)
        }
    }
}

impl PcapSource {
    pub fn new(tx: mpsc::Sender<Envelope>) -> Self {
        Self {
            tx,
            base: std::time::Instant::now(),
            quad_pid: Arc::new(Mutex::new(HashMap::new())),
            emitted: dashmap_like::DashSetU64::new(),
        }
    }

    fn now(&self) -> Timestamp {
        Timestamp(self.base.elapsed().as_millis() as u64)
    }

    /// en0 + 回环双路抓包：`tcp or udp port 53`（IPv4/IPv6 均覆盖）。
    pub fn run(&self, device: &str) -> anyhow::Result<()> {
        let mut errbuf = [0i8; 256];
        let dev_c = CString::new(device)?;
        let p = unsafe { pcap_open_live(dev_c.as_ptr(), 128, 0, 100, errbuf.as_mut_ptr()) };
        if p.is_null() {
            return Err(anyhow::anyhow!(
                "pcap_open_live({device}) 失败：{}",
                unsafe { CStr::from_ptr(errbuf.as_ptr()).to_string_lossy() }
            ));
        }
        unsafe {
            pcap_setdirection(p, 1);
            let mut fp = [0u8; 64]; // bpf_program 结构（M3 按头文件精确布局）
            let filter = CString::new("tcp or udp port 53")?;
            if pcap_compile(p, fp.as_mut_ptr().cast(), filter.as_ptr(), 1, 0) == 0 {
                pcap_setfilter(p, fp.as_mut_ptr().cast());
            }
        }
        std::thread::spawn(Self::refresh_quad_pid_loop(self));
        loop {
            let mut hdr: *mut pcap_pkthdr = std::ptr::null_mut();
            let mut data: *const u8 = std::ptr::null();
            let rc = unsafe { pcap_next_ex(p, &mut hdr, &mut data) };
            if rc != 1 {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            let (hdr, bytes) = unsafe {
                (
                    &*hdr,
                    std::slice::from_raw_parts(data, (*hdr).caplen as usize),
                )
            };
            let _ = hdr;
            self.on_packet(bytes);
        }
    }

    fn on_packet(&self, b: &[u8]) {
        // 链路层类型默认 EN10MB(1)：14B 头；BPF 设备回环为 NULL(0)：4B 头——按首 2 字节嗅探
        let ip_off = if b.len() > 14 && b[12] == 0x08 && b[13] == 0 {
            14
        } else {
            4
        };
        let (src, dst, proto, l4) = match parse_ip(&b[ip_off..]) {
            Some(x) => x,
            None => return,
        };
        match proto {
            6 => {
                // TCP：上行判定 = 目的非本机——简化为按源/目的端口齐全即登记，
                // 字节累计仅对 data 包（ACK 窗口字节计入）
                let (sport, dport, payload_len) = match parse_tcp(l4) {
                    Some(x) => x,
                    None => return,
                };
                let local = SocketAddr::new(src, sport);
                let remote = SocketAddr::new(dst, dport);
                let id = conn_hash(local, remote);
                let pid = self
                    .quad_pid
                    .lock()
                    .unwrap()
                    .get(&(local, remote))
                    .copied()
                    .unwrap_or(0);
                if self.emitted.insert(id) && pid != 0 {
                    let _ = self.tx.try_send(Envelope::new(
                        self.now(),
                        RawEvent::ConnOpen {
                            pid,
                            start_time: StartTime(0), // lsof 采样无启动时刻，0=未知（引擎侧已容忍）
                            conn_id: ConnId(id),
                            proto: Proto::Tcp,
                            local,
                            remote,
                        },
                    ));
                }
                if payload_len > 0 {
                    let _ = self.tx.try_send(Envelope::new(
                        self.now(),
                        RawEvent::ConnTx {
                            conn_id: ConnId(id),
                            bytes_out_delta: payload_len as u64,
                        },
                    ));
                }
            }
            17 => {
                if let Some((qname, answers, is_response)) = parse_dns_udp(l4) {
                    if is_response {
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
            _ => {}
        }
    }

    fn refresh_quad_pid_loop(&self) -> impl Fn() + Send + Sync + 'static {
        // 闭包只持有 quad_pid 的 Arc（不借用 self），'static 才成立
        let quad_pid = Arc::clone(&self.quad_pid);
        move || loop {
            if let Ok(out) = std::process::Command::new("lsof")
                .args(["-nP", "-i4TCP", "-i6TCP", "-Fpcn"])
                .output()
            {
                let mut map = HashMap::new();
                let text = String::from_utf8_lossy(&out.stdout);
                let (mut pid, mut l, mut r) = (0u32, None, None);
                for line in text.lines() {
                    let (k, v) = line.split_at(1);
                    match k {
                        "p" => {
                            pid = v.parse().unwrap_or(0);
                            l = None;
                            r = None;
                        }
                        "c" => {}
                        "n" => {
                            // "local->remote"
                            if let Some((a, b)) = v.split_once("->") {
                                l = a.parse().ok();
                                r = b.parse().ok();
                                if let (Some(la), Some(ra)) = (l, r) {
                                    map.insert((la, ra), pid);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                *quad_pid.lock().unwrap() = map;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }
}

fn conn_hash(local: SocketAddr, remote: SocketAddr) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for s in [local, remote] {
        let b: Vec<u8> = match s.ip() {
            IpAddr::V4(v) => v.octets().to_vec(),
            IpAddr::V6(v) => v.octets().to_vec(),
        };
        for x in b.iter().chain(s.port().to_be_bytes().iter()) {
            h ^= *x as u64;
            h = h.wrapping_mul(0x100_0000_01b3);
        }
    }
    h
}

fn parse_ip(b: &[u8]) -> Option<(IpAddr, IpAddr, u8, &[u8])> {
    match b[0] >> 4 {
        4 => {
            let ihl = ((b[0] & 0x0f) as usize) * 4;
            if b.len() < ihl + 20 {
                return None;
            }
            let src = IpAddr::from([b[12], b[13], b[14], b[15]]);
            let dst = IpAddr::from([b[16], b[17], b[18], b[19]]);
            Some((src, dst, b[9], &b[ihl..]))
        }
        6 => {
            if b.len() < 40 + 20 {
                return None;
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[8..24]);
            let src = IpAddr::from(a);
            a.copy_from_slice(&b[24..40]);
            let dst = IpAddr::from(a);
            Some((src, dst, b[6], &b[40..]))
        }
        _ => None,
    }
}

fn parse_tcp(b: &[u8]) -> Option<(u16, u16, usize)> {
    if b.len() < 20 {
        return None;
    }
    let sport = u16::from_be_bytes([b[0], b[1]]);
    let dport = u16::from_be_bytes([b[2], b[3]]);
    let doff = ((b[12] >> 4) as usize) * 4;
    Some((sport, dport, b.len().saturating_sub(doff)))
}

fn parse_dns_udp(b: &[u8]) -> Option<(String, Vec<IpAddr>, bool)> {
    if b.len() < 8 + 12 {
        return None;
    }
    let p = &b[8..];
    let qr = p[2] & 0x80 != 0;
    let qd = u16::from_be_bytes([p[4], p[5]]) as usize;
    let an = u16::from_be_bytes([p[6], p[7]]) as usize;
    let mut off = 12;
    let mut qname = String::new();
    for _ in 0..qd {
        loop {
            let l = *p.get(off)? as usize;
            off += 1;
            if l == 0 {
                break;
            }
            if l & 0xC0 != 0 {
                return None;
            }
            if !qname.is_empty() {
                qname.push('.');
            }
            qname.push_str(&String::from_utf8_lossy(p.get(off..off + l)?));
            off += l;
        }
        off += 4;
    }
    let mut answers = Vec::new();
    for _ in 0..an {
        let l = *p.get(off)? as usize;
        off += 1;
        if l & 0xC0 != 0 {
            off += 1;
        } else {
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
        match (rtype, rdlen) {
            (1, 4) => answers.push(IpAddr::from([
                *p.get(rd)?,
                *p.get(rd + 1)?,
                *p.get(rd + 2)?,
                *p.get(rd + 3)?,
            ])),
            (28, 16) => {
                let mut a = [0u8; 16];
                a.copy_from_slice(p.get(rd..rd + 16)?);
                answers.push(IpAddr::from(a));
            }
            _ => {}
        }
        off = rd + rdlen;
    }
    Some((qname, answers, qr))
}
