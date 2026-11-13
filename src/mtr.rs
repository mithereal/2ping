use crate::crypto::SecurityConfig;
use crate::engine::TargetSpec;
use crate::protocol::Packet;
use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time;

#[derive(Debug, Clone, Serialize)]
pub struct HopReport {
    pub hop: u8,
    pub router_ip: Option<String>,
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f64,
    pub avg_rtt_ms: Option<f64>,
    pub min_rtt_ms: Option<f64>,
    pub max_rtt_ms: Option<f64>,
}

#[derive(Serialize)]
struct MtrJsonOutput<'a> {
    event: &'a str,
    target: &'a str,
    peer: String,
    hops: Vec<HopReport>,
}

pub async fn run_mtr_trace(
    targets: Arc<RwLock<Vec<TargetSpec>>>,
    security: Arc<RwLock<SecurityConfig>>,
    max_hops: u8,
    rounds: u32,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let target_list = targets.read().await.clone();
    let sec_snapshot = security.read().await.clone();

    for target in target_list {
        if !json_output {
            println!(
                "\n2PING MTR Path Trace to {} ({}) — max_hops={}, rounds={}",
                target.name, target.addr, max_hops, rounds
            );
            println!(
                "{:<5} {:<40} {:<8} {:<10} {:<10} {:<10}",
                "HOP", "ROUTER IP", "LOSS%", "AVG(ms)", "MIN(ms)", "MAX(ms)"
            );
        }

        let mut reports = Vec::new();
        let is_v6 = target.addr.is_ipv6() && target.addr.ip().to_canonical().is_ipv6();

        for ttl in 1..=max_hops {
            let mut rtts_ms = Vec::new();
            let mut responder_ip: Option<IpAddr> = None;
            let mut reached_dest = false;

            for _ in 0..rounds {
                if let Some((ip, rtt, is_dest)) =
                    probe_single_hop(target.addr, ttl, is_v6, &sec_snapshot).await
                {
                    responder_ip = Some(ip);
                    rtts_ms.push(rtt.as_secs_f64() * 1000.0);
                    if is_dest {
                        reached_dest = true;
                    }
                }
                time::sleep(Duration::from_millis(40)).await;
            }

            let received = rtts_ms.len() as u32;
            let loss_pct = ((rounds - received) as f64 / rounds as f64) * 100.0;
            let (avg, min, max) = if !rtts_ms.is_empty() {
                let sum: f64 = rtts_ms.iter().sum();
                let min_v = rtts_ms.iter().cloned().fold(f64::INFINITY, f64::min);
                let max_v = rtts_ms.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
                (
                    Some((sum / rtts_ms.len() as f64 * 1000.0).round() / 1000.0),
                    Some((min_v * 1000.0).round() / 1000.0),
                    Some((max_v * 1000.0).round() / 1000.0),
                )
            } else {
                (None, None, None)
            };

            let ip_str = responder_ip.map(|ip| ip.to_canonical().to_string());
            if !json_output {
                println!(
                    "{:<5} {:<40} {:<7.1}% {:<10} {:<10} {:<10}",
                    ttl,
                    ip_str.as_deref().unwrap_or("???"),
                    loss_pct,
                    avg.map(|v| format!("{:.3}", v)).unwrap_or_else(|| "-".into()),
                    min.map(|v| format!("{:.3}", v)).unwrap_or_else(|| "-".into()),
                    max.map(|v| format!("{:.3}", v)).unwrap_or_else(|| "-".into()),
                );
            }

            reports.push(HopReport {
                hop: ttl,
                router_ip: ip_str,
                sent: rounds,
                received,
                loss_pct: (loss_pct * 10.0).round() / 10.0,
                avg_rtt_ms: avg,
                min_rtt_ms: min,
                max_rtt_ms: max,
            });

            if reached_dest {
                break;
            }
        }

        if json_output {
            let out = MtrJsonOutput {
                event: "mtr_trace",
                target: &target.name,
                peer: target.addr.to_string(),
                hops: reports,
            };
            if let Ok(line) = serde_json::to_string(&out) {
                println!("{}", line);
            }
        }
    }

    Ok(())
}

async fn probe_single_hop(
    target: SocketAddr,
    ttl: u8,
    is_v6: bool,
    sec: &SecurityConfig,
) -> Option<(IpAddr, Duration, bool)> {
    let domain = if is_v6 { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    sock.set_nonblocking(true).ok()?;

    if is_v6 {
        sock.set_unicast_hops_v6(ttl as u32).ok()?;
    } else {
        sock.set_ttl(ttl as u32).ok()?;
    }

    let bind_addr: SocketAddr = if is_v6 {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    sock.bind(&bind_addr.into()).ok()?;

    let udp = UdpSocket::from_std(sock.into()).ok()?;
    let local_port = udp.local_addr().ok()?.port();

    // Optional raw ICMP listener (works when CAP_NET_RAW / root is available)
    let icmp_sock = bind_icmp_listener(is_v6);

    let mut pkt = Packet::new();
    pkt.reply_requested = true;
    let wire = pkt.encode(sec);

    let dest = if is_v6 {
        target
    } else {
        SocketAddr::new(target.ip().to_canonical(), target.port())
    };

    let sent_at = Instant::now();
    udp.send_to(&wire, dest).await.ok()?;

    let mut udp_buf = [0u8; 2048];
    let mut icmp_buf = [0u8; 2048];

    tokio::select! {
        res = time::timeout(Duration::from_millis(500), udp.recv_from(&mut udp_buf)) => {
            if let Ok(Ok((len, src))) = res {
                if Packet::decode(&udp_buf[..len], sec).is_ok() {
                    return Some((src.ip(), sent_at.elapsed(), true));
                }
            }
            None
        }
        res = async {
            match &icmp_sock {
                Some(s) => time::timeout(Duration::from_millis(500), s.recv_from(&mut icmp_buf)).await,
                None => {
                    time::sleep(Duration::from_millis(500)).await;
                    Err(tokio::time::error::Elapsed::from(
                        time::timeout(Duration::ZERO, async {}).await.unwrap_err()
                    ))
                }
            }
        } => {
            if let Ok(Ok((len, router_addr))) = res {
                if icmp_matches_udp_port(&icmp_buf[..len], local_port, dest.port(), is_v6) {
                    return Some((router_addr.ip(), sent_at.elapsed(), false));
                }
            }
            None
        }
    }
}

fn bind_icmp_listener(is_v6: bool) -> Option<UdpSocket> {
    let (domain, proto, bind_str) = if is_v6 {
        (Domain::IPV6, Protocol::ICMPV6, "[::]:0")
    } else {
        (Domain::IPV4, Protocol::ICMPV4, "0.0.0.0:0")
    };
    let sock = Socket::new(domain, Type::RAW, Some(proto)).ok()?;
    sock.set_nonblocking(true).ok()?;
    let addr: SocketAddr = bind_str.parse().ok()?;
    sock.bind(&addr.into()).ok()?;
    UdpSocket::from_std(sock.into()).ok()
}

/// Checks if an ICMP Time Exceeded (Type 11 IPv4 / Type 3 IPv6) quotes our UDP src/dst ports.
fn icmp_matches_udp_port(buf: &[u8], src_port: u16, dst_port: u16, is_v6: bool) -> bool {
    if is_v6 {
        // ICMPv6 Header (8B) + Inner IPv6 Header (40B) + Inner UDP Header (4B ports) = 52B
        if buf.len() < 52 || buf != 3 {
            return false;
        }
        let s_port = u16::from_be_bytes([buf, buf]);
        let d_port = u16::from_be_bytes([buf, buf]);
        s_port == src_port && d_port == dst_port
    } else {
        // IPv4 Header (20B) + ICMP Header (8B) + Inner IPv4 Header (20B) + Inner UDP Ports (4B) = 52B
        if buf.len() < 52 {
            return false;
        }
        let ihl = ((buf & 0x0F) as usize) * 4;
        if buf.len() < ihl + 8 + 20 + 4 || buf[ihl] != 11 {
            return false;
        }
        let inner_ip_start = ihl + 8;
        let inner_ihl = ((buf[inner_ip_start] & 0x0F) as usize) * 4;
        let udp_start = inner_ip_start + inner_ihl;
        if buf.len() < udp_start + 4 {
            return false;
        }
        let s_port = u16::from_be_bytes([buf[udp_start], buf[udp_start + 1]]);
        let d_port = u16::from_be_bytes([buf[udp_start + 2], buf[udp_start + 3]]);
        s_port == src_port && d_port == dst_port
    }
}
