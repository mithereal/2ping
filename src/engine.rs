use crate::crypto::SecurityConfig;
use crate::protocol::{hex_id, Packet};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time;

#[derive(Debug, Clone)]
struct SentRecord {
    seq: Option<u64>,
    sent_at: Instant,
    peer: SocketAddr,
    is_first_leg: bool,
    acked: bool,
}

#[derive(Default)]
struct State {
    sent_packets: HashMap<[u8; 6], SentRecord>,
    courtesy_queue: HashMap<SocketAddr, Vec<[u8; 6]>>,
    stats: Stats,
}

#[derive(Default, Clone)]
pub struct Stats {
    pub pings_transmitted: u64,
    pub pings_received: u64,
    pub outbound_loss: u64,
    pub inbound_loss: u64,
    pub undetermined_loss: u64,
    pub rtts_ms: Vec<f64>,
    pub raw_tx: u64,
    pub raw_rx: u64,
    pub auth_or_decrypt_errors: u64,
}

impl Stats {
    pub fn print_summary(&self, target: &str, elapsed: Duration) {
        let total_loss = self.pings_transmitted.saturating_sub(self.pings_received);
        let loss_pct = if self.pings_transmitted > 0 {
            (total_loss as f64 / self.pings_transmitted as f64) * 100.0
        } else {
            0.0
        };

        println!("\n--- {} 2ping statistics ---", target);
        println!(
            "{} pings transmitted, {} received, {:.1}% ping loss, time {}ms",
            self.pings_transmitted,
            self.pings_received,
            loss_pct,
            elapsed.as_millis()
        );
        if self.pings_transmitted > 0 {
            let out_pct = (self.outbound_loss as f64 / self.pings_transmitted as f64) * 100.0;
            let in_pct = (self.inbound_loss as f64 / self.pings_transmitted as f64) * 100.0;
            let und_pct = (self.undetermined_loss as f64 / self.pings_transmitted as f64) * 100.0;
            println!(
                "{} outbound ping losses ({:.1}%), {} inbound ({:.1}%), {} undetermined ({:.1}%)",
                self.outbound_loss,
                out_pct,
                self.inbound_loss,
                in_pct,
                self.undetermined_loss,
                und_pct
            );
        }
        if !self.rtts_ms.is_empty() {
            let min = self.rtts_ms.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = self.rtts_ms.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            let avg = self.rtts_ms.iter().sum::<f64>() / (self.rtts_ms.len() as f64);
            println!("rtt min/avg/max = {:.3}/{:.3}/{:.3} ms", min, avg, max);
        }
        println!(
            "{} raw packets transmitted, {} received ({} dropped/invalid)",
            self.raw_tx, self.raw_rx, self.auth_or_decrypt_errors
        );
    }
}

pub struct EngineConfig {
    pub listen_mode: bool,
    pub target_addr: Option<SocketAddr>,
    pub target_name: String,
    pub interval: Duration,
    pub count: Option<u64>,
    pub min_packet_size: usize,
    pub pad_pattern: Vec<u8>,
    pub quiet: bool,
    pub verbose: bool,
    pub three_way: bool,
    pub security: SecurityConfig,
}

pub async fn run_engine(socket: UdpSocket, config: EngineConfig) -> std::io::Result<()> {
    let socket = Arc::new(socket);
    let state = Arc::new(Mutex::new(State::default()));
    let security = Arc::new(config.security);
    let start_time = Instant::now();

    if config.listen_mode {
        println!("2PING listener bound to {}", socket.local_addr()?);
    } else if let Some(addr) = config.target_addr {
        println!(
            "2PING {} ({}): {} bytes of data.",
            config.target_name, addr, config.min_packet_size
        );
    }

    let rx_socket = Arc::clone(&socket);
    let rx_state = Arc::clone(&state);
    let rx_sec = Arc::clone(&security);
    let quiet = config.quiet;
    let verbose = config.verbose;
    let three_way = config.three_way;
    let min_size = config.min_packet_size;
    let pattern = config.pad_pattern.clone();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((len, src)) = rx_socket.recv_from(&mut buf).await {
            let recv_time = Instant::now();
            let mut st = rx_state.lock().await;

            let pkt = match Packet::decode(&buf[..len], &rx_sec) {
                Ok(p) => p,
                Err(e) => {
                    st.stats.auth_or_decrypt_errors += 1;
                    if verbose {
                        eprintln!("Dropped invalid packet from {}: {}", src, e);
                    }
                    continue;
                }
            };

            st.stats.raw_rx += 1;

            if verbose {
                println!(
                    "RX from {} id={} reply_req={} in_reply_to={:?}",
                    src,
                    pkt.id_hex(),
                    pkt.reply_requested,
                    pkt.in_reply_to.as_ref().map(hex_id)
                );
            }

            if let Some(reply_id) = pkt.in_reply_to {
                if let Some(rec) = st.sent_packets.get_mut(&reply_id) {
                    rec.acked = true;
                    let rtt = recv_time.duration_since(rec.sent_at);
                    let rtt_ms = rtt.as_secs_f64() * 1000.0;

                    if rec.is_first_leg {
                        st.stats.pings_received += 1;
                        st.stats.rtts_ms.push(rtt_ms);
                        if !quiet {
                            println!(
                                "{} bytes from {}: ping_seq={} time={:.3} ms",
                                len,
                                src,
                                rec.seq.unwrap_or(0),
                                rtt_ms
                            );
                        }
                    }

                    st.courtesy_queue.entry(src).or_default().push(reply_id);
                }
            }

            for expired_id in &pkt.courtesy_expires {
                st.sent_packets.remove(expired_id);
            }

            for inv_id in &pkt.investigate {
                if let Some(rec) = st.sent_packets.get(inv_id) {
                    if !rec.acked && rec.is_first_leg && !quiet {
                        println!(
                            "Lost inbound packet from {}: ping_seq={}",
                            src,
                            rec.seq.unwrap_or(0)
                        );
                        st.stats.inbound_loss += 1;
                    }
                }
            }

            if pkt.reply_requested {
                let mut reply = Packet::new();
                reply.min_size = min_size;
                reply.pad_pattern = pattern.clone();
                reply.in_reply_to = Some(pkt.message_id);

                if three_way && pkt.in_reply_to.is_none() {
                    reply.reply_requested = true;
                    st.sent_packets.insert(
                        reply.message_id,
                        SentRecord {
                            seq: None,
                            sent_at: Instant::now(),
                            peer: src,
                            is_first_leg: false,
                            acked: false,
                        },
                    );
                }

                if let Some(courtesy) = st.courtesy_queue.remove(&src) {
                    reply.courtesy_expires = courtesy;
                }

                let wire = reply.encode(&rx_sec);
                if rx_socket.send_to(&wire, src).await.is_ok() {
                    st.stats.raw_tx += 1;
                }
            }
        }
    });

    let gc_state = Arc::clone(&state);
    let gc_quiet = config.quiet;
    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let mut st = gc_state.lock().await;
            let now = Instant::now();
            let mut expired_keys = Vec::new();

            for (id, rec) in &st.sent_packets {
                if now.duration_since(rec.sent_at) > Duration::from_secs(10) {
                    if !rec.acked && rec.is_first_leg {
                        st.stats.outbound_loss += 1;
                        if !gc_quiet {
                            println!(
                                "Lost outbound packet to {}: ping_seq={}",
                                rec.peer,
                                rec.seq.unwrap_or(0)
                            );
                        }
                    }
                    expired_keys.push(*id);
                }
            }

            for k in expired_keys {
                st.sent_packets.remove(&k);
            }
        }
    });

    if config.listen_mode {
        tokio::signal::ctrl_c().await?;
    } else if let Some(target) = config.target_addr {
        let mut seq = 1u64;
        let mut ticker = time::interval(config.interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Some(max) = config.count {
                        if seq > max {
                            time::sleep(Duration::from_millis(500)).await;
                            break;
                        }
                    }

                    let mut pkt = Packet::new();
                    pkt.reply_requested = true;
                    pkt.min_size = config.min_packet_size;
                    pkt.pad_pattern = config.pad_pattern.clone();

                    {
                        let mut st = state.lock().await;
                        if let Some(courtesy) = st.courtesy_queue.remove(&target) {
                            pkt.courtesy_expires = courtesy;
                        }

                        let unacked: Vec<[u8; 6]> = st.sent_packets
                            .iter()
.filter(|(_, r)| !r.acked && !r.is_first_leg && r.sent_at.elapsed() > Duration::from_secs(2))
.map(|(id, _)| *id)
.take(4)
.collect();
pkt.investigate = unacked;
st.sent_packets.insert(
pkt.message_id,
SentRecord {
seq: Some(seq),
sent_at: Instant::now(),
peer: target,
is_first_leg: true,
acked: false,
},
);
st.stats.pings_transmitted += 1;
st.stats.raw_tx += 1;
}
let wire = pkt.encode(&security);
socket.send_to(&wire, target).await?;
seq += 1;
}
_ = tokio::signal::ctrl_c() => {
break;
}
}
}
}
let st = state.lock().await;
st.stats
.print_summary(&config.target_name, start_time.elapsed());
Ok(())
}