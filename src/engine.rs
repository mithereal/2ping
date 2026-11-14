use crate::crypto::SecurityConfig;
use crate::protocol::{hex_id, Packet};
use crate::timestamp::{enable_kernel_timestamps, now_utc_ns, recv_with_timestamp};
use crate::tui::run_tui_loop;
use crate::webhooks::WebhookDispatcher;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, RwLock};
use tokio::time;

const REPLAY_TTL: Duration = Duration::from_secs(30);
const REPLAY_MAX_ENTRIES: usize = 10_000;
const STATS_WINDOW_CAP: usize = 10_000;

#[derive(Debug, Clone)]
pub struct TargetSpec {
    pub name: String,
    pub addr: SocketAddr,
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum JsonEvent<'a> {
    Reply {
        target: &'a str,
        peer: String,
        bytes: usize,
        seq: u64,
        rtt_ms: f64,
        raw_rtt_ms: f64,
        host_latency_ms: Option<f64>,
        outbound_owd_ms: Option<f64>,
        inbound_owd_ms: Option<f64>,
        jitter_ms: f64,
    },
    PacketLoss {
        target: &'a str,
        direction: &'a str,
        peer: String,
        seq: u64,
    },
    MtuResult {
        target: &'a str,
        peer: String,
        discovered_mtu_bytes: usize,
    },
    Summary {
        target: &'a str,
        elapsed_ms: u128,
        transmitted: u64,
        received: u64,
        loss_pct: f64,
        outbound_loss: u64,
        inbound_loss: u64,
        undetermined_loss: u64,
        rtt_min_ms: Option<f64>,
        rtt_avg_ms: Option<f64>,
        rtt_max_ms: Option<f64>,
        rtt_mdev_ms: Option<f64>,
        rtt_p50_ms: Option<f64>,
        rtt_p95_ms: Option<f64>,
        rtt_p99_ms: Option<f64>,
        outbound_owd_avg_ms: Option<f64>,
        inbound_owd_avg_ms: Option<f64>,
        jitter_ms: f64,
        peer_processing_avg_ms: Option<f64>,
        raw_tx: u64,
        raw_rx: u64,
        dropped_invalid: u64,
    },
}

#[derive(Debug, Clone)]
struct SentRecord {
    target_name: String,
    seq: Option<u64>,
    sent_at: Instant,
    tx_wall_ns: u64,
    peer: SocketAddr,
    is_first_leg: bool,
    acked: bool,
}

#[derive(Default)]
struct ReplayCache {
    seen: HashMap<(SocketAddr, [u8; 6]), Instant>,
}

impl ReplayCache {
    fn check_and_insert(&mut self, peer: SocketAddr, msg_id: [u8; 6], now: Instant) -> bool {
        if self.seen.len() >= REPLAY_MAX_ENTRIES {
            self.evict_expired(now);
            if self.seen.len() >= REPLAY_MAX_ENTRIES {
                if let Some((&oldest_key, _)) = self.seen.iter().min_by_key(|(_, &ts)| ts) {
                    self.seen.remove(&oldest_key);
                }
            }
        }

        if let Some(&prev_time) = self.seen.get(&(peer, msg_id)) {
            if now.duration_since(prev_time) < REPLAY_TTL {
                return false;
            }
        }

        self.seen.insert((peer, msg_id), now);
        true
    }

    fn evict_expired(&mut self, now: Instant) {
        self.seen
            .retain(|_, &mut seen_at| now.duration_since(seen_at) < REPLAY_TTL);
    }
}

#[derive(Default)]
pub struct State {
    sent_packets: HashMap<[u8; 6], SentRecord>,
    courtesy_queue: HashMap<SocketAddr, Vec<[u8; 6]>>,
    replay_cache: ReplayCache,
    pub per_target_stats: HashMap<String, Stats>,
    pub global_stats: Stats,
}

#[derive(Default, Clone)]
pub struct Stats {
    pub pings_transmitted: u64,
    pub pings_received: u64,
    pub outbound_loss: u64,
    pub inbound_loss: u64,
    pub undetermined_loss: u64,
    pub rtts_ms: VecDeque<f64>,
    pub host_latencies_ms: VecDeque<f64>,
    pub outbound_owds_ms: VecDeque<f64>,
    pub inbound_owds_ms: VecDeque<f64>,
    pub jitter_ms: f64,
    pub prev_rtt_ms: Option<f64>,
    pub raw_tx: u64,
    pub raw_rx: u64,
    pub auth_or_decrypt_errors: u64,
}

impl Stats {
    pub fn record_rtt(
        &mut self,
        net_rtt_ms: f64,
        host_lat_ms: Option<f64>,
        out_owd_ms: Option<f64>,
        in_owd_ms: Option<f64>,
    ) {
        if let Some(prev) = self.prev_rtt_ms {
            let diff = (net_rtt_ms - prev).abs();
            self.jitter_ms += (diff - self.jitter_ms) / 16.0;
        }
        self.prev_rtt_ms = Some(net_rtt_ms);

        push_bounded(&mut self.rtts_ms, net_rtt_ms);
        if let Some(h_ms) = host_lat_ms {
            push_bounded(&mut self.host_latencies_ms, h_ms);
        }
        if let Some(o_ms) = out_owd_ms {
            push_bounded(&mut self.outbound_owds_ms, o_ms);
        }
        if let Some(i_ms) = in_owd_ms {
            push_bounded(&mut self.inbound_owds_ms, i_ms);
        }
    }

    pub fn avg_rtt(&self) -> f64 {
        mean_deque(&self.rtts_ms).unwrap_or(0.0)
    }

    pub fn avg_outbound_owd(&self) -> Option<f64> {
        mean_deque(&self.outbound_owds_ms)
    }

    pub fn avg_inbound_owd(&self) -> Option<f64> {
        mean_deque(&self.inbound_owds_ms)
    }

    pub fn print_summary(&self, target: &str, elapsed: Duration, json_output: bool) {
        let total_loss = self.pings_transmitted.saturating_sub(self.pings_received);
        let loss_pct = if self.pings_transmitted > 0 {
            (total_loss as f64 / self.pings_transmitted as f64) * 100.0
        } else {
            0.0
        };

        let rtt_metrics = if !self.rtts_ms.is_empty() {
            let mut sorted: Vec<f64> = self.rtts_ms.iter().copied().collect();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

            let min = sorted[0];
            let max = sorted[sorted.len() - 1];
            let sum: f64 = sorted.iter().sum();
            let avg = sum / (sorted.len() as f64);

            let variance = sorted
                .iter()
                .map(|v| {
                    let diff = v - avg;
                    diff * diff
                })
                .sum::<f64>()
                / (sorted.len() as f64);
            let mdev = variance.sqrt();

            let p50 = percentile(&sorted, 50.0);
            let p95 = percentile(&sorted, 95.0);
            let p99 = percentile(&sorted, 99.0);

            Some((min, avg, max, mdev, p50, p95, p99))
        } else {
            None
        };

        let avg_host = mean_deque(&self.host_latencies_ms);
        let avg_out_owd = self.avg_outbound_owd();
        let avg_in_owd = self.avg_inbound_owd();

        if json_output {
            let (min, avg, max, mdev, p50, p95, p99) = match rtt_metrics {
                Some((min, avg, max, mdev, p50, p95, p99)) => (
                    Some(round3(min)),
                    Some(round3(avg)),
                    Some(round3(max)),
                    Some(round3(mdev)),
                    Some(round3(p50)),
                    Some(round3(p95)),
                    Some(round3(p99)),
                ),
                None => (None, None, None, None, None, None, None),
            };

            let summary = JsonEvent::Summary {
                target,
                elapsed_ms: elapsed.as_millis(),
                transmitted: self.pings_transmitted,
                received: self.pings_received,
                loss_pct: (loss_pct * 10.0).round() / 10.0,
                outbound_loss: self.outbound_loss,
                inbound_loss: self.inbound_loss,
                undetermined_loss: self.undetermined_loss,
                rtt_min_ms: min,
                rtt_avg_ms: avg,
                rtt_max_ms: max,
                rtt_mdev_ms: mdev,
                rtt_p50_ms: p50,
                rtt_p95_ms: p95,
                rtt_p99_ms: p99,
                outbound_owd_avg_ms: avg_out_owd.map(round3),
                inbound_owd_avg_ms: avg_in_owd.map(round3),
                jitter_ms: round3(self.jitter_ms),
                peer_processing_avg_ms: avg_host.map(round3),
                raw_tx: self.raw_tx,
                raw_rx: self.raw_rx,
                dropped_invalid: self.auth_or_decrypt_errors,
            };
            if let Ok(line) = serde_json::to_string(&summary) {
                println!("{}", line);
            }
            return;
        }

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
        if let Some((min, avg, max, mdev, p50, p95, p99)) = rtt_metrics {
            println!(
                "rtt min/avg/max/mdev = {:.3}/{:.3}/{:.3}/{:.3} ms (jitter {:.3} ms)",
                min, avg, max, mdev, self.jitter_ms
            );
            println!(
                "rtt percentiles p50/p95/p99 = {:.3}/{:.3}/{:.3} ms",
                p50, p95, p99
            );
        }
        if let (Some(o_owd), Some(i_owd)) = (avg_out_owd, avg_in_owd) {
            println!(
                "one-way delay (OWD) avg: outbound = {:.3} ms, inbound = {:.3} ms",
                o_owd, i_owd
            );
        }
        if let Some(h_avg) = avg_host {
            println!(
                "peer processing latency avg = {:.3} ms (subtracted from rtt)",
                h_avg
            );
        }
        println!(
            "{} raw packets transmitted, {} received ({} dropped/invalid)",
            self.raw_tx, self.raw_rx, self.auth_or_decrypt_errors
        );
    }
}

fn push_bounded(q: &mut VecDeque<f64>, val: f64) {
    if q.len() >= STATS_WINDOW_CAP {
        q.pop_front();
    }
    q.push_back(val);
}

fn mean_deque(q: &VecDeque<f64>) -> Option<f64> {
    if q.is_empty() {
        None
    } else {
        Some(q.iter().sum::<f64>() / (q.len() as f64))
    }
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = (pct / 100.0) * ((sorted.len() - 1) as f64);
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    let weight = rank - (lower as f64);
    sorted[lower] * (1.0 - weight) + sorted[upper] * weight
}

pub struct EngineConfig {
    pub listen_mode: bool,
    pub targets: Arc<RwLock<Vec<TargetSpec>>>,
    pub interval: Duration,
    pub count: Option<u64>,
    pub min_packet_size: usize,
    pub pad_pattern: Vec<u8>,
    pub quiet: bool,
    pub verbose: bool,
    pub three_way: bool,
    pub json_output: bool,
    pub mtu_discover: bool,
    pub tui_mode: bool,
    pub adaptive: bool,
    pub metrics_port: Option<u16>,
    pub security: Arc<RwLock<SecurityConfig>>,
    pub webhook: Arc<WebhookDispatcher>,
}

pub async fn run_engine(socket: UdpSocket, config: EngineConfig) -> std::io::Result<()> {
    let _ = enable_kernel_timestamps(&socket);
    let socket = Arc::new(socket);
    let state = Arc::new(Mutex::new(State::default()));
    let active_key_id = config.security.read().await.active_key_id.clone();
    let security = Arc::clone(&config.security);
    let targets = Arc::clone(&config.targets);
    let start_time = Instant::now();
    let suppress_stdout = config.quiet || config.tui_mode;

    if !config.json_output && !config.tui_mode {
        if config.listen_mode {
            println!(
                "2PING dual-stack listener bound to {} (active key: {})",
                socket.local_addr()?,
                active_key_id
            );
        } else {
            let t_list = targets.read().await;
            for t in t_list.iter() {
                println!(
                    "2PING {} ({}): {} bytes of data.",
                    t.name, t.addr, config.min_packet_size
                );
            }
        }
    }

    // Prometheus /metrics HTTP exporter
    if let Some(m_port) = config.metrics_port {
        let m_state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Ok(listener) = TcpListener::bind(("::", m_port)).await {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let (global, per_target) = {
                        let st = m_state.lock().await;
                        (st.global_stats.clone(), st.per_target_stats.clone())
                    };
                    let mut body = format!(
                        "# TYPE twoping_dropped_invalid_total counter\n\
                         twoping_dropped_invalid_total {}\n\
                         # TYPE twoping_pings_transmitted_total counter\n\
                         # TYPE twoping_pings_received_total counter\n\
                         # TYPE twoping_outbound_loss_total counter\n\
                         # TYPE twoping_inbound_loss_total counter\n\
                         # TYPE twoping_rtt_avg_ms gauge\n\
                         # TYPE twoping_outbound_owd_avg_ms gauge\n\
                         # TYPE twoping_inbound_owd_avg_ms gauge\n\
                         # TYPE twoping_jitter_ms gauge\n",
                        global.auth_or_decrypt_errors
                    );
                    if per_target.is_empty() {
                        body.push_str(&format!(
                            "twoping_pings_transmitted_total{{target=\"listener\"}} {}\n\
                             twoping_pings_received_total{{target=\"listener\"}} {}\n\
                             twoping_outbound_loss_total{{target=\"listener\"}} {}\n\
                             twoping_inbound_loss_total{{target=\"listener\"}} {}\n\
                             twoping_rtt_avg_ms{{target=\"listener\"}} {:.3}\n\
                             twoping_jitter_ms{{target=\"listener\"}} {:.3}\n",
                            global.pings_transmitted,
                            global.pings_received,
                            global.outbound_loss,
                            global.inbound_loss,
                            global.avg_rtt(),
                            global.jitter_ms
                        ));
                    } else {
                        for (t_name, s) in &per_target {
                            body.push_str(&format!(
                                "twoping_pings_transmitted_total{{target=\"{}\"}} {}\n\
                                 twoping_pings_received_total{{target=\"{}\"}} {}\n\
                                 twoping_outbound_loss_total{{target=\"{}\"}} {}\n\
                                 twoping_inbound_loss_total{{target=\"{}\"}} {}\n\
                                 twoping_rtt_avg_ms{{target=\"{}\"}} {:.3}\n\
                                 twoping_outbound_owd_avg_ms{{target=\"{}\"}} {:.3}\n\
                                 twoping_inbound_owd_avg_ms{{target=\"{}\"}} {:.3}\n\
                                 twoping_jitter_ms{{target=\"{}\"}} {:.3}\n",
                                t_name,
                                s.pings_transmitted,
                                t_name,
                                s.pings_received,
                                t_name,
                                s.outbound_loss,
                                t_name,
                                s.inbound_loss,
                                t_name,
                                s.avg_rtt(),
                                t_name,
                                s.avg_outbound_owd().unwrap_or(0.0),
                                t_name,
                                s.avg_inbound_owd().unwrap_or(0.0),
                                t_name,
                                s.jitter_ms
                            ));
                        }
                    }
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
            }
        });
    }

    // Background UDP receiver task
    let rx_socket = Arc::clone(&socket);
    let rx_state = Arc::clone(&state);
    let rx_sec = Arc::clone(&security);
    let rx_webhook = Arc::clone(&config.webhook);
    let verbose = config.verbose;
    let three_way = config.three_way;
    let json_output = config.json_output;
    let min_size = config.min_packet_size;
    let pattern = config.pad_pattern.clone();
    let multi_target = targets.read().await.len() > 1;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((len, src, recv_time, recv_wall_ns)) =
            recv_with_timestamp(&rx_socket, &mut buf).await
        {
            let sec_guard = rx_sec.read().await;
            let mut st = rx_state.lock().await;
            let pkt = match Packet::decode(&buf[..len], &sec_guard) {
                Ok(p) => p,
                Err(e) => {
                    st.global_stats.auth_or_decrypt_errors += 1;
                    if verbose && !json_output && !suppress_stdout {
                        eprintln!("Dropped invalid packet from {}: {}", src, e);
                    }
                    continue;
                }
            };
            if !st.replay_cache.check_and_insert(src, pkt.message_id, recv_time) {
                st.global_stats.auth_or_decrypt_errors += 1;
                if verbose && !json_output && !suppress_stdout {
                    eprintln!("Dropped replayed packet id={} from {}", pkt.id_hex(), src);
                }
                continue;
            }
            st.global_stats.raw_rx += 1;
            if verbose && !json_output && !suppress_stdout {
                println!(
                    "RX from {} id={} key={:?} reply_req={} in_reply_to={:?} host_lat_us={:?}",
                    src,
                    pkt.id_hex(),
                    pkt.key_id,
                    pkt.reply_requested,
                    pkt.in_reply_to.as_ref().map(hex_id),
                    pkt.host_latency_us
                );
            }
            if let Some(reply_id) = pkt.in_reply_to {
                let matched = if let Some(rec) = st.sent_packets.get_mut(&reply_id) {
                    rec.acked = true;
                    Some((
                        rec.target_name.clone(),
                        rec.sent_at,
                        rec.tx_wall_ns,
                        rec.is_first_leg,
                        rec.seq.unwrap_or(0),
                    ))
                } else {
                    None
                };
                if let Some((t_name, sent_at, client_tx_ns, is_first_leg, seq_num)) = matched {
                    let raw_rtt = recv_time.duration_since(sent_at);
                    let raw_rtt_ms = raw_rtt.as_secs_f64() * 1000.0;
                    let (net_rtt_ms, host_lat_ms) = match pkt.host_latency_us {
                        Some(us) => {
                            let h_ms = (us as f64) / 1000.0;
                            ((raw_rtt_ms - h_ms).max(0.0), Some(h_ms))
                        }
                        None => (raw_rtt_ms, None),
                    };
                    let (out_owd_ms, in_owd_ms) = match (pkt.rx_timestamp_ns, pkt.tx_timestamp_ns) {
                        (Some(listener_rx_ns), Some(listener_tx_ns))
                            if listener_rx_ns >= client_tx_ns && recv_wall_ns >= listener_tx_ns =>
                        {
                            let out_ms = (listener_rx_ns - client_tx_ns) as f64 / 1_000_000.0;
                            let in_ms = (recv_wall_ns - listener_tx_ns) as f64 / 1_000_000.0;
                            (Some(out_ms), Some(in_ms))
                        }
                        _ => (None, None),
                    };
                    if is_first_leg {
                        st.global_stats.pings_received += 1;
                        st.global_stats
                            .record_rtt(net_rtt_ms, host_lat_ms, out_owd_ms, in_owd_ms);
                        let t_stats = st.per_target_stats.entry(t_name.clone()).or_default();
                        t_stats.pings_received += 1;
                        t_stats.raw_rx += 1;
                        t_stats.record_rtt(net_rtt_ms, host_lat_ms, out_owd_ms, in_owd_ms);
                        let cur_jitter = t_stats.jitter_ms;
                        let cur_avg_rtt = t_stats.avg_rtt();
                        let cur_in_loss_pct = if t_stats.pings_transmitted > 0 {
                            (t_stats.inbound_loss as f64 / t_stats.pings_transmitted as f64) * 100.0
                        } else {
                            0.0
                        };
                        let wh = Arc::clone(&rx_webhook);
                        let wh_target = t_name.clone();
                        tokio::spawn(async move {
                            wh.evaluate_and_notify(
                                &wh_target,
                                "inbound",
                                cur_in_loss_pct,
                                cur_avg_rtt,
                                cur_jitter,
                            )
                            .await;
                        });
                        if !suppress_stdout {
                            if json_output {
                                let ev = JsonEvent::Reply {
                                    target: &t_name,
                                    peer: src.to_string(),
                                    bytes: len,
                                    seq: seq_num,
                                    rtt_ms: round3(net_rtt_ms),
                                    raw_rtt_ms: round3(raw_rtt_ms),
                                    host_latency_ms: host_lat_ms.map(round3),
                                    outbound_owd_ms: out_owd_ms.map(round3),
                                    inbound_owd_ms: in_owd_ms.map(round3),
                                    jitter_ms: round3(cur_jitter),
                                };
                                if let Ok(line) = serde_json::to_string(&ev) {
                                    println!("{}", line);
                                }
                            } else {
                                let label = if multi_target {
                                    format!("{} ({})", t_name, src)
                                } else {
                                    src.to_string()
                                };
                                match (host_lat_ms, out_owd_ms, in_owd_ms) {
                                    (_, Some(o), Some(i)) => println!(
                                        "{} bytes from {}: ping_seq={} time={:.3} ms (owd out={:.3} ms, in={:.3} ms)",
                                        len, label, seq_num, net_rtt_ms, o, i
                                    ),
                                    (Some(h_ms), _, _) if h_ms > 0.001 => println!(
                                        "{} bytes from {}: ping_seq={} time={:.3} ms (raw={:.3} ms, host={:.3} ms)",
                                        len, label, seq_num, net_rtt_ms, raw_rtt_ms, h_ms
                                    ),
                                    _ => println!(
                                        "{} bytes from {}: ping_seq={} time={:.3} ms",
                                        len, label, seq_num, net_rtt_ms
                                    ),
                                }
                            }
                        }
                    }
                    st.courtesy_queue.entry(src).or_default().push(reply_id);
                }
            }
            for expired_id in &pkt.courtesy_expires {
                st.sent_packets.remove(expired_id);
            }
            for inv_id in &pkt.investigate {
                let lost_info = if let Some(rec) = st.sent_packets.get(inv_id) {
                    if !rec.acked && rec.is_first_leg {
                        Some((rec.target_name.clone(), rec.seq.unwrap_or(0)))
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some((t_name, seq_num)) = lost_info {
                    st.global_stats.inbound_loss += 1;
                    let t_stats = st.per_target_stats.entry(t_name.clone()).or_default();
                    t_stats.inbound_loss += 1;
                    let loss_pct = if t_stats.pings_transmitted > 0 {
                        (t_stats.inbound_loss as f64 / t_stats.pings_transmitted as f64) * 100.0
                    } else {
                        0.0
                    };
                    let avg_rtt = t_stats.avg_rtt();
                    let jitter = t_stats.jitter_ms;
                    let wh = Arc::clone(&rx_webhook);
                    let wh_target = t_name.clone();
                    tokio::spawn(async move {
                        wh.evaluate_and_notify(&wh_target, "inbound", loss_pct, avg_rtt, jitter)
                            .await;
                    });
                    if !suppress_stdout {
                        if json_output {
                            let ev = JsonEvent::PacketLoss {
                                target: &t_name,
                                direction: "inbound",
                                peer: src.to_string(),
                                seq: seq_num,
                            };
                            if let Ok(line) = serde_json::to_string(&ev) {
                                println!("{}", line);
                            }
                        } else {
                            println!("Lost inbound packet from {}: ping_seq={}", src, seq_num);
                        }
                    }
                }
            }
            if pkt.reply_requested {
                let mut reply = Packet::new();
                reply.min_size = min_size;
                reply.pad_pattern = pattern.clone();
                reply.in_reply_to = Some(pkt.message_id);
                reply.rx_timestamp_ns = Some(recv_wall_ns);
                if three_way && pkt.in_reply_to.is_none() {
                    reply.reply_requested = true;
                    st.sent_packets.insert(
                        reply.message_id,
                        SentRecord {
                            target_name: "listener".into(),
                            seq: None,
                            sent_at: Instant::now(),
                            tx_wall_ns: now_utc_ns(),
                            peer: src,
                            is_first_leg: false,
                            acked: false,
                        },
                    );
                }
                if let Some(courtesy) = st.courtesy_queue.remove(&src) {
                    reply.courtesy_expires = courtesy;
                }
                let processing_us = recv_time.elapsed().as_micros().min(u32::MAX as u128) as u32;
                reply.host_latency_us = Some(processing_us);
                reply.tx_timestamp_ns = Some(now_utc_ns());
                let wire = reply.encode(&sec_guard);
                if rx_socket.send_to(&wire, src).await.is_ok() {
                    st.global_stats.raw_tx += 1;
                }
            }
        }
    });

    // Background garbage collector and outbound loss analyzer
    let gc_state = Arc::clone(&state);
    let gc_webhook = Arc::clone(&config.webhook);
    let gc_json = config.json_output;
    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let mut st = gc_state.lock().await;
            let now = Instant::now();
            st.replay_cache.evict_expired(now);
            let mut expired_keys = Vec::new();
            let mut outbound_losses = Vec::new();
            for (id, rec) in &st.sent_packets {
                if now.duration_since(rec.sent_at) > Duration::from_secs(10) {
                    if !rec.acked && rec.is_first_leg {
                        outbound_losses.push((
                            rec.target_name.clone(),
                            rec.peer,
                            rec.seq.unwrap_or(0),
                        ));
                    }
                    expired_keys.push(*id);
                }
            }
            for (t_name, peer, seq_num) in outbound_losses {
                st.global_stats.outbound_loss += 1;
                let t_stats = st.per_target_stats.entry(t_name.clone()).or_default();
                t_stats.outbound_loss += 1;
                let loss_pct = if t_stats.pings_transmitted > 0 {
                    (t_stats.outbound_loss as f64 / t_stats.pings_transmitted as f64) * 100.0
                } else {
                    0.0
                };
                let avg_rtt = t_stats.avg_rtt();
                let jitter = t_stats.jitter_ms;
                let wh = Arc::clone(&gc_webhook);
                let wh_target = t_name.clone();
                tokio::spawn(async move {
                    wh.evaluate_and_notify(&wh_target, "outbound", loss_pct, avg_rtt, jitter)
                        .await;
                });
                if !suppress_stdout {
                    if gc_json {
                        let ev = JsonEvent::PacketLoss {
                            target: &t_name,
                            direction: "outbound",
                            peer: peer.to_string(),
                            seq: seq_num,
                        };
                        if let Ok(line) = serde_json::to_string(&ev) {
                            println!("{}", line);
                        }
                    } else {
                        println!("Lost outbound packet to {}: ping_seq={}", peer, seq_num);
                    }
                }
            }
            for k in expired_keys {
                st.sent_packets.remove(&k);
            }
        }
    });

    // Spawn interactive TUI if requested
    let tui_handle = if config.tui_mode {
        let tui_state = Arc::clone(&state);
        let tui_kid = active_key_id.clone();
        Some(tokio::spawn(async move {
            let _ = run_tui_loop(tui_state, tui_kid).await;
        }))
    } else {
        None
    };

    if config.listen_mode {
        if let Some(handle) = tui_handle {
            let _ = handle.await;
        } else {
            tokio::signal::ctrl_c().await?;
        }
    } else if config.mtu_discover {
        run_mtu_discovery(&socket, &state, &security, &targets, &config).await?;
    } else {
        let mut seq = 1u64;
        let base_interval = config.interval;
        loop {
            let current_interval = if config.adaptive {
                let st = state.lock().await;
                let tx = st.global_stats.pings_transmitted;
                let rx = st.global_stats.pings_received;
                if tx > 5 && (rx as f64 / tx as f64) < 0.80 {
                    (base_interval * 2).min(Duration::from_secs(10))
                } else {
                    base_interval
                }
            } else {
                base_interval
            };
            let tui_exited = tui_handle.as_ref().map(|h| h.is_finished()).unwrap_or(false);
            if tui_exited {
                break;
            }
            tokio::select! {
                _ = time::sleep(current_interval) => {
                    if let Some(max) = config.count {
                        if seq > max {
                            time::sleep(Duration::from_millis(500)).await;
                            break;
                        }
                    }
                    let current_targets = targets.read().await.clone();
                    let sec_guard = security.read().await;
                    for target in &current_targets {
                        let mut pkt = Packet::new();
                        pkt.reply_requested = true;
                        pkt.min_size = config.min_packet_size;
                        pkt.pad_pattern = config.pad_pattern.clone();
                        let tx_wall_ns = now_utc_ns();
                        pkt.tx_timestamp_ns = Some(tx_wall_ns);
                        {
                            let mut st = state.lock().await;
                            if let Some(courtesy) = st.courtesy_queue.remove(&target.addr) {
                                pkt.courtesy_expires = courtesy;
                            }
                            let unacked: Vec<[u8; 6]> = st.sent_packets
                                .iter()
                                .filter(|(_, r)| {
                                    !r.acked
                                        && !r.is_first_leg
                                        && r.peer == target.addr
                                        && r.sent_at.elapsed() > Duration::from_secs(2)
                                })
                                .map(|(id, _)| *id)
                                .take(4)
                                .collect();
                            pkt.investigate = unacked;
                            st.sent_packets.insert(
                                pkt.message_id,
                                SentRecord {
                                    target_name: target.name.clone(),
                                    seq: Some(seq),
                                    sent_at: Instant::now(),
                                    tx_wall_ns,
                                    peer: target.addr,
                                    is_first_leg: true,
                                    acked: false,
                                },
                            );
                            st.global_stats.pings_transmitted += 1;
                            st.global_stats.raw_tx += 1;
                            let t_stats = st.per_target_stats.entry(target.name.clone()).or_default();
                            t_stats.pings_transmitted += 1;
                            t_stats.raw_tx += 1;
                        }
                        let wire = pkt.encode(&sec_guard);
                        socket.send_to(&wire, target.addr).await?;
                    }
                    seq += 1;
                }
                _ = tokio::signal::ctrl_c() => {
                    break;
                }
            }
        }
    }

    if let Some(handle) = tui_handle {
        handle.abort();
    }

    let st = state.lock().await;
    if config.listen_mode {
        st.global_stats
            .print_summary("listener", start_time.elapsed(), config.json_output);
    } else {
        let t_list = targets.read().await;
        for t in t_list.iter() {
            let stats = st
                .per_target_stats
                .get(&t.name)
                .cloned()
                .unwrap_or_default();
            stats.print_summary(&t.name, start_time.elapsed(), config.json_output);
        }
    }
    Ok(())
}

async fn run_mtu_discovery(
    socket: &UdpSocket,
    state: &Arc<Mutex<State>>,
    security: &Arc<RwLock<SecurityConfig>>,
    targets: &Arc<RwLock<Vec<TargetSpec>>>,
    config: &EngineConfig,
) -> std::io::Result<()> {
    let target_list = targets.read().await.clone();
    let sec_guard = security.read().await;
    for target in &target_list {
        if !config.json_output {
            println!("Discovering Path MTU to {} ({})...", target.name, target.addr);
        }
        let mut low = 128usize;
        let mut high = 9000usize;
        let mut best_ok = 0usize;
        while low <= high {
            let mid = low + (high - low) / 2;
            let mut pkt = Packet::new();
            pkt.reply_requested = true;
            pkt.min_size = mid;
            pkt.pad_pattern = config.pad_pattern.clone();
            let msg_id = pkt.message_id;
            {
                let mut st = state.lock().await;
                st.sent_packets.insert(
                    msg_id,
                    SentRecord {
                        target_name: target.name.clone(),
                        seq: Some(mid as u64),
                        sent_at: Instant::now(),
                        tx_wall_ns: now_utc_ns(),
                        peer: target.addr,
                        is_first_leg: true,
                        acked: false,
                    },
                );
                st.global_stats.pings_transmitted += 1;
                st.global_stats.raw_tx += 1;
                let t_stats = st.per_target_stats.entry(target.name.clone()).or_default();
                t_stats.pings_transmitted += 1;
                t_stats.raw_tx += 1;
            }
            let wire = pkt.encode(&sec_guard);
            let actual_payload_len = wire.len();
            if socket.send_to(&wire, target.addr).await.is_err() {
                high = mid - 1;
                continue;
            }
            let mut got_ack = false;
            for _ in 0..8 {
                time::sleep(Duration::from_millis(50)).await;
                let st = state.lock().await;
                if let Some(rec) = st.sent_packets.get(&msg_id) {
                    if rec.acked {
                        got_ack = true;
                        break;
                    }
                }
            }
            if got_ack {
                best_ok = actual_payload_len;
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }
        let ip_overhead = if target.addr.is_ipv6() { 48 } else { 28 };
        let path_mtu = if best_ok > 0 { best_ok + ip_overhead } else { 0 };
        if config.json_output {
            let ev = JsonEvent::MtuResult {
                target: &target.name,
                peer: target.addr.to_string(),
                discovered_mtu_bytes: path_mtu,
            };
            if let Ok(line) = serde_json::to_string(&ev) {
                println!("{}", line);
            }
        } else {
            println!(
                "Path MTU to {} ({}): {} bytes (max UDP payload {} bytes)",
                target.name, target.addr, path_mtu, best_ok
            );
        }
    }
    Ok(())
}