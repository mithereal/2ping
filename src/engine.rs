use crate::crypto::SecurityConfig;
use crate::protocol::{hex_id, Packet};
use crate::timestamp::{enable_kernel_timestamps, recv_with_timestamp};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tokio::time;

const REPLAY_TTL: Duration = Duration::from_secs(30);
const REPLAY_MAX_ENTRIES: usize = 10_000;

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum JsonEvent<'a> {
    Reply {
        peer: String,
        bytes: usize,
        seq: u64,
        rtt_ms: f64,
        raw_rtt_ms: f64,
        host_latency_ms: Option<f64>,
        jitter_ms: f64,
    },
    PacketLoss {
        direction: &'a str,
        peer: String,
        seq: u64,
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
        jitter_ms: f64,
        peer_processing_avg_ms: Option<f64>,
        raw_tx: u64,
        raw_rx: u64,
        dropped_invalid: u64,
    },
}

#[derive(Debug, Clone)]
struct SentRecord {
    seq: Option<u64>,
    sent_at: Instant,
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
struct State {
    sent_packets: HashMap<[u8; 6], SentRecord>,
    courtesy_queue: HashMap<SocketAddr, Vec<[u8; 6]>>,
    replay_cache: ReplayCache,
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
    pub host_latencies_ms: Vec<f64>,
    pub jitter_ms: f64,
    pub prev_rtt_ms: Option<f64>,
    pub raw_tx: u64,
    pub raw_rx: u64,
    pub auth_or_decrypt_errors: u64,
}

impl Stats {
    pub fn record_rtt(&mut self, net_rtt_ms: f64, host_lat_ms: Option<f64>) {
        if let Some(prev) = self.prev_rtt_ms {
            let diff = (net_rtt_ms - prev).abs();
            self.jitter_ms += (diff - self.jitter_ms) / 16.0;
        }
        self.prev_rtt_ms = Some(net_rtt_ms);
        self.rtts_ms.push(net_rtt_ms);

        if let Some(h_ms) = host_lat_ms {
            self.host_latencies_ms.push(h_ms);
        }
    }

    pub fn print_summary(&self, target: &str, elapsed: Duration, json_output: bool) {
        let total_loss = self.pings_transmitted.saturating_sub(self.pings_received);
        let loss_pct = if self.pings_transmitted > 0 {
            (total_loss as f64 / self.pings_transmitted as f64) * 100.0
        } else {
            0.0
        };

        let rtt_metrics = if !self.rtts_ms.is_empty() {
            let mut sorted = self.rtts_ms.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

            let min = sorted;
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

        let avg_host = if !self.host_latencies_ms.is_empty() {
            Some(
                self.host_latencies_ms.iter().sum::<f64>()
                    / (self.host_latencies_ms.len() as f64),
            )
        } else {
            None
        };

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

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted;
    }
    let rank = (pct / 100.0) * ((sorted.len() - 1) as f64);
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    let weight = rank - (lower as f64);
    sorted[lower] * (1.0 - weight) + sorted[upper] * weight
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
    pub json_output: bool,
    pub metrics_port: Option<u16>,
    pub security: SecurityConfig,
}

pub async fn run_engine(socket: UdpSocket, config: EngineConfig) -> std::io::Result<()> {
    let _ = enable_kernel_timestamps(&socket);

    let socket = Arc::new(socket);
    let state = Arc::new(Mutex::new(State::default()));
    let security = Arc::new(config.security);
    let start_time = Instant::now();

    if !config.json_output {
        if config.listen_mode {
            println!("2PING listener bound to {}", socket.local_addr()?);
        } else if let Some(addr) = config.target_addr {
            println!(
                "2PING {} ({}): {} bytes of data.",
config.target_name, addr, config.min_packet_size
);
}
}
// Optional Prometheus /metrics HTTP exporter
if let Some(m_port) = config.metrics_port {
let m_state = Arc::clone(&state);
tokio::spawn(async move {
if let Ok(listener) = TcpListener::bind(("0.0.0.0", m_port)).await {
while let Ok((mut stream, _)) = listener.accept().await {
let snapshot = {
let st = m_state.lock().await;
st.stats.clone()
};
let avg_rtt = if snapshot.rtts_ms.is_empty() {
0.0
} else {
snapshot.rtts_ms.iter().sum::() / (snapshot.rtts_ms.len() as f64)
};
let body = format!(
"# TYPE twoping_pings_transmitted_total counter\n
twoping_pings_transmitted_total {}\n
# TYPE twoping_pings_received_total counter\n
twoping_pings_received_total {}\n
# TYPE twoping_outbound_loss_total counter\n
twoping_outbound_loss_total {}\n
# TYPE twoping_inbound_loss_total counter\n
twoping_inbound_loss_total {}\n
# TYPE twoping_dropped_invalid_total counter\n
twoping_dropped_invalid_total {}\n
# TYPE twoping_rtt_avg_ms gauge\n
twoping_rtt_avg_ms {:.3}\n
# TYPE twoping_jitter_ms gauge\n
twoping_jitter_ms {:.3}\n",
snapshot.pings_transmitted,
snapshot.pings_received,
snapshot.outbound_loss,
snapshot.inbound_loss,
snapshot.auth_or_decrypt_errors,
avg_rtt,
snapshot.jitter_ms
);
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
// Background UDP receiver task with kernel timestamp support
let rx_socket = Arc::clone(&socket);
let rx_state = Arc::clone(&state);
let rx_sec = Arc::clone(&security);
let quiet = config.quiet;
let verbose = config.verbose;
let three_way = config.three_way;
let json_output = config.json_output;
let min_size = config.min_packet_size;
let pattern = config.pad_pattern.clone();
tokio::spawn(async move {
let mut buf = vec![0u8; 65535];
while let Ok((len, src, recv_time)) = recv_with_timestamp(&rx_socket, &mut buf).await {
let mut st = rx_state.lock().await;
let pkt = match Packet::decode(&buf[..len], &rx_sec) {
Ok(p) => p,
Err(e) => {
st.stats.auth_or_decrypt_errors += 1;
if verbose && !json_output {
eprintln!("Dropped invalid packet from {}: {}", src, e);
}
continue;
}
};
if !st.replay_cache.check_and_insert(src, pkt.message_id, recv_time) {
st.stats.auth_or_decrypt_errors += 1;
if verbose && !json_output {
eprintln!("Dropped replayed packet id={} from {}", pkt.id_hex(), src);
}
continue;
}
st.stats.raw_rx += 1;
if verbose && !json_output {
println!(
"RX from {} id={} reply_req={} in_reply_to={:?} host_lat_us={:?}",
src,
pkt.id_hex(),
pkt.reply_requested,
pkt.in_reply_to.as_ref().map(hex_id),
pkt.host_latency_us
);
}
if let Some(reply_id) = pkt.in_reply_to {
if let Some(rec) = st.sent_packets.get_mut(&reply_id) {
rec.acked = true;
let raw_rtt = recv_time.duration_since(rec.sent_at);
let raw_rtt_ms = raw_rtt.as_secs_f64() * 1000.0;
let (net_rtt_ms, host_lat_ms) = match pkt.host_latency_us {
Some(us) => {
let h_ms = (us as f64) / 1000.0;
((raw_rtt_ms - h_ms).max(0.0), Some(h_ms))
}
None => (raw_rtt_ms, None),
};
if rec.is_first_leg {
let seq_num = rec.seq.unwrap_or(0);
st.stats.pings_received += 1;
st.stats.record_rtt(net_rtt_ms, host_lat_ms);
if !quiet {
if json_output {
let ev = JsonEvent::Reply {
peer: src.to_string(),
bytes: len,
seq: seq_num,
rtt_ms: round3(net_rtt_ms),
raw_rtt_ms: round3(raw_rtt_ms),
host_latency_ms: host_lat_ms.map(round3),
jitter_ms: round3(st.stats.jitter_ms),
};
if let Ok(line) = serde_json::to_string(&ev) {
println!("{}", line);
}
} else {
match host_lat_ms {
Some(h_ms) if h_ms > 0.001 => println!(
"{} bytes from {}: ping_seq={} time={:.3} ms (raw={:.3} ms, host={:.3} ms)",
len, src, seq_num, net_rtt_ms, raw_rtt_ms, h_ms
),
_ => println!(
"{} bytes from {}: ping_seq={} time={:.3} ms",
len, src, seq_num, net_rtt_ms
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
if let Some(rec) = st.sent_packets.get(inv_id) {
if !rec.acked && rec.is_first_leg {
st.stats.inbound_loss += 1;
if !quiet {
let seq_num = rec.seq.unwrap_or(0);
if json_output {
let ev = JsonEvent::PacketLoss {
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
let processing_us = recv_time.elapsed().as_micros().min(u32::MAX as u128) as u32;
reply.host_latency_us = Some(processing_us);
let wire = reply.encode(&rx_sec);
if rx_socket.send_to(&wire, src).await.is_ok() {
st.stats.raw_tx += 1;
}
}
}
});
// Background garbage collector and outbound loss analyzer
let gc_state = Arc::clone(&state);
let gc_quiet = config.quiet;
let gc_json = config.json_output;
tokio::spawn(async move {
let mut ticker = time::interval(Duration::from_secs(1));
loop {
ticker.tick().await;
let mut st = gc_state.lock().await;
let now = Instant::now();
st.replay_cache.evict_expired(now);
let mut expired_keys = Vec::new();
for (id, rec) in &st.sent_packets {
if now.duration_since(rec.sent_at) > Duration::from_secs(10) {
if !rec.acked && rec.is_first_leg {
st.stats.outbound_loss += 1;
if !gc_quiet {
let seq_num = rec.seq.unwrap_or(0);
if gc_json {
let ev = JsonEvent::PacketLoss {
direction: "outbound",
peer: rec.peer.to_string(),
seq: seq_num,
};
if let Ok(line) = serde_json::to_string(&ev) {
println!("{}", line);
}
} else {
println!(
"Lost outbound packet to {}: ping_seq={}",
rec.peer, seq_num
);
}
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
// Client ping loop or listener Ctrl-C wait
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
.print_summary(&config.target_name, start_time.elapsed(), config.json_output);
Ok(())
}