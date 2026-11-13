use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use twoping::config::{AppConfigFile, KeyringFile};
use twoping::crypto::{AuthDigest, EncryptMethod, SecurityConfig};
use twoping::engine::{run_engine, EngineConfig};
use twoping::mtr::run_mtr_trace;
use twoping::protocol::DEFAULT_PORT;
use twoping::reload::{spawn_hot_reloader, ReloadSpec, RuntimeControls};
use twoping::resolve_targets_public;
use twoping::webhooks::{WebhookConfig, WebhookDispatcher};

#[derive(Parser, Debug)]
#[command(name = "2ping", version, about = "Enterprise bi-directional ping utility in Rust")]
struct Cli {
    /// One or more hostnames or IP addresses of 2ping listeners
    hosts: Vec<String>,

    /// Path to a TOML configuration file (hot-reloaded on change or SIGHUP)
    #[arg(long)]
    config: Option<PathBuf>,

    /// Path to a TOML keyring file for zero-downtime key rotation
    #[arg(long)]
    keyring: Option<PathBuf>,

    /// Active key ID to sign/encrypt outgoing packets with when using --keyring
    #[arg(long)]
    active_key_id: Option<String>,

    /// Launch interactive live terminal UI dashboard
    #[arg(long)]
    tui: bool,

    /// Start in dual-stack listener mode (IPv4 + IPv6)
    #[arg(long)]
    listen: bool,

    /// Run per-hop MTR path trace to target(s)
    #[arg(long)]
    mtr: bool,

    /// Maximum TTL/hop limit for --mtr tracing
    #[arg(long, default_value_t = 30)]
    max_hops: u8,

    /// Probe rounds per hop for --mtr tracing
    #[arg(long, default_value_t = 3)]
    mtr_rounds: u32,

    /// Resolve target hosts via _2ping._udp.<domain> DNS SRV records
    #[arg(long)]
    srv: bool,

    /// Binary-search Path MTU (128..9000 bytes) with Don't Fragment enabled
    #[arg(long)]
    mtu_discover: bool,

    /// Automatically slow down probe rate during high packet loss (>20%)
    #[arg(long)]
    adaptive: bool,

    /// Webhook URL for loss/RTT degradation alerts (requires --features webhooks)
    #[cfg(feature = "webhooks")]
    #[arg(long)]
    webhook_url: Option<String>,

    /// Directional packet loss % threshold to trigger webhook alerts
    #[cfg(feature = "webhooks")]
    #[arg(long, default_value_t = 5.0)]
    webhook_loss_threshold: f64,

    /// Average RTT ms threshold to trigger webhook alerts
    #[cfg(feature = "webhooks")]
    #[arg(long)]
    webhook_rtt_threshold: Option<f64>,

    /// Stop after sending count pings per target
    #[arg(short = 'c', long)]
    count: Option<u64>,

    /// Wait interval seconds between sending each packet
    #[arg(short = 'i', long)]
    interval: Option<f64>,

    /// UDP port to bind or connect to
    #[arg(long)]
    port: Option<u16>,

    /// Expose Prometheus /metrics HTTP endpoint on the specified port
    #[arg(long)]
    metrics_port: Option<u16>,

    /// Minimum packet size in bytes
    #[arg(long)]
    min_packet_size: Option<usize>,

    /// Ping compatibility payload size (sets min-packet-size to bytes + 8)
    #[arg(short = 's', long)]
    packetsize_compat: Option<usize>,

    /// Hex pattern to pad packets with (e.g. "ff" or "deadbeef")
    #[arg(short = 'p', long)]
    pattern: Option<String>,

    /// Set IP DSCP / QoS class (e.g. "EF", "AF41", "CS5", or 0..63)
    #[arg(long)]
    dscp: Option<String>,

    /// Emit newline-delimited JSON (NDJSON) events and summary
    #[arg(long)]
    json: bool,

    /// Shared secret key for HMAC packet authentication
    #[arg(long)]
    auth: Option<String>,

    /// HMAC digest algorithm (hmac-md5, hmac-sha256, hmac-sha512)
    #[arg(long, default_value = "hmac-sha256")]
    auth_digest: String,

    /// Shared secret key for payload encryption
    #[arg(long)]
    encrypt: Option<String>,

    /// Encryption cipher method (chacha20-poly1305 or aes256-cbc)
    #[arg(long, default_value = "chacha20-poly1305")]
    encrypt_method: String,

    /// Disable 3-way pings (use 2-way request/reply only)
    #[arg(long)]
    no_3way: bool,

    /// Quiet output (only display startup and summary)
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Verbose packet decode output
    #[arg(short = 'v', long)]
    verbose: bool,
}

fn parse_dscp(val: &str) -> Result<u8, String> {
    let upper = val.trim().to_uppercase();
    let dscp_6bit = match upper.as_str() {
        "BE" | "DF" | "CS0" => 0,
        "CS1" => 8,
        "AF11" => 10,
        "AF12" => 12,
        "AF13" => 14,
        "CS2" => 16,
        "AF21" => 18,
        "AF22" => 20,
        "AF23" => 22,
        "CS3" => 24,
        "AF31" => 26,
        "AF32" => 28,
        "AF33" => 30,
        "CS4" => 32,
        "AF41" => 34,
        "AF42" => 36,
        "AF43" => 38,
        "CS5" => 40,
        "EF" => 46,
        "CS6" => 48,
        "CS7" => 56,
        _ => {
            let num: u8 = upper
                .parse()
                .map_err(|_| format!("Invalid DSCP value '{}'. Use EF, AF41, CS5, or 0..63", val))?;
            if num > 63 {
                return Err(format!("DSCP numeric value {} out of range (must be 0..63)", num));
            }
            num
        }
    };
    Ok(dscp_6bit << 2)
}

fn parse_hex_pattern(hex: &str) -> Result<Vec<u8>, String> {
    let cleaned = hex.trim();
    if cleaned.len() % 2 != 0 {
        return Err("Pattern hex string must have an even number of characters".into());
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn bind_dual_stack_socket(
    port: u16,
    tos_byte: Option<u8>,
    dont_fragment: bool,
) -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_only_v6(false)?;
    sock.set_nonblocking(true)?;

    if let Some(tos) = tos_byte {
        let _ = sock.set_tos(tos as u32);
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "freebsd"
        ))]
        let _ = sock.set_tclass_v6(tos as u32);
    }

    if dont_fragment {
        #[cfg(target_os = "linux")]
        unsafe {
            use std::os::fd::AsRawFd;
            let val: libc::c_int = libc::IP_PMTUDISC_DO;
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            let val6: libc::c_int = libc::IPV6_PMTUDISC_DO;
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                &val6 as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    let bind_addr: SocketAddr = format!("[::]:{}", port).parse().unwrap();
    sock.bind(&bind_addr.into())?;

    let std_sock: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_sock)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let file_cfg = match &cli.config {
        Some(path) => AppConfigFile::load(path)?,
        None => AppConfigFile::default(),
    };

    let listen_mode = cli.listen || file_cfg.listen.unwrap_or(false);
    let cli_hosts_override = !cli.hosts.is_empty();
    let hosts = if cli_hosts_override {
        cli.hosts.clone()
    } else {
        file_cfg.targets.unwrap_or_default()
    };

    if !listen_mode && hosts.is_empty() {
        eprintln!("Error: Must specify at least one target host or --listen");
        std::process::exit(1);
    }

    let port = cli.port.or(file_cfg.port).unwrap_or(DEFAULT_PORT);
    let metrics_port = cli.metrics_port.or(file_cfg.metrics_port);
    let interval_sec = cli.interval.or(file_cfg.interval).unwrap_or(1.0);
    let count = cli.count.or(file_cfg.count);
    let use_srv = cli.srv || file_cfg.srv.unwrap_or(false);
    let adaptive = cli.adaptive || file_cfg.adaptive.unwrap_or(false);
    let dscp_str = cli.dscp.or(file_cfg.dscp);

    let tos_byte = match &dscp_str {
        Some(d) => Some(parse_dscp(d)?),
        None => None,
    };

    let enc_method = EncryptMethod::from_str(&cli.encrypt_method)?;
    let digest = AuthDigest::from_str(&cli.auth_digest)?;

    let initial_security = if let Some(kr_path) = &cli.keyring {
        let kr = KeyringFile::load(kr_path)?;
        let active_id = cli.active_key_id.as_deref().or(kr.active_key_id.as_deref());
        SecurityConfig::from_keyring(&kr.keys, active_id, digest, enc_method)?
    } else if !file_cfg.keys.is_empty() {
        let active_id = cli
            .active_key_id
            .as_deref()
            .or(file_cfg.active_key_id.as_deref());
        SecurityConfig::from_keyring(&file_cfg.keys, active_id, digest, enc_method)?
    } else {
        SecurityConfig::new(
            cli.auth.as_deref(),
            digest,
            cli.encrypt.as_deref(),
            enc_method,
        )
    };

    let base_min_size = cli
        .min_packet_size
        .or(file_cfg.min_packet_size)
        .unwrap_or(128);
    let min_packet_size = cli
        .packetsize_compat
        .map(|s| s + 8)
        .unwrap_or(base_min_size);

    let pad_pattern = match &cli.pattern {
        Some(p) => parse_hex_pattern(p)?,
        None => Vec::new(),
    };

    let (bind_port, initial_targets) = if listen_mode {
        (port, Vec::new())
    } else {
        let resolved_targets = resolve_targets_public(&hosts, port, use_srv).await?;
        (0, resolved_targets)
    };

    let shared_security = Arc::new(RwLock::new(initial_security));
    let shared_targets = Arc::new(RwLock::new(initial_targets));
// Start hot-reload watcher for SIGHUP and file changes
spawn_hot_reloader(
RuntimeControls {
security: Arc::clone(&shared_security),
targets: Arc::clone(&shared_targets),
},
ReloadSpec {
config_path: cli.config.clone(),
keyring_path: cli.keyring.clone(),
cli_active_key_id: cli.active_key_id.clone(),
cli_auth: cli.auth.clone(),
cli_encrypt: cli.encrypt.clone(),
digest,
encrypt_method: enc_method,
default_port: port,
use_srv,
cli_hosts_override,
quiet: cli.quiet,
json_output: cli.json,
},
);
if cli.mtr {
run_mtr_trace(
shared_targets,
shared_security,
cli.max_hops,
cli.mtr_rounds,
cli.json,
)
.await?;
return Ok(());
}
#[cfg(feature = "webhooks")]
let webhook_cfg = WebhookConfig {
url: cli.webhook_url.or(file_cfg.webhook_url),
loss_threshold_pct: file_cfg
.webhook_loss_threshold
.unwrap_or(cli.webhook_loss_threshold),
rtt_threshold_ms: cli.webhook_rtt_threshold.or(file_cfg.webhook_rtt_threshold),
cooldown: Duration::from_secs(60),
};
#[cfg(not(feature = "webhooks"))]
let webhook_cfg = WebhookConfig::default();
let socket = bind_dual_stack_socket(bind_port, tos_byte, cli.mtu_discover)?;
let config = EngineConfig {
listen_mode,
targets: shared_targets,
interval: Duration::from_secs_f64(interval_sec.max(0.01)),
count,
min_packet_size,
pad_pattern,
quiet: cli.quiet,
verbose: cli.verbose,
three_way: !cli.no_3way,
json_output: cli.json,
mtu_discover: cli.mtu_discover,
tui_mode: cli.tui,
adaptive,
metrics_port,
security: shared_security,
webhook: Arc::new(WebhookDispatcher::new(webhook_cfg)),
};
run_engine(socket, config).await?;
Ok(())
}