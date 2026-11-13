use clap::Parser;
use hickory_resolver::TokioAsyncResolver;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UdpSocket;
use twoping::config::{AppConfigFile, KeyringFile};
use twoping::crypto::{AuthDigest, EncryptMethod, SecurityConfig};
use twoping::engine::{run_engine, EngineConfig, TargetSpec};
use twoping::protocol::DEFAULT_PORT;

#[derive(Parser, Debug)]
#[command(name = "2ping", version, about = "Enterprise bi-directional ping utility in Rust")]
struct Cli {
    /// One or more hostnames or IP addresses of 2ping listeners
    hosts: Vec<String>,

    /// Path to a TOML configuration file
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

    /// Resolve target hosts via _2ping._udp.<domain> DNS SRV records
    #[arg(long)]
    srv: bool,

    /// Binary-search Path MTU (128..9000 bytes) with Don't Fragment enabled
    #[arg(long)]
    mtu_discover: bool,

    /// Automatically slow down probe rate during high packet loss (>20%)
    #[arg(long)]
    adaptive: bool,

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

fn normalize_for_dual_stack(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port()),
        SocketAddr::V6(v6) => SocketAddr::V6(v6),
    }
}

async fn resolve_targets(
    hosts: &[String],
    default_port: u16,
    use_srv: bool,
) -> Result<Vec<TargetSpec>, Box<dyn std::error::Error>> {
    let mut specs = Vec::new();
    let resolver = if use_srv {
        Some(TokioAsyncResolver::tokio_from_system_conf()?)
    } else {
        None
    };

    for host in hosts {
        if let Some(ref res) = resolver {
            let srv_query = format!("_2ping._udp.{}.", host.trim_end_matches('.'));
            let srv_lookup = res.srv_lookup(&srv_query).await?;
            let record = srv_lookup
                .iter()
                .min_by_key(|r| (r.priority(), std::cmp::Reverse(r.weight())))
                .ok_or_else(|| format!("No SRV records found for {}", srv_query))?;

            let target_host = record.target().to_utf8();
            let addr_str = format!("{}:{}", target_host.trim_end_matches('.'), record.port());
            let resolved = addr_str
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| format!("Unable to resolve SRV target {}", addr_str))?;

            specs.push(TargetSpec {
                name: format!("{} ({}:{})", host, target_host.trim_end_matches('.'), record.port()),
                addr: normalize_for_dual_stack(resolved),
            });
        } else {
            let addr_str = if host.starts_with('[') || host.matches(':').count() == 1 {
                host.clone()
            } else if host.contains(':') {
                format!("[{}]:{}", host, default_port)
            } else {
                format!("{}:{}", host, default_port)
            };

            let resolved = addr_str
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| format!("Unable to resolve host '{}'", host))?;

            specs.push(TargetSpec {
                name: host.clone(),
                addr: normalize_for_dual_stack(resolved),
            });
        }
    }

    Ok(specs)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let file_cfg = match &cli.config {
        Some(path) => AppConfigFile::load(path)?,
        None => AppConfigFile::default(),
    };

    let listen_mode = cli.listen || file_cfg.listen.unwrap_or(false);
    let hosts = if !cli.hosts.is_empty() {
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

    // Build SecurityConfig from --keyring, --config keys, or single CLI secrets
    let security = if let Some(kr_path) = &cli.keyring {
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
let (bind_port, targets) = if listen_mode {
(port, Vec::new())
} else {
let resolved_targets = resolve_targets(&hosts, port, use_srv).await?;
(0, resolved_targets)
};
let socket = bind_dual_stack_socket(bind_port, tos_byte, cli.mtu_discover)?;
let config = EngineConfig {
listen_mode,
targets,
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
security,
};
run_engine(socket, config).await?;
Ok(())
}