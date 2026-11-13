use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::UdpSocket;
use twoping::crypto::{AuthDigest, EncryptMethod, SecurityConfig};
use twoping::engine::{run_engine, EngineConfig};
use twoping::protocol::DEFAULT_PORT;

#[derive(Parser, Debug)]
#[command(name = "2ping", version, about = "A bi-directional ping utility in Rust")]
struct Cli {
    /// Hostname or IP address of the 2ping listener
    host: Option<String>,

    /// Start in listener mode
    #[arg(long)]
    listen: bool,

    /// Stop after sending count pings
    #[arg(short = 'c', long)]
    count: Option<u64>,

    /// Wait interval seconds between sending each packet
    #[arg(short = 'i', long, default_value = "1.0")]
    interval: f64,

    /// UDP port to bind or connect to
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Expose Prometheus /metrics HTTP endpoint on the specified port
    #[arg(long)]
    metrics_port: Option<u16>,

    /// Minimum packet size in bytes
    #[arg(long, default_value_t = 128)]
    min_packet_size: usize,

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

fn bind_configured_socket(bind_addr: SocketAddr, tos_byte: Option<u8>) -> std::io::Result<UdpSocket> {
    let domain = if bind_addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_nonblocking(true)?;

    if let Some(tos) = tos_byte {
        if bind_addr.is_ipv4() {
            sock.set_tos(tos as u32)?;
        } else {
            #[cfg(any(
                target_os = "linux",
                target_os = "android",
                target_os = "macos",
                target_os = "freebsd"
            ))]
            sock.set_tclass_v6(tos as u32)?;
        }
    }

    sock.bind(&bind_addr.into())?;
    let std_sock: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_sock)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if !cli.listen && cli.host.is_none() {
        eprintln!("Error: Must specify either a target host or --listen");
        std::process::exit(1);
    }

    let tos_byte = match &cli.dscp {
        Some(d) => Some(parse_dscp(d)?),
        None => None,
    };

    let enc_method = EncryptMethod::from_str(&cli.encrypt_method)?;
    let digest = AuthDigest::from_str(&cli.auth_digest)?;
    let security = SecurityConfig::new(
        cli.auth.as_deref(),
        digest,
        cli.encrypt.as_deref(),
        enc_method,
    );

    let min_packet_size = cli
        .packetsize_compat
        .map(|s| s + 8)
        .unwrap_or(cli.min_packet_size);

    let pad_pattern = match &cli.pattern {
        Some(p) => parse_hex_pattern(p)?,
        None => Vec::new(),
    };

    let (bind_addr, target_addr, target_name) = if cli.listen {
        let addr: SocketAddr = format!("0.0.0.0:{}", cli.port).parse()?;
        (addr, None, "listener".to_string())
    } else {
        let host = cli.host.unwrap();
        let addr_str = if host.contains(':') {
            host.clone()
        } else {
            format!("{}:{}", host, cli.port)
        };
        let resolved: SocketAddr = addr_str
            .to_socket_addrs()?
            .next()
            .ok_or("Unable to resolve target host")?;
        let local_bind: SocketAddr = if resolved.is_ipv6() {
            "[::]:0".parse()?
        } else {
            "0.0.0.0:0".parse()?
        };
        (local_bind, Some(resolved), host)
    };

    let socket = bind_configured_socket(bind_addr, tos_byte)?;

    let config = EngineConfig {
        listen_mode: cli.listen,
        target_addr,
        target_name,
        interval: Duration::from_secs_f64(cli.interval.max(0.01)),
        count: cli.count,
        min_packet_size,
        pad_pattern,
        quiet: cli.quiet,
        verbose: cli.verbose,
        three_way: !cli.no_3way,
        json_output: cli.json,
        metrics_port: cli.metrics_port,
        security,
    };

    run_engine(socket, config).await?;
    Ok(())
}