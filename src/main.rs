mod crypto;
mod engine;
mod protocol;

use clap::Parser;
use twoping::{crypto, engine, protocol};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::UdpSocket;

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

    /// Minimum packet size in bytes
    #[arg(long, default_value_t = 128)]
    min_packet_size: usize,

    /// Ping compatibility payload size (sets min-packet-size to bytes + 8)
    #[arg(short = 's', long)]
    packetsize_compat: Option<usize>,

    /// Hex pattern to pad packets with (e.g. "ff" or "deadbeef")
    #[arg(short = 'p', long)]
    pattern: Option<String>,

    /// Shared secret key for HMAC packet authentication
    #[arg(long)]
    auth: Option<String>,

    /// HMAC digest algorithm (hmac-md5, hmac-sha256, hmac-sha512)
    #[arg(long, default_value = "hmac-sha256")]
    auth_digest: String,

    /// Shared secret key for AES-256-CBC payload encryption
    #[arg(long)]
    encrypt: Option<String>,

    /// Encryption cipher method (currently aes256-cbc)
    #[arg(long, default_value = "aes256-cbc")]
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if !cli.listen && cli.host.is_none() {
        eprintln!("Error: Must specify either a target host or --listen");
        std::process::exit(1);
    }

    if cli.encrypt_method.to_lowercase() != "aes256-cbc" {
        eprintln!("Error: Only 'aes256-cbc' encryption method is supported");
        std::process::exit(1);
    }

    let digest = AuthDigest::from_str(&cli.auth_digest)?;
    let security = SecurityConfig::new(cli.auth.as_deref(), digest, cli.encrypt.as_deref());

    let min_packet_size = cli
        .packetsize_compat
        .map(|s| s + 8)
        .unwrap_or(cli.min_packet_size);

    let pad_pattern = match &cli.pattern {
        Some(p) => parse_hex_pattern(p)?,
        None => Vec::new(),
    };

    let (bind_addr, target_addr, target_name) = if cli.listen {
        (format!("0.0.0.0:{}", cli.port), None, "listener".to_string())
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
        ("0.0.0.0:0".to_string(), Some(resolved), host)
    };

    let socket = UdpSocket::bind(&bind_addr).await?;

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
        security,
    };

    run_engine(socket, config).await?;
    Ok(())
}