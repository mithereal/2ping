pub mod config;
pub mod crypto;
pub mod engine;
pub mod mtr;
pub mod protocol;
pub mod reload;
pub mod timestamp;
pub mod tui;
pub mod webhooks;

use crate::engine::TargetSpec;
use hickory_resolver::TokioAsyncResolver;
use std::net::{SocketAddr, ToSocketAddrs};

pub fn normalize_for_dual_stack(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port()),
        SocketAddr::V6(v6) => SocketAddr::V6(v6),
    }
}

pub async fn resolve_targets_public(
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
                name: format!(
                    "{} ({}:{})",
                    host,
                    target_host.trim_end_matches('.'),
                    record.port()
                ),
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
