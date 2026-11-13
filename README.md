# 2ping (twoping-rs)

An enterprise-grade, asynchronous Rust implementation of **2ping**, a bi-directional UDP ping utility. Using 3-way handshakes (akin to TCP `SYN`, `SYN/ACK`, `ACK`) and after-the-fact state comparison between listeners and clients, `2ping` isolates whether packet loss or latency spikes occur on the **outbound** or **inbound** network path.


---

## Comparison: Original Python `2ping` vs. Rust `2ping` (`v1.0.0`)

While remaining wire-compatible with the core `2ping` binary framing (`0x3250` magic header, 16-bit one's complement checksums, 48-bit Message IDs, and standard opcodes), this Rust rewrite delivers major improvements in timing accuracy, cryptography, multi-target scale, and observability:

| Capability | Original Python `2ping` | Rust `2ping` (`v1.0.0`) |
| :--- | :--- | :--- |
| **Runtime & Memory** | Single-threaded Python 3 process with optional C-extensions (`pycryptodomex`, `dnspython`, `netifaces`) | Single compiled native binary powered by `tokio` async I/O with bounded `10,000`-sample ring buffers for flat 24/7 memory usage |
| **Receive Timestamps** | User-space `time.time()` calls subject to Python GIL and event-loop jitter | Kernel nanosecond receive timestamps via `SO_TIMESTAMPNS` / `SCM_TIMESTAMPNS` (`recvmsg`) on Linux |
| **One-Way Delay (OWD)** | RTT only | Embeds nanosecond UTC wall-clock opcodes (`TxTimestampNs` / `RxTimestampNs`) to separate **outbound transit ms** from **inbound transit ms** on NTP/PTP-synced hosts |
| **Host Processing Delay** | Parses `HostLatency` (`0x0010`) | Measures exact listener processing delay in microseconds and subtracts it from client RTT to isolate true network transit time |
| **Multi-Target & Dual-Stack** | Single target per invocation | Probes multiple hosts concurrently (`2ping host1 host2 ...`) over a single dual-stack `[::]` IPv4/IPv6 UDP socket |
| **Path MTU Discovery** | Not supported | Built-in `--mtu-discover` binary search (`128..9000` bytes) with IP Don't Fragment (`DF`) enabled to pinpoint tunnel/VPN MTU ceilings |
| **Cryptography & Key Rotation** | Single static secret with `AES-256-CBC` + `HMAC` | Defaults to **`ChaCha20-Poly1305` AEAD** (binding the 12-byte outer header as Associated Data), supports **zero-downtime multi-key rotation (`--keyring`)**, and includes a sliding-window `ReplayCache` |
| **QoS / DiffServ Marking** | Not supported | Built-in `--dscp` flag (`EF`, `AF41`, `CS5`, or `0..63`) setting `IP_TOS` / `IPV6_TCLASS` |
| **Observability & UI** | Plaintext stdout only | Live interactive **`--tui` terminal dashboard** (sparklines & directional gauges), **`--json` NDJSON** streaming, and a **`--metrics-port` Prometheus `/metrics`** HTTP exporter |


---

## Features

- **Directional Packet Loss & One-Way Latency:** Distinguishes outbound vs. inbound drops and separates upload vs. download transit times.
- **Kernel-Level Precision:** Uses Linux `SO_TIMESTAMPNS` ancillary control messages and `HostLatency` subtraction to eliminate user-space scheduling jitter.
- **Tail Latency & Jitter Metrics:** Computes `min/avg/max/mdev`, RFC 3550 smoothed jitter, and `p50/p95/p99` percentiles over a bounded sliding window.
- **Zero-Downtime Key Rotation (`--keyring`):** Supports active and staged secrets via `KeyId` (`0x0080`) with `ChaCha20-Poly1305` AEAD or `AES-256-CBC` + `HMAC`.
- **Anti-Replay Protection:** Drops duplicate UDP packets per peer using a bounded 30-second sliding-window cache.
- **Path MTU Sweep (`--mtu-discover`):** Binary-searches maximum non-fragmented packet sizes (`128..9000` bytes) to uncover asymmetric MTU blackholes.
- **Fleet & DevOps Ready:** Supports declarative TOML configs (`--config`), DNS `SRV` auto-discovery (`--srv`), adaptive loss backoff (`--adaptive`), interactive `--tui`, `--json` NDJSON logs, and Prometheus `/metrics`.


---

## Installation

### Prerequisites
- Rust toolchain (`1.70+` recommended)

### Install `2ping` Globally via Cargo

From the repository root, build and install the `2ping` binary into `~/.cargo/bin`:

```bash
cargo install --path .
```

Verify the installation:

```bash
which 2ping
2ping --help
```

*(Note: Ensure `~/.cargo/bin` is ahead of `/usr/bin` in your `PATH` if the original Python `2ping` is also installed.)*

---

## Usage

### 0. Ping the Public Server 

```bash
2ping test.2ping.net -c 5
```
### 1. Basic Plaintext Mode

Start a listener on the remote host (binds to UDP port `15998` by default):

```bash
2ping --listen
```

Connect from the client machine:

```bash
2ping <LISTENER_IP_OR_HOST>
```

### 2. Modern AEAD Encryption (`ChaCha20-Poly1305`)

With `ChaCha20-Poly1305` (the default cipher), a single `--encrypt` secret provides full authenticated encryption over both the outer header and inner opcodes:

```bash
# Listener
2ping --listen --encrypt "shared-aead-secret"

# Client
2ping <LISTENER_IP_OR_HOST> -c 10 --encrypt "shared-aead-secret"
```

### 3. Legacy Compatibility Mode (`AES-256-CBC` + `HMAC`)

```bash
# Listener
2ping --listen \
  --auth "shared-hmac-secret" \
  --auth-digest hmac-sha512 \
  --encrypt "shared-aes-secret" \
  --encrypt-method aes256-cbc

# Client
2ping <LISTENER_IP_OR_HOST> -c 10 \
  --auth "shared-hmac-secret" \
  --auth-digest hmac-sha512 \
  --encrypt "shared-aes-secret" \
  --encrypt-method aes256-cbc
```

### 4. QoS DSCP Testing, JSON Logs & Prometheus Metrics

```bash
# Listener exposing Prometheus metrics on :9100
2ping --listen --metrics-port 9100

# Client testing Expedited Forwarding (EF) QoS queue with NDJSON output
2ping <LISTENER_IP_OR_HOST> -c 5 --dscp EF --json
```

### 5. Declarative TOML Config & Zero-Downtime Key Rotation

Create `2ping.toml`:

```toml
port = 15998
metrics_port = 9100
interval = 1.0
dscp = "EF"
adaptive = true
targets = ["10.0.0.5", "10.0.0.12"]

active_key_id = "2026-q4"

[[keys]]
id = "2026-q3"
encrypt_secret = "previous-quarter-secret-key"

[[keys]]
id = "2026-q4"
encrypt_secret = "current-quarter-secret-key"
```

### 6. Path MTU Discovery & QoS DSCP Probing

```bash
# Binary-search Path MTU (128..9000B) with Don't Fragment set
2ping 10.0.0.5 --mtu-discover

# Probe Expedited Forwarding (EF) QoS queue with NDJSON telemetry
2ping 10.0.0.5 -c 5 --dscp EF --json
---

## CLI Options

| Flag | Default | Description |
| :--- | :--- | :--- |
| `<HOSTS...>` | — | One or more hostnames or IPv4/IPv6 addresses of `2ping` listeners |
| `--config <FILE>` | — | Load fleet targets, ports, DSCP, and keyring from a TOML file |
| `--keyring <FILE>` | — | Load multi-key rotation secrets from a TOML keyring file |
| `--active-key-id <ID>` | First key | Key ID from keyring used to sign/encrypt outgoing packets |
| `--listen` | `false` | Start in dual-stack IPv4/IPv6 listener mode |
| `--srv` | `false` | Resolve target hosts via `_2ping._udp.<domain>` DNS `SRV` records |
| `--mtu-discover` | `false` | Binary-search Path MTU (`128..9000` bytes) with Dont Fragment set |
| `--tui` | `false` | Launch interactive live terminal UI dashboard (`ratatui`) |
| `--adaptive` | `false` | Automatically back off probe interval during high packet loss (`>20%`) |
| `--port <PORT>` | `15998` | UDP port to bind (listener) or connect to (client) |
| `--metrics-port <PORT>` | — | Expose Prometheus `/metrics` HTTP endpoint on the specified port |
| `-c, --count <N>` | Infinite | Stop after sending `N` pings per target |
| `-i, --interval <SEC>` | `1.0` | Wait interval in seconds between sending packets |
| `--min-packet-size <BYTES>` | `128` | Minimum wire packet size in bytes |
| `-s <BYTES>` | — | Ping compatibility payload size (`min-packet-size = bytes + 8`) |
| `-p, --pattern <HEX>` | `00` | Hex byte pattern used to pad packets (e.g., `deadbeef`) |
| `--dscp <CLASS_OR_NUM>` | — | Set IP DSCP / QoS class (`EF`, `AF41`, `CS5`, `BE`, or `0..63`) |
| `--json` | `false` | Emit newline-delimited JSON (NDJSON) events and summary |
| `--auth <SECRET>` | — | Shared secret for HMAC packet authentication |
| `--auth-digest <ALG>` | `hmac-sha256` | HMAC algorithm (`hmac-md5`, `hmac-sha256`, `hmac-sha512`) |
| `--encrypt <SECRET>` | — | Shared secret for payload encryption |
| `--encrypt-method <ALG>` | `chacha20-poly1305` | Encryption cipher method (`chacha20-poly1305` or `aes256-cbc`) |
| `--no-3way` | `false` | Disable 3-way pings (use standard 2-way request/reply) |
| `-q, --quiet` | `false` | Quiet output (only display startup and final summary) |
| `-v, --verbose` | `false` | Print per-packet decode and drop diagnostics |


---

## Project Architecture

```text
2ping-rs/
├── Cargo.toml                  # Crate manifest (`2ping` binary + library exports)
├── Dockerfile                  # Multi-stage container build
├── docker-compose.yml          # Listener + client test stack
├── src/
│   ├── lib.rs                  # Library module exports
│   ├── main.rs                 # CLI parsing, TOML config, dual-stack socket & DNS SRV
│   ├── config.rs               # TOML fleet configuration and keyring parser
│   ├── crypto.rs               # PBKDF2 key derivation, Multi-Key Ring, ChaCha20-Poly1305, AES-CBC, HMAC
│   ├── protocol.rs             # Binary wire encoding, decoding, OWD & KeyId opcodes, checksums
│   ├── timestamp.rs            # Linux SO_TIMESTAMPNS kernel receive timestamps & UTC wall clock
│   ├── tui.rs                  # Live Ratatui sparkline and directional loss terminal dashboard
│   └── engine.rs               # Async 3-way state machine, replay cache, MTU sweep, stats & metrics
└── tests/
    └── protocol_and_crypto.rs  # Unit and multi-target loopback UDP integration 
```

---

## Running Tests

Run the unit and localhost 3-way UDP integration test suite with:

```bash
cargo test
```

---

## Run 2ping Server via Systemd.

 Installation & Activation Commands

Run these commands on your Linux server to install the binary, configure the service, and enable it at boot:
bash
## 1. Copy the compiled release binary to /usr/local/bin
sudo cp target/release/2ping /usr/local/bin/2ping
sudo chmod 755 /usr/local/bin/2ping

## 2. Create the environment file (restrict permissions to root)
sudo bash -c 'echo "TWOPING_OPTS=\"--quiet\"" > /etc/default/2ping'
sudo chmod 600 /etc/default/2ping

## 3. Reload systemd, enable at boot, and start immediately
sudo systemctl daemon-reload
sudo systemctl enable --now 2ping.service

## 4. Verification & Firewall Notes

• Check service status and logs:bash

sudo systemctl status 2ping.service

sudo journalctl -u 2ping.service -f

    • Open UDP port 15998 in your firewall:

    • UFW (Ubuntu/Debian): sudo ufw allow 15998/udp

    • firewalld (RHEL/Fedora): sudo firewall-cmd --add-port=15998/udp 
    --permanent && sudo firewall-cmd --reload



## License

Inspired by Ryan Finnie's `2ping` utility (licensed under MPL-2.0).
