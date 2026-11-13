# 2ping (twoping-rs)

An enterprise-grade, asynchronous Rust implementation of **2ping**, a bi-directional UDP ping utility. Using 3-way handshakes (akin to TCP `SYN`, `SYN/ACK`, `ACK`) and after-the-fact state comparison between listeners and clients, `2ping` isolates whether packet loss or latency spikes occur on the **outbound** or **inbound** network path.


---

## Comparison: Original Python `2ping` vs. Rust `2ping` (`v1.2.0`)

While remaining wire-compatible with the core `2ping` binary framing (`0x3250` magic header, 16-bit one's complement checksums, 48-bit Message IDs, and standard opcodes), this Rust rewrite delivers major improvements in timing accuracy, cryptography, path diagnostics, and operational automation:

| Capability | Original Python `2ping` | Rust `2ping` (`v1.2.0`) |
| :--- | :--- | :--- |
| **Runtime & Memory** | Single-threaded Python 3 process with optional C-extensions (`pycryptodomex`, `dnspython`, `netifaces`) | Single compiled native binary powered by `tokio` async I/O with bounded `10,000`-sample ring buffers for flat 24/7 memory usage |
| **Receive Timestamps** | User-space `time.time()` calls subject to Python GIL and event-loop jitter | Kernel nanosecond receive timestamps via `SO_TIMESTAMPNS` / `SCM_TIMESTAMPNS` (`recvmsg`) on Linux |
| **One-Way Delay (OWD)** | RTT only | Embeds nanosecond UTC wall-clock opcodes (`TxTimestampNs` / `RxTimestampNs`) to separate **outbound transit ms** from **inbound transit ms** on NTP/PTP-synced hosts |
| **Host Processing Delay** | Parses `HostLatency` (`0x0010`) | Measures exact listener processing delay in microseconds and subtracts it from client RTT to isolate true network transit time |
| **Multi-Target & Dual-Stack** | Single target per invocation | Probes multiple hosts concurrently (`2ping host1 host2 ...`) over a single dual-stack `[::]` IPv4/IPv6 UDP socket |
| **Path Diagnostics** | Basic packet loss & RTT | Built-in **per-hop MTR path tracing (`--mtr`)** and **Path MTU binary search (`--mtu-discover`, `128..9000` bytes)** |
| **Cryptography & Key Rotation** | Single static secret with `AES-256-CBC` + `HMAC` | Defaults to **`ChaCha20-Poly1305` AEAD** (binding the 12-byte outer header as Associated Data), supports **zero-downtime multi-key rotation (`--keyring`)**, and includes a sliding-window `ReplayCache` |
| **Hot-Reloading** | Requires process restart | Watches `--config` and `--keyring` files automatically and responds to **`SIGHUP`** (`systemctl reload 2ping`) without dropping active sessions |
| **Alerting & Observability** | Plaintext stdout only | Interactive **`--tui` terminal dashboard**, **`--json` NDJSON** streaming, **`--metrics-port` Prometheus `/metrics`**, and **optional compile-time webhook alerts (`--features webhooks`)** |



---

## Features

- **Directional Packet Loss & One-Way Latency:** Distinguishes outbound vs. inbound drops and separates upload vs. download transit times.
- **Kernel-Level Precision:** Uses Linux `SO_TIMESTAMPNS` ancillary control messages and `HostLatency` subtraction to eliminate user-space scheduling jitter.
- **Per-Hop Path Tracing (`--mtr`):** Traces intermediate router hops via incremental IP `TTL` / `Hop Limit` probes and ICMP `Time Exceeded` capture.
- **Path MTU Sweep (`--mtu-discover`):** Binary-searches maximum non-fragmented packet sizes (`128..9000` bytes) with Don't Fragment (`DF`) set to uncover asymmetric VPN/tunnel MTU blackholes.
- **Zero-Downtime Key Rotation & Hot-Reload:** Supports active and staged secrets via `KeyId` (`0x0080`) with `ChaCha20-Poly1305` AEAD or `AES-256-CBC` + `HMAC`, reloaded live via file watch or `SIGHUP`.
- **Anti-Replay Protection:** Drops duplicate UDP packets per peer using a bounded 30-second sliding-window cache.
- **Optional Webhook Alerting (`--features webhooks`):** Excluded from default builds to keep dependencies minimal; enable at compile time for standalone Slack/Discord/PagerDuty degradation and recovery notifications.
- **SRE & DevOps Ready:** Supports declarative TOML configs (`--config`), DNS `SRV` auto-discovery (`--srv`), adaptive loss backoff (`--adaptive`), interactive `--tui`, `--json` NDJSON logs, and Prometheus `/metrics`.



---

## Installation

### Prerequisites
- Rust toolchain (`1.70+` recommended)

### Install `2ping` Globally via Cargo

### 1. Default Lean Build (No HTTP Client Dependencies)

From the repository root, run the test suite and install `2ping` into `~/.cargo/bin`:

```bash
cargo test
cargo install --path .
```

### 2. Optional Build with Standalone Webhook Alerting

To compile in `reqwest` and enable `--webhook-url`:

```bash
cargo install --path . --features webhooks
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

### 2. Multi-Target Probing with Live Terminal UI (`--tui`)

```bash
2ping 10.0.0.5 10.0.0.12 test.2ping.net --tui
```

### 3. Per-Hop Path Tracing (`--mtr`) & Path MTU Discovery (`--mtu-discover`)

```bash
# Trace hop-by-hop latency and packet loss to target
sudo 2ping 10.0.0.5 --mtr --max-hops 20 --mtr-rounds 5

# Binary-search Path MTU (128..9000B) with Don't Fragment enabled
2ping 10.0.0.5 --mtu-discover
```

### 4. Modern AEAD Encryption (`ChaCha20-Poly1305`)

With `ChaCha20-Poly1305` (the default cipher), a single `--encrypt` secret provides full authenticated encryption over both the outer header and inner opcodes:

```bash
# Listener
2ping --listen --encrypt "shared-aead-secret"

# Client
2ping <LISTENER_IP_OR_HOST> -c 10 --encrypt "shared-aead-secret"
```

### 5. Legacy Compatibility Mode (`AES-256-CBC` + `HMAC`)

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

### 6. QoS DSCP Testing, JSON Logs & Prometheus Metrics

```bash
# Listener exposing Prometheus metrics on :9100
2ping --listen --metrics-port 9100

# Client testing Expedited Forwarding (EF) QoS queue with NDJSON output
2ping <LISTENER_IP_OR_HOST> -c 5 --dscp EF --json
```

### 7. Declarative TOML Config & Zero-Downtime Key Rotation

Create `2ping.toml`:

```toml
port = 15998
metrics_port = 9100
interval = 1.0
dscp = "EF"
adaptive = true
targets = ["10.0.0.5", "10.0.0.12"]

# Optional (requires --features webhooks):
# webhook_url = "https://slack.com"
# webhook_loss_threshold = 5.0
# webhook_rtt_threshold = 150.0

active_key_id = "2026-q4"

[[keys]]
id = "2026-q3"
encrypt_secret = "previous-quarter-secret-key"

[[keys]]
id = "2026-q4"
encrypt_secret = "current-quarter-secret-key"
```

Run with `--config` and reload keys or targets live at any time via `SIGHUP` (or by editing the file):

```bash
2ping --config 2ping.toml --tui

# Trigger manual hot-reload without restarting or resetting stats:
kill -HUP $(pidof 2ping)
```

### 8. Path MTU Discovery & QoS DSCP Probing

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
| `--config <FILE>` | — | Load fleet targets, ports, DSCP, and keyring from a TOML file (hot-reloaded) |
| `--keyring <FILE>` | — | Load multi-key rotation secrets from a TOML keyring file (hot-reloaded) |
| `--active-key-id <ID>` | First key | Key ID from keyring used to sign/encrypt outgoing packets |
| `--listen` | `false` | Start in dual-stack IPv4/IPv6 listener mode |
| `--mtr` | `false` | Run per-hop MTR path trace to target(s) |
| `--max-hops <N>` | `30` | Maximum TTL/hop limit for `--mtr` tracing |
| `--mtr-rounds <N>` | `3` | Probe rounds per hop for `--mtr` tracing |
| `--srv` | `false` | Resolve target hosts via `_2ping._udp.<domain>` DNS `SRV` records |
| `--mtu-discover` | `false` | Binary-search Path MTU (`128..9000` bytes) with Dont Fragment set |
| `--tui` | `false` | Launch interactive live terminal UI dashboard (`ratatui`) |
| `--adaptive` | `false` | Automatically back off probe interval during high packet loss (`>20%`) |
| `--webhook-url <URL>` | — | Webhook URL for degradation/recovery alerts *(requires `--features webhooks`)* |
| `--webhook-loss-threshold <PCT>` | `5.0` | Directional packet loss % threshold for webhook alerts *(requires `--features webhooks`)* |
| `--webhook-rtt-threshold <MS>` | — | Average RTT ms threshold for webhook alerts *(requires `--features webhooks`)* |
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
├── Cargo.toml                  # Crate manifest (`2ping` binary, library exports, optional `webhooks` feature)
├── Dockerfile                  # Multi-stage container build
├── docker-compose.yml          # Dual-stack listener, client, and TUI compose stack
├── .github/workflows/
│   ├── rust.yml                # PR formatting, Clippy, and test CI
│   └── release.yml             # Multi-arch static musl binaries + GHCR Docker release workflow
├── src/
│   ├── lib.rs                  # Library module exports and dual-stack target/SRV resolver
│   ├── main.rs                 # CLI parsing, socket setup, and mode dispatch
│   ├── config.rs               # TOML fleet configuration and keyring parser
│   ├── crypto.rs               # PBKDF2 key derivation, Multi-Key Ring, ChaCha20-Poly1305, AES-CBC, HMAC
│   ├── protocol.rs             # Binary wire encoding, decoding, OWD & KeyId opcodes, checksums
│   ├── timestamp.rs            # Linux SO_TIMESTAMPNS kernel receive timestamps & UTC wall clock
│   ├── reload.rs               # SIGHUP and filesystem watcher for zero-downtime hot-reloading
│   ├── mtr.rs                  # Per-hop TTL/ICMP path tracer
│   ├── webhooks.rs             # Compile-time gated webhook alert dispatcher
│   ├── tui.rs                  # Live Ratatui sparkline and directional loss terminal dashboard
│   └── engine.rs               # Async 3-way state machine, replay cache, MTU sweep, stats & metrics
└── tests/
└── protocol_and_crypto.rs  # Unit and multi-target loopback UDP integration tests
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
### 1. Copy the compiled release binary to /usr/local/bin
sudo cp target/release/2ping /usr/local/bin/2ping
sudo chmod 755 /usr/local/bin/2ping

### 2. Create the environment file (restrict permissions to root)
sudo bash -c 'echo "TWOPING_OPTS=\"--quiet\"" > /etc/default/2ping'
sudo chmod 600 /etc/default/2ping

### 3. Reload systemd, enable at boot, and start immediately
sudo systemctl daemon-reload
sudo systemctl enable --now 2ping.service

### 4. Verification & Firewall Notes

• Check service status and logs:bash

sudo systemctl status 2ping.service

sudo journalctl -u 2ping.service -f

    • Open UDP port 15998 in your firewall:

    • UFW (Ubuntu/Debian): sudo ufw allow 15998/udp

    • firewalld (RHEL/Fedora): sudo firewall-cmd --add-port=15998/udp 
    --permanent && sudo firewall-cmd --reload



## License

Inspired by Ryan Finnie's `2ping` utility (licensed under MPL-2.0).
