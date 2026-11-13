# 2ping (twoping-rs)

A fast, asynchronous Rust rewrite of **2ping**, a bi-directional UDP ping utility. Using 3-way handshakes (akin to TCP `SYN`, `SYN/ACK`, `ACK`) and after-the-fact state comparison between a listener and a client, `2ping` determines whether packet loss occurs on the **outbound** or **inbound** path.

---

## Differences from the Original Python `2ping`

While remaining compatible with the core `2ping` binary wire framing (`0x3250` magic header, 16-bit one's complement checksums, 48-bit Message IDs, and standard opcodes), this Rust implementation introduces major upgrades in timing accuracy, cryptography, observability, and runtime performance:

| Feature / Capability | Original Python `2ping` | Rust `2ping` (`v0.4.0`) |
| :--- | :--- | :--- |
| **Runtime & Concurrency** | Single-threaded Python 3 event loop with optional external dependencies (`pycryptodomex`, `dnspython`, `netifaces`) | Compiled native binary powered by `tokio` async I/O with zero runtime interpreter overhead |
| **Receive Timestamps** | User-space `time.time()` calls subject to Python GIL and event-loop wakeup jitter | Kernel nanosecond receive timestamps via `SO_TIMESTAMPNS` / `SCM_TIMESTAMPNS` (`recvmsg`) on Linux |
| **Host Processing Delay** | Parses `HostLatency` (`0x0010`) | Measures exact listener processing time in microseconds and subtracts it from client RTT to isolate true network transit latency |
| **Statistical Output** | Basic `min / avg / max` RTT and directional loss percentages | Adds standard deviation (`mdev`), RFC 3550 smoothed inter-packet jitter, and tail latency percentiles (`p50 / p95 / p99`) |
| **Encryption & Auth** | Separate `AES-256-CBC` + `HMAC` (`hmac-md5`, `hmac-sha256`, `hmac-sha512`) | Defaults to modern **`ChaCha20-Poly1305` AEAD** (authenticating the 12-byte outer header as Associated Data) while retaining `AES-256-CBC` + `HMAC` compatibility |
| **Replay Protection** | Relies on short-lived state cleanup | Dedicated bounded sliding-window `ReplayCache` (30s TTL, 10,000 entries per peer) dropping duplicate Message IDs |
| **QoS / DiffServ Marking** | Not available natively | Built-in `--dscp` flag (`EF`, `AF41`, `CS5`, or `0..63`) setting `IP_TOS` / `IPV6_TCLASS` |
| **Telemetry & Observability** | Human-readable stdout text only | Native `--json` (NDJSON) streaming output and an optional `--metrics-port` Prometheus `/metrics` HTTP endpoint |

---

## Features

- **Directional Packet Loss Detection:** Distinguishes between outbound loss, inbound loss, and undetermined loss using 3-way UDP exchanges and `Investigate` / `CourtesyExpires` state tracking.
- **Kernel-Level Precision:** Uses Linux `SO_TIMESTAMPNS` ancillary messages and `HostLatency` subtraction to eliminate user-space scheduling jitter.
- **Tail Latency & Jitter Metrics:** Reports `min/avg/max/mdev`, RFC 3550 jitter, and `p50/p95/p99` percentiles.
- **Modern AEAD & Legacy Crypto:** Supports `ChaCha20-Poly1305` AEAD encryption (default) as well as `AES-256-CBC` and constant-time `HMAC` (`hmac-md5`, `hmac-sha256`, `hmac-sha512`).
- **Anti-Replay Protection:** Rejects replayed UDP datagrams using a per-peer sliding-window cache.
- **SRE & DevOps Ready:** Supports `--json` NDJSON event logging, `--dscp` QoS queue testing, and a built-in Prometheus `/metrics` endpoint.

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

---

## CLI Options

| Flag | Default | Description |
| :--- | :--- | :--- |
| `<HOST>` | — | Hostname or IP address of the `2ping` listener (client mode) |
| `--listen` | `false` | Start in listener mode |
| `--port <PORT>` | `15998` | UDP port to bind (listener) or connect to (client) |
| `--metrics-port <PORT>` | — | Expose Prometheus `/metrics` HTTP endpoint on the specified port |
| `-c, --count <N>` | Infinite | Stop after sending `N` pings |
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
├── Cargo.toml                  # Crate config (outputs `2ping` binary) and dependencies
├── Dockerfile                  # Multi-stage container build
├── docker-compose.yml          # Listener + client test stack
└── src/
    ├── lib.rs                  # Library module exports
    ├── main.rs                 # CLI parsing, DSCP socket setup, and entrypoint
    ├── crypto.rs               # PBKDF2 key derivation, ChaCha20-Poly1305, AES-256-CBC, HMAC
    ├── protocol.rs             # Binary wire encoding, decoding, and checksums
    ├── timestamp.rs            # Linux SO_TIMESTAMPNS kernel receive timestamps
    └── engine.rs               # Async 3-way state machine, replay cache, stats, and metrics
└── tests/
    └── protocol_and_crypto.rs  # Unit and loopback UDP integration tests
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
