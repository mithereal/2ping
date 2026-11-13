
# twoping (2ping-rs)

A fast, asynchronous Rust implementation of **2ping**, a bi-directional UDP ping utility. Using 3-way handshakes (akin to TCP `SYN`, `SYN/ACK`, `ACK`) and after-the-fact state comparison between a listener and a client, `twoping` identifies whether packet loss occurs on the **outbound** or **inbound** path.

---

## Features

- **Directional Packet Loss Detection:** Distinguishes between outbound loss, inbound loss, and undetermined loss using 3-way UDP exchanges and `Investigate` / `CourtesyExpires` state tracking.
- **2ping Wire Protocol Compatible:** Implements the `0x3250` ("2P") big-endian binary header, 16-bit one's complement checksums, 48-bit random Message IDs, and standard opcode flags.
- **HMAC Packet Authentication:** Supports constant-time packet signing and verification using `hmac-sha256`, `hmac-sha512`, or `hmac-md5` (`--auth` / `--auth-digest`).
- **AES-256-CBC Payload Encryption:** Encrypts inner opcodes and metadata with a fresh 16-byte random IV per packet in an **Encrypt-then-MAC** layout (`--encrypt`).
- **Async Tokio Engine:** Built on `tokio` for non-blocking UDP I/O, background state garbage collection, and clean `Ctrl+C` summary statistics.

---

## Installation

### Prerequisites
- Rust toolchain (`1.70+` recommended)

### Build from Source

```bash
git clone <your-repo-url>
cd 2ping-rs
cargo build --release
```

The compiled binary will be available at `target/release/twoping`.

---

## Usage

### 1. Basic Plaintext Mode

Start a listener on the remote host (binds to UDP port `15998` by default):

```bash
./target/release/twoping --listen
```

Connect from the client machine:

```bash
./target/release/twoping <LISTENER_IP_OR_HOST>
```

### 2. Authenticated & Encrypted Mode

Start a listener requiring both HMAC-SHA512 authentication and AES-256-CBC encryption:

```bash
./target/release/twoping --listen \
  --auth "shared-hmac-secret" \
  --auth-digest hmac-sha512 \
  --encrypt "shared-aes-secret"
```

Connect from the client with matching keys:

```bash
./target/release/twoping <LISTENER_IP_OR_HOST> \
  -c 10 \
  --auth "shared-hmac-secret" \
  --auth-digest hmac-sha512 \
  --encrypt "shared-aes-secret"
```

---

## CLI Options

| Flag | Default | Description |
| :--- | :--- | :--- |
| `<HOST>` | — | Hostname or IP address of the `2ping` listener (client mode) |
| `--listen` | `false` | Start in listener mode |
| `--port <PORT>` | `15998` | UDP port to bind (listener) or connect to (client) |
| `-c, --count <N>` | Infinite | Stop after sending `N` pings |
| `-i, --interval <SEC>` | `1.0` | Wait interval in seconds between sending packets |
| `--min-packet-size <BYTES>` | `128` | Minimum wire packet size in bytes |
| `-s <BYTES>` | — | Ping compatibility payload size (`min-packet-size = bytes + 8`) |
| `-p, --pattern <HEX>` | `00` | Hex byte pattern used to pad packets (e.g., `deadbeef`) |
| `--auth <SECRET>` | — | Shared secret for HMAC packet authentication |
| `--auth-digest <ALG>` | `hmac-sha256` | HMAC algorithm (`hmac-md5`, `hmac-sha256`, `hmac-sha512`) |
| `--encrypt <SECRET>` | — | Shared secret for AES-256-CBC payload encryption |
| `--encrypt-method <ALG>` | `aes256-cbc` | Encryption cipher method |
| `--no-3way` | `false` | Disable 3-way pings (use standard 2-way request/reply) |
| `-q, --quiet` | `false` | Quiet output (only display startup and final summary) |
| `-v, --verbose` | `false` | Print per-packet decode and drop diagnostics |

---

## Project Architecture

```text
2ping-rs/
├── Cargo.toml                  # Dependencies (tokio, clap, rustcrypto crates)
├── src/
│   ├── lib.rs                  # Library module exports
│   ├── main.rs                 # CLI argument parsing and socket setup
│   ├── crypto.rs               # PBKDF2 key derivation, HMAC, and AES-256-CBC
│   ├── protocol.rs             # Binary wire encoding, decoding, and checksums
│   └── engine.rs               # Async 3-way state machine and loss statistics
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

## License

This project is inspired by Ryan Finnie's `2ping` utility (licensed under MPL-2.0). Choose and include the license file appropriate for your distribution.
