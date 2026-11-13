# --- Stage 1: Build ---
FROM rust:1-bookworm AS builder

WORKDIR /usr/src/app

# Cache dependencies first
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    echo "" > src/lib.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source and tests, then build
COPY src ./src
COPY tests ./tests
RUN touch src/main.rs src/lib.rs && cargo build --release

# --- Stage 2: Minimal Runtime ---
FROM debian:bookworm-slim

RUN useradd -r -s /usr/sbin/nologin twoping

COPY --from=builder /usr/src/app/target/release/2ping /usr/local/bin/2ping

USER twoping
EXPOSE 15998/udp

ENTRYPOINT ["2ping"]
CMD ["--listen"]
