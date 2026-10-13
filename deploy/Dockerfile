# PRISM test server — quiche-backend + Linux TUN.
# Build context: prism/ directory (docker compose sets context: ..)

# Match rust-toolchain.toml (1.75.0) — avoids re-downloading rustc inside the container.
FROM rust:1.75-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake clang llvm-dev libclang-dev perl pkg-config git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rustup set profile minimal

WORKDIR /build
COPY rust-toolchain.toml ./
RUN rustup show

COPY . .

RUN cargo build --release -p prism-server \
    --features quiche-backend,tunnel

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates iptables iproute2 openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/prism-server /usr/local/bin/prism-server
COPY deploy/entrypoint.sh /entrypoint.sh
# Strip Windows CRLF — otherwise Linux reports "exec /entrypoint.sh: no such file or directory"
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
