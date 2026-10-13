//! `prism-transport` — native pure-Rust UDP transport for PRISM.
//!
//! This is the runnable, no-native-dependency transport: real UDP sockets, a
//! Reality-style X25519 handshake, ChaCha20-Poly1305 payload protection, and the
//! same morphing / congestion-control machinery as the rest of the workspace.
//!
//! It reuses [`prism_morph`] (CDN Profile Replay), [`prism_cc`] (BBRv3-PRISM via
//! `CcGate`), [`prism_auth`] (Reality shadow-key) and [`prism_core`] (crypto and
//! deterministic seeding).
//!
//! ## Relationship to the quiche path
//!
//! This transport is wire-compatible *with itself*, not byte-identical to Chrome
//! QUIC. Byte-level indistinguishability requires the `quiche-backend`
//! (BoringSSL) path, which needs a native C/C++ toolchain. The native transport
//! exists so PRISM can run and be tested over a real network today, and so the
//! morph/congestion/auth logic is exercised end-to-end over actual sockets.

pub mod backend;
pub mod client;
pub mod conn;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod reliability;
pub mod scheduler;
pub mod server;
pub mod session;
pub mod stream;
pub mod varint;
pub mod wire;

pub use backend::TransportBackend;
pub use client::{ClientConfig, ClientConnection};
pub use conn::{Connection, ConnectionState, Side, StreamChunk};
pub use error::{Result, TransportError};
pub use server::{Server, ServerConfig};
pub use session::{PrismSession, PrismStream, SendJob};

#[cfg(test)]
mod e2e_tests {
    use super::*;
    use prism_core::crypto::X25519Secret;

    /// Full client<->server round trip over real loopback UDP sockets.
    #[tokio::test]
    async fn echo_round_trip_over_real_udp() {
        let shadow_sk = X25519Secret::generate();
        let shadow_pk = shadow_sk.public();
        let decoy = "www.cloudflare.com";

        // Bind the server on an ephemeral port.
        let mut srv = Server::bind(ServerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            shadow_sk,
            decoy,
        ))
        .await
        .unwrap();
        let server_addr = srv.local_addr().unwrap();

        // Drive the server in the background.
        let server_task = tokio::spawn(async move {
            // INIT + 3 data datagrams = 4 cycles.
            for _ in 0..4 {
                srv.serve_once().await.unwrap();
            }
        });

        // Connect and send three VPN packets, collecting echoes.
        let mut cli = ClientConnection::connect(ClientConfig::new(server_addr, shadow_pk, decoy))
            .await
            .unwrap();

        let payloads: Vec<Vec<u8>> = (0..3)
            .map(|i| format!("vpn-packet-{i}").into_bytes())
            .collect();

        for (i, p) in payloads.iter().enumerate() {
            cli.send_packet((i as u64) * 4, true, p).await.unwrap();
        }

        let mut echoed = Vec::new();
        for _ in 0..payloads.len() {
            let chunks = cli
                .recv_chunks(std::time::Duration::from_secs(2))
                .await
                .unwrap();
            for c in chunks {
                echoed.push(c.data.to_vec());
            }
        }

        server_task.await.unwrap();

        echoed.sort();
        let mut expected: Vec<Vec<u8>> = payloads.clone();
        expected.sort();
        assert_eq!(echoed, expected, "all VPN packets should round-trip over real UDP");
    }

    /// A client with the wrong decoy SNI must be rejected (no session established).
    #[tokio::test]
    async fn wrong_credentials_are_rejected() {
        let shadow_sk = X25519Secret::generate();
        let shadow_pk = shadow_sk.public();

        let mut srv = Server::bind(ServerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            shadow_sk,
            "real.decoy.example",
        ))
        .await
        .unwrap();
        let server_addr = srv.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            // INIT (rejected) + one data datagram (dropped) = 2 cycles.
            for _ in 0..2 {
                srv.serve_once().await.unwrap();
            }
        });

        // Client believes the decoy SNI is something else -> auth tag mismatch.
        let mut cli = ClientConnection::connect(ClientConfig::new(
            server_addr,
            shadow_pk,
            "attacker.guess.example",
        ))
        .await
        .unwrap();
        cli.send_packet(0, true, b"should-not-be-echoed").await.unwrap();

        // No echo should arrive.
        let res = cli.recv_chunks(std::time::Duration::from_millis(400)).await;
        assert!(matches!(res, Err(TransportError::Timeout)));

        server_task.await.unwrap();
    }
}
