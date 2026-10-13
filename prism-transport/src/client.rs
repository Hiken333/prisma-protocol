//! Client side of the native UDP transport: real socket, Reality handshake,
//! then morph-shaped, AEAD-protected data datagrams.

use std::net::SocketAddr;
use std::time::Duration;

use prism_core::crypto::X25519Public;
use prism_morph::CdnProfile;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::conn::{Connection, Side, StreamChunk};
use crate::crypto::SessionKeys;
use crate::error::{Result, TransportError};
use crate::handshake::ClientHandshake;

/// Client connection configuration.
pub struct ClientConfig {
    pub server: SocketAddr,
    pub shadow_pk: X25519Public,
    pub decoy_sni: String,
    pub profile: CdnProfile,
    pub jitter_pct: f64,
    pub mtu: usize,
    pub handshake_pad: usize,
}

impl ClientConfig {
    pub fn new(server: SocketAddr, shadow_pk: X25519Public, decoy_sni: impl Into<String>) -> Self {
        Self {
            server,
            shadow_pk,
            decoy_sni: decoy_sni.into(),
            profile: CdnProfile::synthetic_chrome(),
            jitter_pct: 0.10,
            mtu: 1400,
            handshake_pad: 1200,
        }
    }
}

/// An established client connection.
pub struct ClientConnection {
    sock: UdpSocket,
    conn: Connection,
}

impl ClientConnection {
    /// Perform the handshake over a real UDP socket and return the connection.
    pub async fn connect(cfg: ClientConfig) -> Result<Self> {
        let bind: SocketAddr = if cfg.server.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let sock = UdpSocket::bind(bind).await?;
        sock.connect(cfg.server).await?;

        // Phase 1: send the Reality INIT.
        let hs = ClientHandshake::new(&cfg.shadow_pk, &cfg.decoy_sni, cfg.handshake_pad);
        sock.send(hs.init_packet()).await?;
        tracing::info!(server = %cfg.server, pad = cfg.handshake_pad, "sent Reality INIT");

        // Derive keys from the shadow shared secret (no extra round trip needed).
        let keys = SessionKeys::derive(&hs.shared, true)?;
        let conn = Connection::new(keys, Side::Client, cfg.profile, cfg.jitter_pct, cfg.mtu)?;

        Ok(Self { sock, conn })
    }

    /// Send one VPN payload on `stream_id` as a morph-shaped datagram.
    pub async fn send_packet(&mut self, stream_id: u64, fin: bool, payload: &[u8]) -> Result<()> {
        let frames = Connection::encode_stream(stream_id, 0, fin, payload);
        let dgram = self.conn.seal_datagram(frames)?;
        self.conn.pace(dgram.len()).await;
        self.sock.send(&dgram).await?;
        tokio::time::sleep(self.conn.delay()).await;
        Ok(())
    }

    /// Receive and decode one inbound datagram, with a timeout.
    pub async fn recv_chunks(&mut self, wait: Duration) -> Result<Vec<StreamChunk>> {
        let mut buf = vec![0u8; 2048];
        let n = match timeout(wait, self.sock.recv(&mut buf)).await {
            Ok(r) => r?,
            Err(_) => return Err(TransportError::Timeout),
        };
        self.conn.open_datagram(&buf[..n]).await
    }
}
