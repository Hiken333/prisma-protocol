//! Server side of the native UDP transport.
//!
//! Listens on a single UDP socket, classifies each client's Reality INIT, and
//! either establishes a PRISM connection (echoing VPN streams back) or hands the
//! traffic to the decoy proxy. Rejected/garbage traffic is dropped silently —
//! there is no distinguishable rejection (§3.3).

use std::collections::HashMap;
use std::net::SocketAddr;

use prism_core::crypto::X25519Secret;
use prism_decoy::DecoyProxy;
use prism_morph::CdnProfile;
use tokio::net::UdpSocket;

use crate::conn::{self, Connection, Side};
use crate::crypto::SessionKeys;
use crate::error::Result;
use crate::handshake::{self, ServerAuth};
use crate::wire;

/// Server configuration.
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub shadow_sk: X25519Secret,
    pub decoy_sni: String,
    /// If set, rejected clients are transparently proxied here.
    pub decoy: Option<DecoyProxy>,
    pub profile: CdnProfile,
    pub jitter_pct: f64,
    pub mtu: usize,
}

impl ServerConfig {
    pub fn new(listen: SocketAddr, shadow_sk: X25519Secret, decoy_sni: impl Into<String>) -> Self {
        Self {
            listen,
            shadow_sk,
            decoy_sni: decoy_sni.into(),
            decoy: None,
            profile: CdnProfile::synthetic_chrome(),
            jitter_pct: 0.10,
            mtu: 1400,
        }
    }
}

/// Handle to a running server.
pub struct Server {
    sock: UdpSocket,
    cfg: ServerConfig,
    peers: HashMap<SocketAddr, Connection>,
}

impl Server {
    pub async fn bind(cfg: ServerConfig) -> Result<Self> {
        let sock = UdpSocket::bind(cfg.listen).await?;
        tracing::info!(listen = %cfg.listen, decoy = %cfg.decoy_sni, "PRISM UDP server listening");
        Ok(Self { sock, cfg, peers: HashMap::new() })
    }

    /// The bound local address (useful when binding to port 0 in tests).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.sock.local_addr()?)
    }

    /// Serve a single datagram cycle. Returns after handling one packet, so a
    /// caller can loop or bound the number of iterations (tests).
    pub async fn serve_once(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 2048];
        let (n, from) = self.sock.recv_from(&mut buf).await?;
        let dgram = &buf[..n];

        if wire::is_init(dgram) {
            self.handle_init(dgram, from).await?;
        } else if conn::looks_like_data(dgram) {
            self.handle_data(dgram, from).await?;
        } else {
            tracing::debug!(%from, len = n, "dropping unrecognized datagram");
        }
        Ok(())
    }

    /// Serve forever.
    pub async fn run(mut self) -> Result<()> {
        loop {
            if let Err(e) = self.serve_once().await {
                tracing::warn!(error = %e, "serve cycle error");
            }
        }
    }

    async fn handle_init(&mut self, dgram: &[u8], from: SocketAddr) -> Result<()> {
        let view = match handshake::parse_init(dgram) {
            Ok(v) => v,
            Err(_) => return self.maybe_decoy(dgram, from).await,
        };

        match handshake::server_classify(&self.cfg.shadow_sk, &self.cfg.decoy_sni, &view) {
            ServerAuth::Accept { shared } => {
                let keys = SessionKeys::derive(&shared, false)?;
                let conn = Connection::new(
                    keys,
                    Side::Server,
                    self.cfg.profile.clone(),
                    self.cfg.jitter_pct,
                    self.cfg.mtu,
                )?;
                self.peers.insert(from, conn);
                tracing::info!(%from, "Reality handshake ACCEPT -> PRISM session established");
                Ok(())
            }
            ServerAuth::Reject => {
                tracing::info!(%from, "Reality handshake REJECT -> decoy/drop (indistinguishable)");
                self.maybe_decoy(dgram, from).await
            }
        }
    }

    async fn handle_data(&mut self, dgram: &[u8], from: SocketAddr) -> Result<()> {
        let Some(conn) = self.peers.get_mut(&from) else {
            tracing::debug!(%from, "data from unknown peer -> drop");
            return Ok(());
        };

        let chunks = match conn.open_datagram(dgram).await {
            Ok(c) => c,
            Err(_) => {
                tracing::debug!(%from, "failed to open datagram -> drop");
                return Ok(());
            }
        };

        // Demo behavior: echo each received VPN stream back to the client. In a
        // real deployment this is where decoded IP packets would be written to
        // the server-side TUN / forwarded upstream.
        for chunk in chunks {
            let frames = Connection::encode_stream(chunk.stream_id, chunk.offset, chunk.fin, &chunk.data);
            let reply = conn.seal_datagram(frames)?;
            conn.pace(reply.len()).await;
            self.sock.send_to(&reply, from).await?;
            tracing::info!(%from, stream = chunk.stream_id, bytes = chunk.data.len(), "echoed VPN stream");
        }
        Ok(())
    }

    /// Forward to the decoy origin if configured, otherwise drop silently.
    async fn maybe_decoy(&self, dgram: &[u8], from: SocketAddr) -> Result<()> {
        if let Some(decoy) = &self.cfg.decoy {
            if let Err(e) = decoy.relay_udp(dgram, from, &self.sock).await {
                tracing::debug!(%from, error = %e, "decoy relay ended");
            }
        }
        Ok(())
    }
}
