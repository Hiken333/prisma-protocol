//! Transparent reverse proxy to the decoy origin.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::error::DecoyError;

/// Forwards probe traffic to the real decoy origin without modification.
#[derive(Clone, Debug)]
pub struct DecoyProxy {
    origin: SocketAddr,
    /// Idle timeout for spliced UDP flows.
    udp_idle: Duration,
}

impl DecoyProxy {
    pub fn new(origin: SocketAddr) -> Self {
        Self { origin, udp_idle: Duration::from_secs(30) }
    }

    pub fn resolve(origin: &str) -> Result<Self, DecoyError> {
        let addr = origin
            .parse::<SocketAddr>()
            .map_err(|e| DecoyError::Address(format!("{origin}: {e}")))?;
        Ok(Self::new(addr))
    }

    /// TCP/443 fallback: splice the inbound connection to the decoy origin.
    ///
    /// The probe sees the real TLS termination (nginx/caddy) — indistinguishable
    /// from connecting to the CDN directly.
    pub async fn relay_tcp(&self, mut inbound: TcpStream) -> Result<(), DecoyError> {
        let mut upstream = TcpStream::connect(self.origin).await?;
        let _ = copy_bidirectional(&mut inbound, &mut upstream).await?;
        upstream.shutdown().await.ok();
        inbound.shutdown().await.ok();
        Ok(())
    }

    /// UDP/QUIC fallback: forward `first` (the original Initial datagram,
    /// byte-for-byte) and then splice subsequent datagrams between `client` and
    /// the decoy origin over a dedicated upstream socket.
    ///
    /// `down` is the listening server socket used to reach the client; replies
    /// from the decoy are sent back to `client` through it.
    pub async fn relay_udp(
        &self,
        first: &[u8],
        client: SocketAddr,
        down: &UdpSocket,
    ) -> Result<(), DecoyError> {
        let bind: SocketAddr = if self.origin.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let up = UdpSocket::bind(bind).await?;
        up.connect(self.origin).await?;

        // Forward the original Initial unchanged.
        up.send(first).await?;

        let mut buf = vec![0u8; 65535];
        loop {
            // Decoy -> client.
            match tokio::time::timeout(self.udp_idle, up.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    down.send_to(&buf[..n], client).await?;
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => return Ok(()), // idle timeout: tear down silently
            }
        }
    }

    pub fn origin(&self) -> SocketAddr {
        self.origin
    }
}
