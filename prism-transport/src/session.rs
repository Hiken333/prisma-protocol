//! `PrismSession` / `PrismStream` — tokio integration with dedicated send/recv loops.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use prism_core::config::FecMode;
use prism_core::crypto::X25519Public;
use prism_morph::CdnProfile;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::conn::{ConnectionState, Side, StreamChunk};
use crate::crypto::SessionKeys;
use crate::error::{Result, TransportError};
use crate::handshake::ClientHandshake;

const SEND_QUEUE: usize = 1024;

/// Work item for the central send loop.
#[derive(Debug)]
pub enum SendJob {
    StreamData {
        id: u64,
        fin: bool,
        data: Bytes,
    },
    Ping,
    Shutdown,
}

struct SessionInner {
    state: Mutex<ConnectionState>,
    socket: Arc<UdpSocket>,
    send_tx: mpsc::Sender<SendJob>,
    shutdown: CancellationToken,
    peer: Option<SocketAddr>,
}

/// Established PRISM session with background I/O tasks.
pub struct PrismSession {
    inner: Arc<SessionInner>,
    send_handle: tokio::task::JoinHandle<()>,
    recv_handle: tokio::task::JoinHandle<()>,
}

impl PrismSession {
    /// Connect as client (Reality INIT + spawn loops).
    pub async fn connect(
        server: SocketAddr,
        shadow_pk: X25519Public,
        decoy_sni: impl Into<String>,
        profile: CdnProfile,
        jitter_pct: f64,
        mtu: usize,
        perf_mode: bool,
    ) -> Result<Self> {
        let bind: SocketAddr = if server.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        socket.connect(server).await?;

        let hs = ClientHandshake::new(&shadow_pk, &decoy_sni.into(), 1200);
        socket.send(hs.init_packet()).await?;
        let keys = SessionKeys::derive(&hs.shared, true)?;
        let state = ConnectionState::with_options(
            keys,
            Side::Client,
            profile,
            jitter_pct,
            mtu,
            perf_mode,
            FecMode::Auto,
        )?;

        Self::spawn(socket, state, Some(server)).await
    }

    /// Wrap an existing server-side connection (after INIT accepted).
    pub async fn from_server(
        socket: Arc<UdpSocket>,
        state: ConnectionState,
        peer: SocketAddr,
    ) -> Result<Self> {
        Self::spawn(socket, state, Some(peer)).await
    }

    async fn spawn(
        socket: Arc<UdpSocket>,
        state: ConnectionState,
        peer: Option<SocketAddr>,
    ) -> Result<Self> {
        let (send_tx, send_rx) = mpsc::channel(SEND_QUEUE);
        let shutdown = CancellationToken::new();
        let inner = Arc::new(SessionInner {
            state: Mutex::new(state),
            socket: Arc::clone(&socket),
            send_tx,
            shutdown: shutdown.clone(),
            peer,
        });

        let send_inner = Arc::clone(&inner);
        let send_handle = tokio::spawn(async move {
            send_loop(send_inner, send_rx).await;
        });

        let recv_inner = Arc::clone(&inner);
        let recv_handle = tokio::spawn(async move {
            recv_loop(recv_inner).await;
        });

        Ok(Self {
            inner,
            send_handle,
            recv_handle,
        })
    }

    /// Open a logical stream (multiplexed on one UDP port).
    pub fn open_stream(&self, id: u64) -> PrismStream {
        PrismStream {
            id,
            inner: Arc::clone(&self.inner),
            read_rx: None,
        }
    }

    pub fn open_stream_with_channel(
        &self,
        id: u64,
        read_rx: mpsc::Receiver<Bytes>,
    ) -> PrismStream {
        PrismStream {
            id,
            inner: Arc::clone(&self.inner),
            read_rx: Some(read_rx),
        }
    }

    pub async fn send_on_stream(&self, stream_id: u64, fin: bool, data: Bytes) -> Result<()> {
        self.inner
            .send_tx
            .send(SendJob::StreamData { id: stream_id, fin, data })
            .await
            .map_err(|_| TransportError::Closed)
    }

    pub async fn recv_chunks(&self, wait: Duration) -> Result<Vec<StreamChunk>> {
        let mut buf = vec![0u8; 2048];
        let n = tokio::time::timeout(wait, self.inner.socket.recv(&mut buf))
            .await
            .map_err(|_| TransportError::Timeout)??;
        let mut st = self.inner.state.lock().await;
        st.open_datagram(&buf[..n]).await
    }

    pub fn shutdown(&self) {
        self.inner.shutdown.cancel();
        let tx = self.inner.send_tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(SendJob::Shutdown).await;
        });
    }

    /// Read in-order bytes from a stream after the background recv loop delivers them.
    pub async fn read_stream(&self, stream_id: u64, out: &mut [u8]) -> Result<(usize, bool)> {
        let mut st = self.inner.state.lock().await;
        st.read_stream(stream_id, out)
    }

    /// Unacked datagram count (for diagnostics / tests).
    pub async fn unacked_packet_count(&self) -> usize {
        self.inner.state.lock().await.unacked_packet_count()
    }
}

impl Drop for PrismSession {
    fn drop(&mut self) {
        self.shutdown();
        self.send_handle.abort();
        self.recv_handle.abort();
    }
}

/// One multiplexed stream inside a session.
pub struct PrismStream {
    id: u64,
    inner: Arc<SessionInner>,
    read_rx: Option<mpsc::Receiver<Bytes>>,
}

impl PrismStream {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub async fn write(&self, data: Bytes, fin: bool) -> Result<()> {
        self.inner
            .send_tx
            .send(SendJob::StreamData {
                id: self.id,
                fin,
                data,
            })
            .await
            .map_err(|_| TransportError::Closed)
    }

    pub async fn read(&mut self) -> Option<Bytes> {
        if let Some(rx) = &mut self.read_rx {
            rx.recv().await
        } else {
            None
        }
    }

    pub async fn set_priority(&self, priority: u32) -> Result<()> {
        let mut st = self.inner.state.lock().await;
        st.set_stream_priority(self.id, priority)
    }
}

async fn send_loop(inner: Arc<SessionInner>, mut rx: mpsc::Receiver<SendJob>) {
    while !inner.shutdown.is_cancelled() {
        let job = match tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
            Ok(Some(j)) => j,
            Ok(None) => break,
            Err(_) => {
                // Periodic flush for ACKs / retransmits.
                flush_send(&inner).await;
                continue;
            }
        };

        match job {
            SendJob::Shutdown => break,
            SendJob::StreamData { id, fin, data } => {
                {
                    let mut st = inner.state.lock().await;
                    if st.queue_send(id, data, fin).is_err() {
                        continue;
                    }
                }
                flush_send(&inner).await;
            }
            SendJob::Ping => {
                let mut frames = Vec::new();
                crate::frame::encode_ping(&mut frames);
                let dgram = {
                    let mut st = inner.state.lock().await;
                    st.seal_datagram(frames).ok()
                };
                if let Some(dgram) = dgram {
                    let _ = send_datagram(&inner, &dgram).await;
                }
            }
        }
    }
}

async fn flush_send(inner: &Arc<SessionInner>) {
    loop {
        let dgram = {
            let mut st = inner.state.lock().await;
            match st.build_datagram() {
                Ok(Some(d)) => d,
                Ok(None) => break,
                Err(_) => break,
            }
        };
        if send_datagram(inner, &dgram).await.is_err() {
            break;
        }
        let delay = {
            let mut st = inner.state.lock().await;
            st.delay()
        };
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
}

async fn send_datagram(inner: &Arc<SessionInner>, dgram: &[u8]) -> Result<()> {
    let st = inner.state.lock().await;
    st.pace(dgram.len()).await;
    drop(st);
    if let Some(peer) = inner.peer {
        inner.socket.send_to(dgram, peer).await?;
    } else {
        inner.socket.send(dgram).await?;
    }
    Ok(())
}

async fn recv_loop(inner: Arc<SessionInner>) {
    let mut buf = vec![0u8; 2048];
    while !inner.shutdown.is_cancelled() {
        let n = match inner.socket.recv(&mut buf).await {
            Ok(n) => n,
            Err(_) => continue,
        };
        let mut st = inner.state.lock().await;
        let _ = st.open_datagram(&buf[..n]).await;
    }
}
