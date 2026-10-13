//! BOLT data plane for TUN mode (MVP).
#![cfg(feature = "tunnel")]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use prism_bolt::{BoltCipher, BoltDirection, BoltSession, BrutalPacer, WireLayout, WIRE_SIZE_MAX};
use prism_core::PrismExporter;
use prism_core::EXPORTER_LEN;
use prism_tun::PlatformTun;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::agent_debug;
use crate::backend::QuicBackend;
use crate::error::{QuicError, Result};
use crate::live::{bolt_active, flush, pump_recv_once_for_peer, PeerPumpOutcome, PEER_IDLE_RELEASE};
use crate::quiche_backend::QuicheBackend;
use crate::tunnel::{framed_ip_packet_len, ipv4_dst};

const TUN_READ_TIMEOUT: Duration = Duration::from_millis(1);
const BOLT_KEEPALIVE: Duration = Duration::from_secs(1);
const TUN_UPLOAD_BURST: usize = 2048;
const FLUSH_LANE_BATCH: usize = 32;
const SEND_TASK_BATCH: usize = 2048;
const SEND_FLUSH_ROUNDS: usize = 32;
const INGEST_FLUSH_EVERY: usize = 64;
const TUN_IDLE_SLEEP: Duration = Duration::from_micros(250);

async fn bolt_loop_cooperate(idle: bool) {
    if idle {
        tokio::time::sleep(TUN_IDLE_SLEEP).await;
    } else {
        tokio::task::yield_now().await;
    }
}

struct BoltStatsView {
    wire_layout: WireLayout,
    turbo: bool,
    frames_sent: Arc<AtomicU64>,
    frames_recv: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    bytes_recv: Arc<AtomicU64>,
    peak_mbps_bits: Arc<AtomicU64>,
}

impl BoltStatsView {
    fn pacer_peak_mbps(&self) -> f64 {
        let bits = self.peak_mbps_bits.load(Ordering::Relaxed);
        if bits == 0 {
            0.0
        } else {
            f64::from_bits(bits)
        }
    }

    fn pacer_mbps(&self) -> f64 {
        prism_bolt::bolt_mbps_from_env()
    }
}

struct BoltDiag {
    role: &'static str,
    loop_iters: u64,
    tun_pkts_in: u64,
    tun_bytes_in: u64,
    tun_pkts_out: u64,
    tun_bytes_out: u64,
    tun_rx_queued: u64,
    upload_queued: u64,
    flush_frames_last_tick: u64,
    last_emit: Instant,
}

impl BoltDiag {
    fn new(role: &'static str) -> Self {
        Self {
            role,
            loop_iters: 0,
            tun_pkts_in: 0,
            tun_bytes_in: 0,
            tun_pkts_out: 0,
            tun_bytes_out: 0,
            tun_rx_queued: 0,
            upload_queued: 0,
            flush_frames_last_tick: 0,
            last_emit: Instant::now(),
        }
    }

    fn maybe_emit(
        &mut self,
        stats: &BoltStatsView,
        tun_rx_pending: &AtomicUsize,
        upload_pending: &AtomicUsize,
    ) {
        if self.last_emit.elapsed() < Duration::from_secs(5) {
            return;
        }
        let bolt_frames_tx = stats.frames_sent.load(Ordering::Relaxed);
        let bolt_frames_rx = stats.frames_recv.load(Ordering::Relaxed);
        let bolt_bytes_tx = stats.bytes_sent.load(Ordering::Relaxed);
        let bolt_bytes_rx = stats.bytes_recv.load(Ordering::Relaxed);
        self.tun_rx_queued = tun_rx_pending.load(Ordering::Relaxed) as u64;
        self.upload_queued = upload_pending.load(Ordering::Relaxed) as u64;
        // #region agent log
        agent_debug::log(
            "B1",
            "bolt_tunnel.rs:tick",
            "bolt_tunnel_tick",
            &format!(
                r#"{{"role":"{}","loop_iters":{},"tun_pkts_in":{},"tun_bytes_in":{},"tun_pkts_out":{},"tun_bytes_out":{},"bolt_frames_tx":{},"bolt_frames_rx":{},"bolt_bytes_tx":{},"bolt_bytes_rx":{},"pacer_mbps":{},"pacer_peak_mbps":{},"lanes":{},"turbo":{},"wire_size":{},"tun_rx_queued":{},"upload_queued":{},"flush_frames_5s":{}}}"#,
                self.role,
                self.loop_iters,
                self.tun_pkts_in,
                self.tun_bytes_in,
                self.tun_pkts_out,
                self.tun_bytes_out,
                bolt_frames_tx,
                bolt_frames_rx,
                bolt_bytes_tx,
                bolt_bytes_rx,
                stats.pacer_mbps(),
                stats.pacer_peak_mbps(),
                prism_bolt::bolt_lanes_from_env(),
                stats.turbo,
                stats.wire_layout.wire_size,
                self.tun_rx_queued,
                self.upload_queued,
                self.flush_frames_last_tick,
            ),
        );
        log_debug_session46756b(
            "B1",
            "bolt_tunnel.rs:tick",
            "bolt_tunnel_tick",
            &format!(
                r#"{{"role":"{}","tun_rx_queued":{},"upload_queued":{},"pacer_peak_mbps":{},"wire_size":{},"tun_bytes_out":{},"tun_bytes_in":{}}}"#,
                self.role,
                self.tun_rx_queued,
                self.upload_queued,
                stats.pacer_peak_mbps(),
                stats.wire_layout.wire_size,
                self.tun_bytes_out,
                self.tun_bytes_in,
            ),
        );
        // #endregion
        self.flush_frames_last_tick = 0;
        self.last_emit = Instant::now();
    }
}

enum BoltSendCmd {
    Packet(Vec<u8>),
    Shutdown,
}

struct BoltSendGuard {
    cmd_tx: mpsc::UnboundedSender<BoltSendCmd>,
    join: JoinHandle<()>,
}

impl BoltSendGuard {
    async fn shutdown(self) {
        let _ = self.cmd_tx.send(BoltSendCmd::Shutdown);
        let _ = self.join.await;
    }
}

async fn drain_tun_downlink(
    tun: &mut PlatformTun,
    tun_pkts_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    tun_rx_pending: &AtomicUsize,
    diag: &mut BoltDiag,
) -> Result<u32> {
    let mut n = 0u32;
    while let Ok(pkt) = tun_pkts_rx.try_recv() {
        let len = pkt.len();
        tun.write_packet(&pkt)
            .await
            .map_err(|e| QuicError::Backend(format!("tun write: {e}")))?;
        tun_rx_pending.fetch_sub(1, Ordering::Relaxed);
        diag.tun_pkts_out += 1;
        diag.tun_bytes_out += len as u64;
        n += 1;
    }
    Ok(n)
}

fn touch_bolt_activity(
    last_activity: &mut Instant,
    stats: &BoltStatsView,
    last_rx_frames: &mut u64,
    last_tx_frames: &mut u64,
    upload_pending: &AtomicUsize,
) {
    let rx = stats.frames_recv.load(Ordering::Relaxed);
    let tx = stats.frames_sent.load(Ordering::Relaxed);
    if rx > *last_rx_frames || tx > *last_tx_frames {
        *last_activity = Instant::now();
        *last_rx_frames = rx;
        *last_tx_frames = tx;
    }
    if upload_pending.load(Ordering::Relaxed) > 0 {
        *last_activity = Instant::now();
    }
}

struct TunDownlinkGuard {
    join: JoinHandle<()>,
}

impl TunDownlinkGuard {
    async fn shutdown(self) {
        self.join.abort();
        let _ = self.join.await;
    }
}

fn spawn_tun_downlink_writer(
    tun: Arc<Mutex<PlatformTun>>,
    mut tun_pkts_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    tun_rx_pending: Arc<AtomicUsize>,
    tun_pkts_out: Arc<AtomicU64>,
    tun_bytes_out: Arc<AtomicU64>,
) -> TunDownlinkGuard {
    let join = tokio::spawn(async move {
        while let Some(pkt) = tun_pkts_rx.recv().await {
            let len = pkt.len();
            let write = async {
                let mut t = tun.lock().await;
                t.write_packet(&pkt).await
            };
            match write.await {
                Ok(()) => {
                    tun_rx_pending.fetch_sub(1, Ordering::Relaxed);
                    tun_pkts_out.fetch_add(1, Ordering::Relaxed);
                    tun_bytes_out.fetch_add(len as u64, Ordering::Relaxed);
                }
                Err(e) => tracing::debug!(error = %e, "BOLT tun downlink write error"),
            }
        }
    });
    TunDownlinkGuard { join }
}

async fn quic_session_tick(
    backend: &mut QuicheBackend,
    quic_sock: &UdpSocket,
    quic_local: SocketAddr,
    peer: SocketAddr,
    fast: bool,
    last_quic_keepalive: &mut Instant,
) -> Result<Option<&'static str>> {
    if fast {
        if last_quic_keepalive.elapsed() < BOLT_KEEPALIVE {
            return Ok(None);
        }
    } else {
        match pump_recv_once_for_peer(
            backend.connection_mut(),
            quic_sock,
            quic_local,
            Some(peer),
            None,
            fast,
        )
        .await
        {
            Ok(PeerPumpOutcome::ReconnectAttempt) => return Ok(Some("reconnect_attempt")),
            Ok(PeerPumpOutcome::Ok) => {}
            Err(e) => tracing::debug!(error = %e, "BOLT QUIC pump"),
        }
    }

    if last_quic_keepalive.elapsed() >= BOLT_KEEPALIVE {
        if fast {
            match pump_recv_once_for_peer(
                backend.connection_mut(),
                quic_sock,
                quic_local,
                Some(peer),
                None,
                fast,
            )
            .await
            {
                Ok(PeerPumpOutcome::ReconnectAttempt) => return Ok(Some("reconnect_attempt")),
                Ok(PeerPumpOutcome::Ok) => {}
                Err(e) => tracing::debug!(error = %e, "BOLT QUIC keepalive pump"),
            }
        }
        let _ = backend.send_ping();
        let conn = backend.connection_mut();
        let _ = flush(conn, quic_sock).await;
        *last_quic_keepalive = Instant::now();
    }
    Ok(None)
}

// #region agent log
fn log_debug_session46756b(hypothesis_id: &str, location: &str, message: &str, data_json: &str) {
    if !agent_debug::enabled() {
        return;
    }
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let line = format!(
        r#"{{"sessionId":"46756b","timestamp":{ts},"hypothesisId":"{hypothesis_id}","location":"{location}","message":"{message}","data":{data_json}}}"#
    );
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("debug-46756b.log")
    {
        let _ = writeln!(f, "{line}");
    }
}
// #endregion

fn exporter_from_backend(backend: &mut QuicheBackend) -> Result<PrismExporter> {
    let mut raw = [0u8; EXPORTER_LEN];
    backend.export_keying_material(b"prism/master", &[], &mut raw)?;
    Ok(PrismExporter::from_raw(raw))
}

fn bolt_session_setup(
    cipher: BoltCipher,
    lanes: prism_bolt::BoltLanes,
    fast: bool,
) -> (BoltSession, BoltStatsView) {
    let turbo = fast || prism_bolt::bolt_turbo_from_env();
    let pacer = BrutalPacer::new_with_turbo(prism_bolt::bolt_mbps_from_env(), turbo);
    let bolt = BoltSession::new(cipher, lanes, pacer);
    let stats = BoltStatsView {
        wire_layout: bolt.wire_layout(),
        turbo,
        frames_sent: Arc::clone(&bolt.frames_sent),
        frames_recv: Arc::clone(&bolt.frames_recv),
        bytes_sent: Arc::clone(&bolt.bytes_sent),
        bytes_recv: Arc::clone(&bolt.bytes_recv),
        peak_mbps_bits: Arc::clone(&bolt.peak_mbps_bits),
    };
    (bolt, stats)
}

fn spawn_bolt_send_task(
    mut bolt: BoltSession,
    upload_pending: Arc<AtomicUsize>,
    flush_counter: Arc<AtomicU64>,
) -> (mpsc::UnboundedSender<BoltSendCmd>, BoltSendGuard) {
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let tx_for_guard = cmd_tx.clone();
    let pending = Arc::clone(&upload_pending);
    let join = tokio::spawn(async move {
        for _ in 0..2 {
            let _ = bolt.send_keepalive().await;
        }
        let mut last_keepalive = Instant::now();
        loop {
            let mut batch = 0usize;
            while batch < SEND_TASK_BATCH {
                match cmd_rx.try_recv() {
                    Ok(BoltSendCmd::Packet(pkt)) => {
                        pending.fetch_sub(1, Ordering::Relaxed);
                        while bolt.needs_flush_before(pkt.len()) {
                            if let Ok(n) = bolt.flush_burst(FLUSH_LANE_BATCH).await {
                                if n > 0 {
                                    flush_counter.fetch_add(n as u64, Ordering::Relaxed);
                                }
                            }
                        }
                        if bolt.ingest_packet(&pkt).is_ok() {
                            batch += 1;
                            if batch % INGEST_FLUSH_EVERY == 0 && bolt.has_pending() {
                                if let Ok(n) = bolt.flush_burst(FLUSH_LANE_BATCH).await {
                                    if n > 0 {
                                        flush_counter.fetch_add(n as u64, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    }
                    Ok(BoltSendCmd::Shutdown) => return,
                    Err(_) => break,
                }
            }

            for _ in 0..SEND_FLUSH_ROUNDS {
                if !bolt.has_pending() {
                    break;
                }
                match bolt.flush_burst(FLUSH_LANE_BATCH).await {
                    Ok(n) if n > 0 => {
                        flush_counter.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Ok(_) => break,
                    Err(e) => {
                        tracing::debug!(error = %e, "BOLT send task flush error");
                        break;
                    }
                }
            }

            if last_keepalive.elapsed() >= BOLT_KEEPALIVE {
                let _ = bolt.send_keepalive().await;
                last_keepalive = Instant::now();
            }

            match tokio::time::timeout(TUN_READ_TIMEOUT, cmd_rx.recv()).await {
                Ok(Some(BoltSendCmd::Packet(pkt))) => {
                    pending.fetch_sub(1, Ordering::Relaxed);
                    while bolt.needs_flush_before(pkt.len()) {
                        let _ = bolt.flush_burst(FLUSH_LANE_BATCH).await;
                    }
                    let _ = bolt.ingest_packet(&pkt);
                }
                Ok(Some(BoltSendCmd::Shutdown)) | Ok(None) => break,
                Err(_) => {}
            }
        }
    });
    (
        cmd_tx,
        BoltSendGuard {
            cmd_tx: tx_for_guard,
            join,
        },
    )
}

/// Client BOLT loop after QUIC handshake + TUN open.
pub async fn run_client_bolt(
    mut backend: QuicheBackend,
    quic_sock: Arc<UdpSocket>,
    quic_local: SocketAddr,
    server: SocketAddr,
    tun: PlatformTun,
    fast: bool,
) -> Result<()> {
    let exporter = exporter_from_backend(&mut backend)?;
    let cipher = BoltCipher::from_exporter(&exporter, BoltDirection::Up)
        .map_err(|e| QuicError::Backend(format!("bolt cipher: {e}")))?;
    let recv_cipher = Arc::new(
        BoltCipher::from_exporter(&exporter, BoltDirection::Up)
            .map_err(|e| QuicError::Backend(format!("bolt cipher: {e}")))?,
    );

    let lanes = prism_bolt::BoltLanes::bind_client(server)
        .await
        .map_err(|e| {
            agent_debug::log(
                "B2",
                "bolt_tunnel.rs:bind_client",
                "bolt lanes bind failed",
                &format!(r#"{{"server":"{server}","error":"{e}"}}"#),
            );
            QuicError::Backend(format!("bolt lanes: {e}"))
        })?;
    agent_debug::log(
        "B2",
        "bolt_tunnel.rs:bind_client",
        "bolt lanes bind ok",
        &format!(
            r#"{{"server":"{server}","lanes":{:?}}}"#,
            prism_bolt::BoltLanes::lane_addrs_default(server)
        ),
    );

    let (bolt, stats) = bolt_session_setup(cipher, lanes, fast);

    tracing::info!(
        lanes = ?prism_bolt::BoltLanes::lane_addrs_default(server),
        lanes_n = prism_bolt::bolt_lanes_from_env(),
        mbps = stats.pacer_mbps(),
        turbo = stats.turbo,
        wire_size = stats.wire_layout.wire_size,
        "PRISM BOLT data plane active (client)"
    );

    let upload_pending = Arc::new(AtomicUsize::new(0));
    let flush_counter = Arc::new(AtomicU64::new(0));

    let (tun_pkts_tx, tun_pkts_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let tun_rx_pending = Arc::new(AtomicUsize::new(0));
    let tun_pkts_out = Arc::new(AtomicU64::new(0));
    let tun_bytes_out = Arc::new(AtomicU64::new(0));
    let tun_shared = Arc::new(Mutex::new(tun));
    let downlink_guard = spawn_tun_downlink_writer(
        Arc::clone(&tun_shared),
        tun_pkts_rx,
        Arc::clone(&tun_rx_pending),
        Arc::clone(&tun_pkts_out),
        Arc::clone(&tun_bytes_out),
    );
    let recv_guard = spawn_bolt_recv(
        recv_cipher,
        bolt.lanes(),
        tun_pkts_tx,
        Arc::clone(&tun_rx_pending),
        Arc::clone(&stats.frames_recv),
        Arc::clone(&stats.bytes_recv),
        stats.wire_layout,
        "client",
    );

    let (upload_tx, send_guard) =
        spawn_bolt_send_task(bolt, Arc::clone(&upload_pending), Arc::clone(&flush_counter));

    let mut tun_buf = vec![0u8; {
        let t = tun_shared.lock().await;
        t.mtu()
    } + 128];
    let mut diag = BoltDiag::new("client_bolt");
    let mut last_quic_keepalive = Instant::now();
    let mut last_bolt_activity = Instant::now();
    let mut last_rx_frames = stats.frames_recv.load(Ordering::Relaxed);
    let mut last_tx_frames = stats.frames_sent.load(Ordering::Relaxed);

    let exit_reason = loop {
        {
            let conn = backend.connection_mut();
            if conn.is_closed() {
                agent_debug::log(
                    "B6",
                    "bolt_tunnel.rs:client_exit",
                    "bolt client exit",
                    r#"{"reason":"quic_closed"}"#,
                );
                tracing::info!("PRISM BOLT tunnel closed (QUIC closed)");
                break "quic_closed";
            }
        }

        if let Some(reason) = quic_session_tick(
            &mut backend,
            &quic_sock,
            quic_local,
            server,
            fast,
            &mut last_quic_keepalive,
        )
        .await?
        {
            break reason;
        }

        touch_bolt_activity(
            &mut last_bolt_activity,
            &stats,
            &mut last_rx_frames,
            &mut last_tx_frames,
            &upload_pending,
        );
        if last_bolt_activity.elapsed() >= PEER_IDLE_RELEASE {
            agent_debug::log(
                "B6",
                "bolt_tunnel.rs:client_exit",
                "bolt client exit",
                &format!(
                    r#"{{"reason":"bolt_peer_idle","idle_secs":{}}}"#,
                    last_bolt_activity.elapsed().as_secs()
                ),
            );
            tracing::info!(
                idle_secs = last_bolt_activity.elapsed().as_secs(),
                "BOLT downlink idle; closing client session"
            );
            break "bolt_peer_idle";
        }

        diag.loop_iters += 1;
        diag.flush_frames_last_tick = flush_counter.swap(0, Ordering::Relaxed);
        diag.tun_pkts_out = tun_pkts_out.load(Ordering::Relaxed);
        diag.tun_bytes_out = tun_bytes_out.load(Ordering::Relaxed);

        let mut work = 0u32;
        for _ in 0..TUN_UPLOAD_BURST {
            let read = async {
                let mut t = tun_shared.lock().await;
                tokio::time::timeout(TUN_READ_TIMEOUT, t.read_packet(&mut tun_buf)).await
            };
            match read.await {
                Ok(Ok(n)) if n > 0 => {
                    let Some(len) = framed_ip_packet_len(&tun_buf[..n]) else {
                        continue;
                    };
                    let pkt = tun_buf[..len].to_vec();
                    upload_pending.fetch_add(1, Ordering::Relaxed);
                    if upload_tx.send(BoltSendCmd::Packet(pkt)).is_err() {
                        return Err(QuicError::Backend("bolt upload task stopped".into()));
                    }
                    diag.tun_pkts_in += 1;
                    diag.tun_bytes_in += len as u64;
                    work += 1;
                }
                Ok(Ok(_)) => break,
                Ok(Err(e)) => return Err(QuicError::Backend(format!("tun read: {e}"))),
                Err(_) => break,
            }
        }

        diag.maybe_emit(&stats, &tun_rx_pending, &upload_pending);
        bolt_loop_cooperate(work == 0).await;
    };
    tracing::debug!(reason = exit_reason, "BOLT client loop finished");
    send_guard.shutdown().await;
    recv_guard.shutdown().await;
    downlink_guard.shutdown().await;
    Ok(())
}

/// Server BOLT loop after QUIC handshake.
pub async fn run_server_bolt(
    mut backend: QuicheBackend,
    quic_sock: Arc<UdpSocket>,
    quic_local: SocketAddr,
    client_peer: SocketAddr,
    tun: &mut PlatformTun,
    client_ip: std::net::Ipv4Addr,
    fast: bool,
) -> Result<()> {
    let exporter = exporter_from_backend(&mut backend)?;
    let cipher = BoltCipher::from_exporter(&exporter, BoltDirection::Down)
        .map_err(|e| QuicError::Backend(format!("bolt cipher: {e}")))?;
    let recv_cipher = Arc::new(
        BoltCipher::from_exporter(&exporter, BoltDirection::Down)
            .map_err(|e| QuicError::Backend(format!("bolt cipher: {e}")))?,
    );

    let lanes = prism_bolt::BoltLanes::bind_server(quic_local)
        .await
        .map_err(|e| {
            agent_debug::log(
                "B8",
                "bolt_tunnel.rs:bind_server",
                "bolt lanes bind failed",
                &format!(r#"{{"error":"{e}","lanes":{}}}"#, prism_bolt::bolt_lanes_from_env()),
            );
            QuicError::Backend(format!("bolt lanes: {e}"))
        })?;
    agent_debug::log(
        "B8",
        "bolt_tunnel.rs:bind_server",
        "bolt lanes bind ok",
        &format!(r#"{{"lanes":{}}}"#, prism_bolt::bolt_lanes_from_env()),
    );

    let (bolt, stats) = bolt_session_setup(cipher, lanes, fast);

    tracing::info!(
        %client_peer,
        lanes = ?prism_bolt::BoltLanes::lane_addrs_default(quic_local),
        lanes_n = prism_bolt::bolt_lanes_from_env(),
        mbps = stats.pacer_mbps(),
        turbo = stats.turbo,
        wire_size = stats.wire_layout.wire_size,
        "PRISM BOLT data plane active (server)"
    );

    let upload_pending = Arc::new(AtomicUsize::new(0));
    let flush_counter = Arc::new(AtomicU64::new(0));

    let (tun_pkts_tx, mut tun_pkts_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let tun_rx_pending = Arc::new(AtomicUsize::new(0));
    let recv_guard = spawn_bolt_recv(
        recv_cipher,
        bolt.lanes(),
        tun_pkts_tx,
        Arc::clone(&tun_rx_pending),
        Arc::clone(&stats.frames_recv),
        Arc::clone(&stats.bytes_recv),
        stats.wire_layout,
        "server",
    );

    let (upload_tx, send_guard) =
        spawn_bolt_send_task(bolt, Arc::clone(&upload_pending), Arc::clone(&flush_counter));

    let mut tun_buf = vec![0u8; tun.mtu() + 128];
    let mut diag = BoltDiag::new("server_bolt");
    let mut last_quic_keepalive = Instant::now();
    let mut last_bolt_activity = Instant::now();
    let mut last_rx_frames = stats.frames_recv.load(Ordering::Relaxed);
    let mut last_tx_frames = stats.frames_sent.load(Ordering::Relaxed);

    let exit_reason = loop {
        {
            let conn = backend.connection_mut();
            if conn.is_closed() {
                agent_debug::log(
                    "B6",
                    "bolt_tunnel.rs:server_exit",
                    "bolt server exit",
                    r#"{"reason":"quic_closed"}"#,
                );
                tracing::info!(%client_peer, "PRISM BOLT server session ended (QUIC closed)");
                break "quic_closed";
            }
        }

        if let Some(reason) = quic_session_tick(
            &mut backend,
            &quic_sock,
            quic_local,
            client_peer,
            fast,
            &mut last_quic_keepalive,
        )
        .await?
        {
            agent_debug::log(
                "B6",
                "bolt_tunnel.rs:server_exit",
                "bolt server exit",
                &format!(r#"{{"reason":"{reason}"}}"#),
            );
            tracing::info!(%client_peer, reason, "BOLT server session ending");
            break reason;
        }

        touch_bolt_activity(
            &mut last_bolt_activity,
            &stats,
            &mut last_rx_frames,
            &mut last_tx_frames,
            &upload_pending,
        );
        if last_bolt_activity.elapsed() >= PEER_IDLE_RELEASE {
            agent_debug::log(
                "B6",
                "bolt_tunnel.rs:server_exit",
                "bolt server exit",
                &format!(
                    r#"{{"reason":"bolt_peer_idle","idle_secs":{}}}"#,
                    last_bolt_activity.elapsed().as_secs()
                ),
            );
            tracing::info!(
                %client_peer,
                idle_secs = last_bolt_activity.elapsed().as_secs(),
                "BOLT peer idle; releasing session for reconnect"
            );
            break "bolt_peer_idle";
        }

        diag.loop_iters += 1;
        diag.flush_frames_last_tick = flush_counter.swap(0, Ordering::Relaxed);

        let mut work = 0u32;
        loop {
            let n = drain_tun_downlink(tun, &mut tun_pkts_rx, &tun_rx_pending, &mut diag).await?;
            if n == 0 {
                break;
            }
            work += n;
        }

        for _ in 0..TUN_UPLOAD_BURST {
            match tokio::time::timeout(TUN_READ_TIMEOUT, tun.read_packet(&mut tun_buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let Some(len) = framed_ip_packet_len(&tun_buf[..n]) else {
                        continue;
                    };
                    let pkt = &tun_buf[..len];
                    if ipv4_dst(pkt) != Some(client_ip) {
                        continue;
                    }
                    let pkt = pkt.to_vec();
                    upload_pending.fetch_add(1, Ordering::Relaxed);
                    if upload_tx.send(BoltSendCmd::Packet(pkt)).is_err() {
                        return Err(QuicError::Backend("bolt upload task stopped".into()));
                    }
                    diag.tun_pkts_in += 1;
                    diag.tun_bytes_in += len as u64;
                    work += 1;
                }
                Ok(Ok(_)) => break,
                Ok(Err(e)) => return Err(QuicError::Backend(format!("tun read: {e}"))),
                Err(_) => break,
            }
        }

        diag.maybe_emit(&stats, &tun_rx_pending, &upload_pending);
        bolt_loop_cooperate(work == 0).await;
    };
    tracing::debug!(reason = exit_reason, %client_peer, "BOLT server loop finished");
    send_guard.shutdown().await;
    recv_guard.shutdown().await;
    Ok(())
}

struct BoltRecvGuard {
    handles: Vec<JoinHandle<()>>,
}

impl BoltRecvGuard {
    async fn shutdown(self) {
        for h in self.handles {
            h.abort();
            let _ = h.await;
        }
    }
}

fn spawn_bolt_recv(
    cipher: Arc<BoltCipher>,
    lanes: &prism_bolt::BoltLanes,
    tun_tx: mpsc::UnboundedSender<Vec<u8>>,
    tun_rx_pending: Arc<AtomicUsize>,
    frames_recv: Arc<AtomicU64>,
    bytes_recv: Arc<AtomicU64>,
    wire_layout: WireLayout,
    role: &'static str,
) -> BoltRecvGuard {
    let mut handles = Vec::with_capacity(lanes.lane_count());
    for lane in 0..lanes.lane_count() {
        let sock = lanes.socket(lane);
        let peer_slot = lanes.peer_handle(lane);
        let cipher = Arc::clone(&cipher);
        let tun_tx = tun_tx.clone();
        let tun_rx_pending = Arc::clone(&tun_rx_pending);
        let frames_recv = Arc::clone(&frames_recv);
        let bytes_recv = Arc::clone(&bytes_recv);
        let expected_wire = wire_layout.wire_size;
        handles.push(tokio::spawn(async move {
            tracing::debug!(role, lane, "BOLT recv task started");
            let mut buf = vec![0u8; WIRE_SIZE_MAX];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        let mut slot = peer_slot.write().expect("peer lock");
                        if *slot != Some(from) {
                            *slot = Some(from);
                            tracing::info!(lane, %from, role, "BOLT peer learned");
                            agent_debug::log(
                                "B5",
                                "bolt_tunnel.rs:learn_peer",
                                "bolt peer learned",
                                &format!(r#"{{"role":"{role}","lane":{lane},"peer":"{from}"}}"#),
                            );
                        }
                        drop(slot);
                        if n != expected_wire {
                            continue;
                        }
                        match cipher.open_wire(&buf[..n]) {
                            Ok(frame) => {
                                frames_recv.fetch_add(1, Ordering::Relaxed);
                                if prism_bolt::BoltSession::is_keepalive(&frame) {
                                    continue;
                                }
                                let bytes: u64 =
                                    frame.chunks.iter().map(|c| c.len() as u64).sum();
                                bytes_recv.fetch_add(bytes, Ordering::Relaxed);
                                for ch in frame.chunks {
                                    tun_rx_pending.fetch_add(1, Ordering::Relaxed);
                                    let _ = tun_tx.send(ch);
                                }
                            }
                            Err(e) => {
                                tracing::debug!(lane, %from, error = %e, role, "BOLT decrypt failed");
                            }
                        }
                    }
                    Err(e) => tracing::debug!(lane, error = %e, role, "BOLT recv error"),
                }
            }
        }));
    }
    BoltRecvGuard { handles }
}

/// Whether this tunnel session should use BOLT instead of QUIC streams.
pub fn use_bolt_data_plane(fast: bool) -> bool {
    bolt_active(fast)
}
