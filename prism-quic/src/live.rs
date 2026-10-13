//! Live PRISM driver over real UDP, on top of the quiche + BoringSSL fork.
//!
//! This is the glue that turns the validated building blocks (Reality injection,
//! the TLS exporter session, Mirror-Cell Carrying, morph-padded datagrams) into
//! a working client and a single-connection server with decoy fallback.
//!
//! The event loop is deliberately single-task: it pumps `send`/`recv`/timeout
//! for one connection. A production server would fan out per-connection, but
//! this mirrors the scope of the pure-Rust `prism-transport` reference and is
//! enough to round-trip VPN packets end to end.
#![cfg(feature = "quiche-backend")]

use std::net::SocketAddr;
use std::time::Duration;

use prism_auth::client_hello::RealityClientHello;
use prism_auth::server::{AuthDecision, ShadowDetector};
use prism_core::crypto::{X25519Public, X25519Secret};
use prism_morph::CdnProfile;
use tokio::net::UdpSocket;

use crate::datagram::fill_datagram;
use crate::error::{QuicError, Result};
use crate::quiche;
use crate::quiche_backend::QuicheBackend;
use crate::session::PrismSession;

// PRISM masquerades as HTTP/3, so the ALPN MUST be "h3" to match Chrome's JA4
// (the JA4_a ALPN field and the ALPN extension itself). Client authentication
// is carried by the Reality GREASE 0x0A0A tag, never by the ALPN.
const ALPN: &[u8] = b"h3";
// Headroom so the morph engine can realize the full top size bucket (profile
// hi = 1452) instead of clamping it to a single value; stays under a 1500-byte
// path MTU (1452 QUIC payload + 8 UDP + 20 IPv4 = 1480).
pub(crate) const MAX_DGRAM: usize = 1452;

/// Max client-initiated bidi streams for TUN mode (one per IP flow).
/// Windows generates many flows as soon as routes install; 64 was too low.
pub(crate) const TUNNEL_MAX_BIDI_STREAMS: u64 = 4096;

/// UDP socket buffer size (stealth). The default (64 KiB on Windows) holds <11 ms
/// of a 50 Mbit/s flow, so any hiccup in the single-threaded event loop drops
/// packets and collapses the congestion window. Wire-invisible; both modes.
const UDP_SOCK_BUF: usize = 4 * 1024 * 1024;

/// Larger kernel RX/TX queues for perf sessions (wire-invisible).
const UDP_SOCK_BUF_PERF: usize = 16 * 1024 * 1024;

/// `1` / `true` boolean environment flag.
pub(crate) fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// `PRISM_PERF=1` (or `--perf` on the client): performance mode. Disables morph
/// size-padding on the client and appends a perf capability byte to GREASE
/// `0x0A0A` so the server mirrors fast downlink morph for that session.
/// `PRISM_FAST=1` on the server still forces fast morph for all sessions.
pub(crate) fn prism_perf() -> bool {
    env_flag("PRISM_PERF")
}

/// Whether a tunnel session runs without morph padding (client perf cap, server
/// `PRISM_FAST` / `PRISM_PERF`, or mirrored client perf).
pub(crate) fn fast_session_active(client_perf: bool) -> bool {
    env_flag("PRISM_FAST") || prism_perf() || client_perf
}

/// BOLT bulk data plane: any fast/perf session, or explicit `PRISM_BOLT=1`.
pub(crate) fn bolt_active(fast: bool) -> bool {
    env_flag("PRISM_BOLT") || fast
}

/// Best-effort enlarge a socket's kernel buffers (loss-avoidance, not stealth
/// relevant: nothing on the wire changes).
pub(crate) fn tune_udp_socket(sock: &UdpSocket) {
    tune_udp_socket_with_buf(sock, UDP_SOCK_BUF);
}

/// Perf sessions use deeper kernel queues to survive burst downlink.
pub(crate) fn tune_udp_socket_perf(sock: &UdpSocket) {
    tune_udp_socket_with_buf(sock, UDP_SOCK_BUF_PERF);
}

fn tune_udp_socket_with_buf(sock: &UdpSocket, bytes: usize) {
    let s = socket2::SockRef::from(sock);
    if let Err(e) = s.set_recv_buffer_size(bytes) {
        tracing::debug!(error = %e, "set_recv_buffer_size failed");
    }
    if let Err(e) = s.set_send_buffer_size(bytes) {
        tracing::debug!(error = %e, "set_send_buffer_size failed");
    }
}

/// Retune quiche for a perf / fast-morph session. Stock pacing throttles bulk
/// server→client delivery to a few Mbit/s even when morph padding is off.
fn apply_throughput_tuning(c: &mut quiche::Config) {
    c.enable_pacing(false);
    c.enable_hystart(false);
    c.set_initial_congestion_window_packets(512);
    // CUBIC without pacing was the stable high-throughput choice before BBR trial.
    let _ = c.set_cc_algorithm_name("cubic");
    let cc = "cubic";
    // #region agent log
    crate::agent_debug::log(
        "H2",
        "live.rs:apply_throughput_tuning",
        "perf CC selected",
        &format!(r#"{{"cc":"{cc}","cwnd_packets":512,"pacing":false}}"#),
    );
    // #endregion
}

/// Build the shared quiche config (client and server differ only by cert).
///
/// Pass `fast_session=true` when morph padding is disabled for this connection
/// (client `--perf` / `PRISM_PERF`, or server mirroring client perf).
pub(crate) fn base_config(fast_session: bool) -> std::result::Result<quiche::Config, QuicError> {
    let mut c = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| QuicError::Backend(format!("config: {e:?}")))?;
    c.set_application_protos(&[ALPN])
        .map_err(|e| QuicError::Backend(format!("alpn: {e:?}")))?;
    c.verify_peer(false);
    // VPN sessions must survive quiet periods (no TUN traffic). 30s was too
    // aggressive and dropped healthy tunnels; keepalive pings cover morph idle.
    c.set_max_idle_timeout(300_000);
    // Generous flow control so a sustained (bulk) session can stream many MB
    // over a single long-lived stream without stalling. These are QUIC
    // transport-parameter values (TLS ext 0x39); JA4 hashes extension *types*,
    // not contents, so this does not affect the ClientHello fingerprint.
    c.set_initial_max_data(1_000_000_000);
    c.set_initial_max_stream_data_bidi_local(256_000_000);
    c.set_initial_max_stream_data_bidi_remote(256_000_000);
    c.set_initial_max_streams_bidi(TUNNEL_MAX_BIDI_STREAMS);
    c.set_max_recv_udp_payload_size(MAX_DGRAM);
    c.set_max_send_udp_payload_size(MAX_DGRAM);
    if fast_session {
        apply_throughput_tuning(&mut c);
        tracing::info!("fast session: quiche pacing off, CUBIC, initial cwnd=512 packets");
    }
    Ok(c)
}

/// Load the morph `CdnProfile`. If `PRISM_CDN_PROFILE` points at a JSON profile
/// (e.g. derived from a real Chrome h3 capture via `scripts/profile_from_capture.py`),
/// it is used; otherwise the built-in synthetic Chrome profile is used. Both
/// ends derive the same morph seed from the TLS exporter, so they only need the
/// same *profile* to agree on target sizes/IATs.
pub(crate) fn load_cdn_profile() -> CdnProfile {
    if let Ok(path) = std::env::var("PRISM_CDN_PROFILE") {
        if !path.is_empty() {
            match CdnProfile::load(std::path::Path::new(&path)) {
                Ok(p) => {
                    tracing::info!(%path, "loaded CdnProfile from PRISM_CDN_PROFILE");
                    return p;
                }
                Err(e) => {
                    tracing::warn!(%path, error = %e, "failed to load PRISM_CDN_PROFILE; using synthetic_chrome");
                }
            }
        }
    }
    CdnProfile::synthetic_chrome()
}

pub(crate) fn rand_cid() -> quiche::ConnectionId<'static> {
    let mut id = [0u8; 16];
    // Cheap unique-ish CID; not security-sensitive (the auth is the Reality tag).
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    id.copy_from_slice(&(nanos as u128).to_le_bytes());
    quiche::ConnectionId::from_vec(id.to_vec())
}

/// Flush everything the connection wants to send onto the socket.
pub(crate) async fn flush(conn: &mut quiche::Connection, sock: &UdpSocket) -> Result<()> {
    let mut out = [0u8; MAX_DGRAM];
    loop {
        match conn.send(&mut out) {
            Ok((0, _)) => break,
            Ok((n, info)) => {
                sock.send_to(&out[..n], info.to)
                    .await
                    .map_err(|e| QuicError::Backend(e.to_string()))?;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(QuicError::Backend(format!("{e:?}"))),
        }
    }
    Ok(())
}

/// Bind an ephemeral UDP socket for the client and `connect()` it to the server.
/// Connected UDP helps Windows deliver return-path handshake packets reliably.
pub(crate) async fn bind_client_udp(peer: SocketAddr) -> Result<(UdpSocket, SocketAddr)> {
    use std::net::Ipv4Addr;

    let sock = if peer.is_ipv4() {
        UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await
    } else {
        UdpSocket::bind("0.0.0.0:0").await
    }
    .map_err(|e| QuicError::Backend(e.to_string()))?;
    if prism_perf() {
        tune_udp_socket_perf(&sock);
    } else {
        tune_udp_socket(&sock);
    }
    sock.connect(peer)
        .await
        .map_err(|e| QuicError::Backend(format!("udp connect {peer}: {e}")))?;
    let local = sock
        .local_addr()
        .map_err(|e| QuicError::Backend(e.to_string()))?;
    Ok((sock, local))
}

/// Drain datagrams already queued in the kernel RX buffer (non-blocking).
/// When `max` is set, stops after that many packets (perf loop fairness).
async fn drain_pending_udp(
    conn: &mut quiche::Connection,
    sock: &UdpSocket,
    local: SocketAddr,
    max: Option<u32>,
) -> Result<u32> {
    let mut buf = [0u8; 2048];
    let mut count = 0u32;
    loop {
        if max.is_some_and(|m| count >= m) {
            break;
        }
        match tokio::time::timeout(Duration::from_millis(0), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                let info = quiche::RecvInfo { from, to: local };
                let _ = conn.recv(&mut buf[..n], info);
                count += 1;
            }
            _ => break,
        }
    }
    Ok(count)
}

/// Drive a QUIC handshake until established or `timeout`.
pub(crate) async fn drive_handshake(
    conn: &mut quiche::Connection,
    sock: &UdpSocket,
    local: SocketAddr,
    timeout: Duration,
) -> Result<()> {
    flush(conn, sock).await?;
    let deadline = std::time::Instant::now() + timeout;
    let mut pkts_in = 0u32;

    while !conn.is_established() {
        if std::time::Instant::now() > deadline {
            tracing::warn!(pkts_in, "QUIC handshake timed out");
            let _ = conn.close(true, 0, b"timeout");
            let _ = flush(conn, sock).await;
            return Err(QuicError::Backend("handshake timed out".into()));
        }

        pkts_in += drain_pending_udp(conn, sock, local, None).await?;
        flush(conn, sock).await?;

        let wait = conn
            .timeout()
            .unwrap_or_else(|| Duration::from_millis(50))
            .min(Duration::from_millis(100));
        let mut buf = [0u8; 2048];
        match tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                pkts_in += 1;
                let info = quiche::RecvInfo { from, to: local };
                let _ = conn.recv(&mut buf[..n], info);
                pkts_in += drain_pending_udp(conn, sock, local, None).await?;
            }
            Ok(Err(e)) => return Err(QuicError::Backend(e.to_string())),
            Err(_) => conn.on_timeout(),
        }

        if conn.is_closed() {
            return Err(QuicError::Backend(
                "connection closed during handshake".into(),
            ));
        }
    }

    tracing::debug!(pkts_in, "QUIC handshake complete");
    Ok(())
}

/// One iteration of the echo/bulk event loop: flush, then wait for a packet or
/// the connection timeout. Callers that send via [`fill_datagram`] (morph-padded
/// outbound) use this so ACKs and control frames still reach the wire.
pub(crate) async fn pump_once(
    conn: &mut quiche::Connection,
    sock: &UdpSocket,
    local: SocketAddr,
) -> Result<()> {
    flush(conn, sock).await?;
    pump_recv_once(conn, sock, local).await
}

/// Upper bound on how long the stealth tunnel loop may block in recv. Without
/// this, `conn.timeout()` can reach the idle deadline (~300 s) and stall the
/// whole loop — no morph flush, no keepalive, delayed ACKs — which shows up as
/// traffic dying after ~10 s (NAT / peer timers) even though the session is
/// still up until max idle.
const PUMP_RECV_MAX_WAIT: Duration = Duration::from_millis(100);

/// Perf mode: never block on recv; drain the kernel RX queue in a tight loop.
const PUMP_RECV_PERF_WAIT: Duration = Duration::from_millis(0);

/// Max datagrams to pull per perf recv burst (prevents unbounded spin).
pub(crate) const PERF_RECV_BURST: u32 = 64;
/// Cap kernel RX drain per recv pump so download cannot monopolize the loop.
pub(crate) const PERF_UDP_DRAIN_CAP: u32 = 32;

/// How long the tunnel loop may block waiting for inbound UDP.
pub(crate) fn pump_recv_max_wait(fast: bool) -> Duration {
    if fast {
        PUMP_RECV_PERF_WAIT
    } else {
        PUMP_RECV_MAX_WAIT
    }
}

/// Outcome of a recv pump bound to one peer (server tunnel mode).
pub(crate) enum PeerPumpOutcome {
    Ok,
    /// A PRISM Initial arrived from a different UDP endpoint (client reconnect).
    ReconnectAttempt,
}

/// Release a server session when the peer stops sending (client killed without
/// QUIC CLOSE). Active tunnels send keepalives every second, so this is safe.
pub(crate) const PEER_IDLE_RELEASE: Duration = Duration::from_secs(15);

/// Receive-side pump for the TUN tunnel loop. **Does not** flush outbound
/// datagrams — the tunnel sends exclusively through morph-aware `flush_morph`.
/// Calling [`flush`] here would drain quiche's send queue with unpadded short
/// headers and starve morph padding (breaking stealth mode and perf-mode
/// downlink when the server keeps padding on).
pub(crate) async fn pump_recv_once(
    conn: &mut quiche::Connection,
    sock: &UdpSocket,
    local: SocketAddr,
) -> Result<()> {
    let _ = pump_recv_once_for_peer(conn, sock, local, None, None, false).await?;
    Ok(())
}

/// Like [`pump_recv_once`], but when `expected_peer` is set the server drops
/// stray datagrams and returns [`PeerPumpOutcome::ReconnectAttempt`] if a new
/// PRISM Initial arrives from another address (typical after the client was
/// killed and reconnects on a fresh ephemeral port).
pub(crate) async fn pump_recv_once_for_peer(
    conn: &mut quiche::Connection,
    sock: &UdpSocket,
    local: SocketAddr,
    expected_peer: Option<SocketAddr>,
    last_peer_rx: Option<&mut std::time::Instant>,
    fast: bool,
) -> Result<PeerPumpOutcome> {
    let mut noop_recv = 0u32;
    pump_recv_burst_for_peer(
        conn,
        sock,
        local,
        expected_peer,
        last_peer_rx,
        pump_recv_max_wait(fast),
        if fast { PERF_RECV_BURST } else { 1 },
        &mut noop_recv,
        if fast {
            Some(PERF_UDP_DRAIN_CAP)
        } else {
            None
        },
    )
    .await
}

/// Drain inbound UDP: non-blocking kernel queue first, then up to `max_extra`
/// blocking reads capped by `max_wait` each. In perf mode `max_wait` is zero and
/// `max_extra` is [`PERF_RECV_BURST`] so downlink + ACK clocking stay hot.
pub(crate) async fn pump_recv_burst_for_peer(
    conn: &mut quiche::Connection,
    sock: &UdpSocket,
    local: SocketAddr,
    expected_peer: Option<SocketAddr>,
    last_peer_rx: Option<&mut std::time::Instant>,
    max_wait: Duration,
    max_extra: u32,
    recv_pkts: &mut u32,
    udp_drain_cap: Option<u32>,
) -> Result<PeerPumpOutcome> {
    let _ = drain_pending_udp(conn, sock, local, udp_drain_cap).await?;

    let mut buf = [0u8; 2048];
    let mut extra = 0u32;
    let mut got_peer_pkt = false;
    loop {
        let timeout = if extra == 0 {
            max_wait
        } else {
            Duration::from_millis(0)
        };
        let wait = conn
            .timeout()
            .unwrap_or_else(|| Duration::from_millis(100))
            .min(timeout);

        match tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                if let Some(peer) = expected_peer {
                    if from != peer {
                        if quiche::prism_peek_client_hello(&buf[..n]).is_some() {
                            tracing::info!(
                                %from,
                                %peer,
                                "new PRISM Initial from different address; releasing stale session"
                            );
                            return Ok(PeerPumpOutcome::ReconnectAttempt);
                        }
                        break;
                    }
                    got_peer_pkt = true;
                }
                let info = quiche::RecvInfo { from, to: local };
                let _ = conn.recv(&mut buf[..n], info);
                let _ = drain_pending_udp(conn, sock, local, udp_drain_cap).await?;
                *recv_pkts += 1;
                extra += 1;
                if extra >= max_extra {
                    break;
                }
            }
            Ok(Err(e)) => return Err(QuicError::Backend(e.to_string())),
            Err(_) => {
                if extra == 0 {
                    conn.on_timeout();
                }
                break;
            }
        }
    }
    if got_peer_pkt {
        if let Some(ts) = last_peer_rx {
            *ts = std::time::Instant::now();
        }
    }
    Ok(PeerPumpOutcome::Ok)
}

/// Connect to a PRISM server, perform the Reality handshake, send each VPN
/// payload as a Mirror Cell in a morph-padded datagram, and collect echoes.
/// Returns the echoed payloads in arrival order.
pub async fn run_client(
    server: SocketAddr,
    shadow_pk: X25519Public,
    decoy: &str,
    payloads: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>> {
    let (sock, local) = bind_client_udp(server).await?;

    let mut cfg = base_config(prism_perf())?;
    let scid = rand_cid();
    let mut conn = quiche::connect(Some(decoy), &scid, local, server, &mut cfg)
        .map_err(|e| QuicError::Backend(format!("connect: {e:?}")))?;

    // Reality injection: ephemeral key_share + GREASE 0x0A0A auth tag.
    let ch = RealityClientHello::build(&shadow_pk, decoy);
    conn.set_prism_x25519_offer_seed(&ch.offer_seed());
    let mut grease_wire = [0u8; prism_auth::client_hello::GREASE_WIRE_LEN_PERF];
    let wire = ch.grease_ext_wire(prism_perf(), &mut grease_wire);
    conn.set_prism_auth_tag(wire);

    drive_handshake(&mut conn, &sock, local, Duration::from_secs(30)).await?;

    let mut backend = QuicheBackend::from_connection(conn, local, server);
    let mut session = PrismSession::derive(&mut backend, load_cdn_profile(), 0.10, MAX_DGRAM)?;

    // Send each payload as a Mirror Cell, one per stream.
    for (i, p) in payloads.iter().enumerate() {
        let sid = (i as u64) * 4;
        crate::mcc::MccEncoder::new(&mut backend).write_ip_packet(sid, p)?;
    }

    // Flush data (morph-padded) and collect echoes within a bounded window.
    let mut received: Vec<Vec<u8>> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut scratch = vec![0u8; 4096];

    while received.len() < payloads.len() && tokio::time::Instant::now() < deadline {
        // Produce morph-padded data datagrams.
        let mut out = vec![0u8; MAX_DGRAM];
        loop {
            let n = fill_datagram(&mut backend, &mut session.morph_up, &mut out)?;
            if n == 0 {
                break;
            }
            let _ = sock.send_to(&out[..n], server).await;
        }
        // Pull any inbound packets and decode echoes.
        {
            let conn = backend.connection_mut();
            pump_once(conn, &sock, local).await?;
        }
        {
            let mut dec = crate::mcc::MccDecoder::new(&mut backend);
            dec.drain(&mut scratch, |_sid, bytes, _fin| {
                if !bytes.is_empty() {
                    received.push(bytes.to_vec());
                }
            })?;
        }
    }

    PrismSession::graceful_close(&mut backend)?;
    {
        let conn = backend.connection_mut();
        flush(conn, &sock).await?;
    }
    Ok(received)
}

/// Stats from a sustained (bulk) PRISM session.
#[derive(Clone, Copy, Debug, Default)]
pub struct BulkStats {
    pub datagrams_sent: u64,
    pub bytes_app: u64,
    pub echoes: u64,
}

/// Connect to a PRISM server and stream sustained, morph-shaped traffic for
/// `duration`. Unlike [`run_client`] (which sends a fixed burst and exits),
/// this paces one morph-sized datagram per `morph_up.delay()` interval over a
/// long-lived stream, so a packet capture sees a *representative* on-wire
/// size / inter-arrival distribution — the input the indistinguishability
/// gate (`prism-eval`) needs. Echoes are drained and discarded.
pub async fn run_client_bulk(
    server: SocketAddr,
    shadow_pk: X25519Public,
    decoy: &str,
    duration: Duration,
) -> Result<BulkStats> {
    let (sock, local) = bind_client_udp(server).await?;

    let mut cfg = base_config(prism_perf())?;
    let scid = rand_cid();
    let mut conn = quiche::connect(Some(decoy), &scid, local, server, &mut cfg)
        .map_err(|e| QuicError::Backend(format!("connect: {e:?}")))?;

    let ch = RealityClientHello::build(&shadow_pk, decoy);
    conn.set_prism_x25519_offer_seed(&ch.offer_seed());
    let mut grease_wire = [0u8; prism_auth::client_hello::GREASE_WIRE_LEN_PERF];
    let wire = ch.grease_ext_wire(prism_perf(), &mut grease_wire);
    conn.set_prism_auth_tag(wire);

    drive_handshake(&mut conn, &sock, local, Duration::from_secs(30)).await?;

    let mut backend = QuicheBackend::from_connection(conn, local, server);
    let mut session = PrismSession::derive(&mut backend, load_cdn_profile(), 0.10, MAX_DGRAM)?;

    // One long-lived bidirectional stream carries the VPN-like byte flow; the
    // server echoes on the same stream. The app chunk per tick is intentionally
    // small (below the smallest morph bucket) so the *morph target* — not the
    // queued payload — determines each datagram's size; PADDING fills the rest.
    // This is what makes the on-wire size distribution track the CdnProfile.
    const STREAM_ID: u64 = 4;
    let chunk = vec![0xA5u8; 48];

    let mut stats = BulkStats::default();
    let mut scratch = vec![0u8; 8192];
    let stop = tokio::time::Instant::now() + duration;

    while tokio::time::Instant::now() < stop {
        // Queue one chunk of app data.
        {
            let mut enc = crate::mcc::MccEncoder::new(&mut backend);
            let n = enc.write_ip_packet(STREAM_ID, &chunk)?;
            stats.bytes_app += n as u64;
        }

        // Emit one morph-padded datagram per tick so each datagram's size is an
        // independent draw from the profile and inter-arrival tracks delay()
        // (emitting all queued datagrams back-to-back would inject IAT~0 spikes).
        let mut out = vec![0u8; MAX_DGRAM];
        let n = fill_datagram(&mut backend, &mut session.morph_up, &mut out)?;
        if n > 0 {
            let _ = sock.send_to(&out[..n], server).await;
            stats.datagrams_sent += 1;
        }

        // Pull inbound packets and drain (discard) echoes to free flow control.
        {
            let conn = backend.connection_mut();
            pump_once(conn, &sock, local).await?;
            if conn.is_closed() {
                break;
            }
        }
        {
            let mut dec = crate::mcc::MccDecoder::new(&mut backend);
            let mut echoed = 0u64;
            dec.drain(&mut scratch, |_sid, bytes, _fin| {
                if !bytes.is_empty() {
                    echoed += 1;
                }
            })?;
            stats.echoes += echoed;
        }

        // Pace to the morph IAT profile so the on-wire inter-arrival
        // distribution tracks the CdnProfile.
        tokio::time::sleep(session.morph_up.delay()).await;
    }

    PrismSession::graceful_close(&mut backend)?;
    {
        let conn = backend.connection_mut();
        flush(conn, &sock).await?;
    }
    Ok(stats)
}

/// Server-side outcome for one inbound connection attempt.
pub enum Served {
    /// A PRISM client was accepted and its packets echoed.
    Prism { echoed: usize },
    /// The inbound handshake was not a PRISM client; it should be proxied to the
    /// decoy origin (caller decides how). Carries the first datagram so the
    /// caller can relay it verbatim.
    Decoy {
        first_datagram: Vec<u8>,
        from: SocketAddr,
    },
}

/// Bind a single-connection PRISM server. It classifies the first Initial via
/// the Reality shadow detector: PRISM clients are accepted and echoed; anything
/// else is reported as [`Served::Decoy`] for the caller to relay untouched.
pub async fn run_server_once(
    bind: SocketAddr,
    shadow_sk: X25519Secret,
    decoy: &str,
    cert: &str,
    key: &str,
) -> Result<Served> {
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| QuicError::Backend(e.to_string()))?;
    let local = sock
        .local_addr()
        .map_err(|e| QuicError::Backend(e.to_string()))?;

    let detector = ShadowDetector::new(shadow_sk, decoy);

    // Wait for the first datagram (a QUIC Initial).
    let mut buf = [0u8; 2048];
    let (n, from) = sock
        .recv_from(&mut buf)
        .await
        .map_err(|e| QuicError::Backend(e.to_string()))?;
    let first = buf[..n].to_vec();

    // Reality classification on the raw Initial.
    let decision = match quiche::prism_peek_client_hello(&first) {
        Some(hello) => detector.classify(&hello),
        None => AuthDecision::ProxyToDecoy,
    };
    if matches!(decision, AuthDecision::ProxyToDecoy) {
        return Ok(Served::Decoy {
            first_datagram: first,
            from,
        });
    }
    let client_perf = matches!(
        &decision,
        AuthDecision::Accept {
            client_perf: true,
            ..
        }
    );

    // Accept the PRISM connection.
    let mut cfg = base_config(fast_session_active(client_perf))?;
    cfg.load_cert_chain_from_pem_file(cert)
        .map_err(|e| QuicError::Backend(format!("cert: {e:?}")))?;
    cfg.load_priv_key_from_pem_file(key)
        .map_err(|e| QuicError::Backend(format!("key: {e:?}")))?;

    let hdr = quiche::Header::from_slice(&mut first.clone(), quiche::MAX_CONN_ID_LEN)
        .map_err(|e| QuicError::Backend(format!("hdr: {e:?}")))?;
    let scid = rand_cid();
    let mut conn = quiche::accept(&scid, Some(&hdr.dcid), local, from, &mut cfg)
        .map_err(|e| QuicError::Backend(format!("accept: {e:?}")))?;

    // Feed the first datagram, then drive the handshake.
    let info = quiche::RecvInfo { from, to: local };
    let mut fb = first.clone();
    let _ = conn.recv(&mut fb, info);

    drive_handshake(&mut conn, &sock, local, Duration::from_secs(30)).await?;

    let mut backend = QuicheBackend::from_connection(conn, local, from);
    let mut session = PrismSession::derive(&mut backend, load_cdn_profile(), 0.10, MAX_DGRAM)?;

    // Echo loop: read mirror cells, mirror them back on the same stream. The
    // deadline is a safety bound; a graceful client close ends the loop sooner.
    let mut scratch = vec![0u8; 8192];
    let mut echoed = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        {
            let conn = backend.connection_mut();
            if conn.is_closed() {
                break;
            }
            pump_once(conn, &sock, local).await?;
        }

        // Collect inbound cells.
        let mut pending: Vec<(u64, Vec<u8>)> = Vec::new();
        {
            let mut dec = crate::mcc::MccDecoder::new(&mut backend);
            dec.drain(&mut scratch, |sid, bytes, _fin| {
                if !bytes.is_empty() {
                    pending.push((sid, bytes.to_vec()));
                }
            })?;
        }
        for (sid, data) in pending {
            crate::mcc::MccEncoder::new(&mut backend).write_ip_packet(sid, &data)?;
            echoed += 1;
        }

        // Flush echoes as morph-padded datagrams.
        let mut out = vec![0u8; MAX_DGRAM];
        loop {
            let n = fill_datagram(&mut backend, &mut session.morph_dn, &mut out)?;
            if n == 0 {
                break;
            }
            let _ = sock.send_to(&out[..n], from).await;
        }

        if tokio::time::Instant::now() > deadline {
            break;
        }
    }

    Ok(Served::Prism { echoed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_flag_parses_truthy_values() {
        const VAR: &str = "PRISM_TEST_ENV_FLAG";
        std::env::remove_var(VAR);
        assert!(!env_flag(VAR));
        for (val, want) in [
            ("1", true),
            ("true", true),
            ("TRUE", true),
            ("0", false),
            ("", false),
        ] {
            std::env::set_var(VAR, val);
            assert_eq!(env_flag(VAR), want, "value {val:?}");
        }
        std::env::remove_var(VAR);
    }

    #[test]
    fn perf_mode_config_builds() {
        assert!(base_config(false).is_ok(), "stealth quiche config must build");
        assert!(base_config(true).is_ok(), "fast-session quiche config must build");
    }
}
