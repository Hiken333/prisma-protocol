//! TUN ↔ PRISM QUIC tunnel (live quiche backend).
#![cfg(feature = "tunnel")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use prism_auth::client_hello::RealityClientHello;
use prism_auth::server::{AuthDecision, ShadowDetector};
use prism_core::crypto::{X25519Public, X25519Secret};
use prism_tun::PlatformTun;
use tokio::net::UdpSocket;
use tokio::time::{sleep, Instant};

use prism_morph::MorphEngine;

use crate::backend::QuicBackend;
use crate::datagram::fill_datagram;
use crate::error::{QuicError, Result};
use crate::live::{
    base_config, bind_client_udp, drive_handshake, flush, load_cdn_profile,
    pump_recv_burst_for_peer, pump_recv_once, pump_recv_once_for_peer, pump_recv_max_wait,
    PeerPumpOutcome, PERF_RECV_BURST, PERF_UDP_DRAIN_CAP, PEER_IDLE_RELEASE, rand_cid, MAX_DGRAM,
};
use crate::quiche;
use crate::quiche_backend::QuicheBackend;
use crate::session::PrismSession;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const TUN_READ_TIMEOUT: Duration = Duration::from_millis(1);
/// Drop server sessions that never receive client QUIC streams (one-sided handshake).
const GHOST_SESSION_TIMEOUT: Duration = Duration::from_secs(20);
/// Max TUN packets to drain into QUIC per loop tick. Draining the whole burst
/// (instead of one packet + a morph sleep) is what lets TCP handshakes and bulk
/// transfers complete — a per-packet sleep overflows the TUN buffer under load.
const TUN_BATCH: usize = 1024;
/// Short idle backoff so the loop does not busy-spin when there is no traffic.
const IDLE_POLL: Duration = Duration::from_millis(1);
/// Keepalive cadence when the tunnel is idle (keeps QUIC + NAT state warm).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(1);

/// Fixed pool of QUIC streams carrying IP packets, selected by a canonical
/// 5-tuple hash (`prism_tun::pool_stream_id`). Stealth uses a small pool;
/// perf widens it to cut head-of-line blocking across browser flows.
const STREAM_POOL_STEALTH: u64 = 8;
const STREAM_POOL_PERF: u64 = 64;
/// Perf TUN upload budget per client tick (download uses recv burst after).
const TUN_UPLOAD_PERF: usize = 512;
/// Server perf: TUN read budget per tick (internet → client download).
const TUN_BATCH_PERF: usize = 512;
/// Server-only: interleave recv and TUN so ACKs stay timely under bulk download.
const PERF_MICRO_ROUNDS: usize = 4;
const PERF_TUN_SLICE: usize = 64;
const PERF_RECV_SLICE: u32 = 16;
/// Multiple `send` rounds per flush — quiche often has several datagrams queued.
const PERF_FLUSH_ROUNDS: usize = 4;
/// Cap UDP datagrams per `flush_morph` call so one tick cannot block for hundreds of ms.
const PERF_DGRAM_SEND_CAP: usize = 64;
const SCRATCH_PERF: usize = 65_536;
/// Cap per-stream outbound queue; beyond this whole packets are dropped (TCP
/// inside the tunnel retransmits).
const MAX_STREAM_BUF: usize = 4 * 1024 * 1024;
const DROP_WARN_INTERVAL: Duration = Duration::from_secs(5);

fn stream_pool(fast: bool) -> u64 {
    if fast {
        STREAM_POOL_PERF
    } else {
        STREAM_POOL_STEALTH
    }
}

fn tun_batch_limit(fast: bool) -> usize {
    if fast {
        TUN_BATCH_PERF
    } else {
        TUN_BATCH
    }
}

// #region agent log
use crate::agent_debug::{self, TunnelTickStats};

struct TunnelDiag {
    role: &'static str,
    fast: bool,
    loop_iters: u64,
    tun_pkts_in: u64,
    tun_bytes_in: u64,
    tun_pkts_out: u64,
    tun_bytes_out: u64,
    udp_pkts_sent: u64,
    udp_bytes_sent: u64,
    udp_pkts_recv: u64,
    keepalives: u64,
    loop_us_sum: u64,
    loop_us_max: u64,
    phase_tun_us: u64,
    phase_recv_us: u64,
    phase_flush_us: u64,
    phase_drain_us: u64,
    since_report: Instant,
    loop_start: Instant,
}

impl TunnelDiag {
    fn new(role: &'static str, fast: bool) -> Self {
        let now = Instant::now();
        Self {
            role,
            fast,
            loop_iters: 0,
            tun_pkts_in: 0,
            tun_bytes_in: 0,
            tun_pkts_out: 0,
            tun_bytes_out: 0,
            udp_pkts_sent: 0,
            udp_bytes_sent: 0,
            udp_pkts_recv: 0,
            keepalives: 0,
            loop_us_sum: 0,
            loop_us_max: 0,
            phase_tun_us: 0,
            phase_recv_us: 0,
            phase_flush_us: 0,
            phase_drain_us: 0,
            since_report: now,
            loop_start: now,
        }
    }

    fn loop_begin(&mut self) {
        self.loop_start = Instant::now();
        self.loop_iters += 1;
    }

    fn loop_end(&mut self, peer_idle_ms: u64) {
        let us = self.loop_start.elapsed().as_micros() as u64;
        self.loop_us_sum += us;
        self.loop_us_max = self.loop_us_max.max(us);
        if self.since_report.elapsed() >= Duration::from_secs(5) {
            let avg = if self.loop_iters > 0 {
                self.loop_us_sum / self.loop_iters
            } else {
                0
            };
            TunnelTickStats {
                role: self.role,
                fast: self.fast,
                loop_iters: self.loop_iters,
                tun_pkts_in: self.tun_pkts_in,
                tun_bytes_in: self.tun_bytes_in,
                tun_pkts_out: self.tun_pkts_out,
                tun_bytes_out: self.tun_bytes_out,
                udp_pkts_sent: self.udp_pkts_sent,
                udp_bytes_sent: self.udp_bytes_sent,
                udp_pkts_recv: self.udp_pkts_recv,
                udp_bytes_recv: 0,
                keepalives: self.keepalives,
                peer_idle_ms,
                loop_us_max: self.loop_us_max,
                loop_us_avg: avg,
                phase_tun_us: self.phase_tun_us,
                phase_recv_us: self.phase_recv_us,
                phase_flush_us: self.phase_flush_us,
                phase_drain_us: self.phase_drain_us,
            }
            .emit("H1");
            self.since_report = Instant::now();
            self.loop_iters = 0;
            self.tun_pkts_in = 0;
            self.tun_bytes_in = 0;
            self.tun_pkts_out = 0;
            self.tun_bytes_out = 0;
            self.udp_pkts_sent = 0;
            self.udp_bytes_sent = 0;
            self.udp_pkts_recv = 0;
            self.keepalives = 0;
            self.loop_us_sum = 0;
            self.loop_us_max = 0;
            self.phase_tun_us = 0;
            self.phase_recv_us = 0;
            self.phase_flush_us = 0;
            self.phase_drain_us = 0;
        }
    }

    fn emit_exit(&self, reason: &str, peer_idle_ms: u64) {
        agent_debug::log(
            "H3",
            "tunnel.rs:session_end",
            reason,
            &format!(
                r#"{{"role":"{}","fast":{},"peer_idle_ms":{},"udp_pkts_sent":{},"udp_bytes_sent":{},"udp_pkts_recv":{}}}"#,
                self.role, self.fast, peer_idle_ms, self.udp_pkts_sent, self.udp_bytes_sent, self.udp_pkts_recv
            ),
        );
    }
}
// #endregion

/// `PRISM_FAST=1` / `PRISM_PERF=1` disables morph size-padding on this process.
/// Client `--perf` also signals perf in GREASE `0x0A0A`; the server mirrors fast
/// morph for that session (or when server env sets fast/perf).
fn morph_padding_disabled_client() -> bool {
    crate::live::fast_session_active(false)
}

fn morph_padding_disabled_server(client_perf: bool) -> bool {
    crate::live::fast_session_active(client_perf)
}

/// Per-stream outbound byte queues. Whole IP packets are appended and drained
/// to QUIC in order, so a flow-control block can never tear a packet apart and
/// desync the length-delimited framing on a shared stream.
struct StreamSendBufs {
    bufs: Vec<Vec<u8>>,
    last_drop_warn: Instant,
    dropped: u64,
}

impl StreamSendBufs {
    fn new(pool: usize) -> Self {
        Self {
            bufs: vec![Vec::new(); pool],
            last_drop_warn: Instant::now()
                .checked_sub(DROP_WARN_INTERVAL)
                .unwrap_or_else(Instant::now),
            dropped: 0,
        }
    }

    /// Queue one whole IP packet for `stream_id`.
    fn queue(&mut self, stream_id: u64, pkt: &[u8]) {
        let slot = (stream_id / 4) as usize % self.bufs.len();
        let buf = &mut self.bufs[slot];
        if buf.len() + pkt.len() > MAX_STREAM_BUF {
            self.dropped += 1;
            if self.last_drop_warn.elapsed() >= DROP_WARN_INTERVAL {
                tracing::warn!(
                    stream_id,
                    dropped = self.dropped,
                    "stream send buffer full; dropping packet"
                );
                self.last_drop_warn = Instant::now();
            }
            return;
        }
        buf.extend_from_slice(pkt);
    }

    /// Drain queued bytes into QUIC streams as flow control allows. A
    /// per-stream backend error drops that stream's queue instead of killing
    /// the whole tunnel.
    fn flush(&mut self, backend: &mut QuicheBackend) -> Result<bool> {
        let mut any = false;
        for (slot, buf) in self.bufs.iter_mut().enumerate() {
            let sid = slot as u64 * 4;
            while !buf.is_empty() {
                match backend.stream_send(sid, buf, false) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.drain(..n);
                        any = true;
                    }
                    Err(QuicError::StreamBlocked(_)) | Err(QuicError::Done) => break,
                    Err(e) => {
                        tracing::warn!(sid, error = %e, "stream send failed; dropping queued bytes");
                        buf.clear();
                        break;
                    }
                }
            }
        }
        Ok(any)
    }

    fn has_pending(&self) -> bool {
        self.bufs.iter().any(|b| !b.is_empty())
    }
}

/// Client: connect to PRISM server and relay IP packets between TUN and QUIC.
/// TUN is opened only after QUIC handshake so wintun cannot disturb UDP path setup.
pub async fn run_client_tunnel(
    server: SocketAddr,
    shadow_pk: X25519Public,
    decoy: &str,
    tun_name: &str,
    tun_mtu: usize,
    tun_cidr: &str,
) -> Result<()> {
    let (sock, local) = bind_client_udp(server).await?;

    let mut cfg = base_config(morph_padding_disabled_client())?;
    let scid = rand_cid();
    let mut conn = quiche::connect(Some(decoy), &scid, local, server, &mut cfg)
        .map_err(|e| QuicError::Backend(format!("connect: {e:?}")))?;

    let ch = RealityClientHello::build(&shadow_pk, decoy);
    conn.set_prism_x25519_offer_seed(&ch.offer_seed());
    let mut grease_wire = [0u8; prism_auth::client_hello::GREASE_WIRE_LEN_PERF];
    let wire = ch.grease_ext_wire(crate::live::prism_perf(), &mut grease_wire);
    conn.set_prism_auth_tag(wire);

    tracing::info!(%server, "PRISM QUIC handshake starting");
    drive_handshake(&mut conn, &sock, local, HANDSHAKE_TIMEOUT).await?;

    tracing::info!(%server, "PRISM QUIC handshake done; opening TUN");

    let mut tun = PlatformTun::open(tun_name, tun_mtu, tun_cidr)
        .await
        .map_err(|e| QuicError::Backend(format!("open TUN: {e}")))?;

    // Full-tunnel routes only after QUIC handshake + TUN open.
    #[cfg(target_os = "windows")]
    let _routes = {
        let (tun_if_index, tun_alias) = tun.windows_route_target();
        prism_tun::RouteGuard::install(&server.ip().to_string(), tun_if_index, &tun_alias)
            .map_err(|e| QuicError::Backend(format!("routes: {e}")))?
    };

    tracing::info!(%server, tun = tun_name, "PRISM tunnel established (client)");

    let fast = morph_padding_disabled_client();
    if fast {
        std::env::set_var("PRISM_SESSION_DEBUG", "1");
        crate::agent_debug::announce();
    }
    if fast {
        tracing::info!(
            perf = crate::live::prism_perf(),
            "client fast path: morph size-padding disabled"
        );
    }

    let mut backend = QuicheBackend::from_connection(conn, local, server);
    let mut session = PrismSession::derive(&mut backend, load_cdn_profile(), 0.10, MAX_DGRAM)?;

    if crate::bolt_tunnel::use_bolt_data_plane(fast) {
        tracing::info!(
            lanes = ?prism_bolt::BoltLanes::lane_addrs_default(server),
            "client upgrading to PRISM BOLT data plane"
        );
        return crate::bolt_tunnel::run_client_bolt(
            backend,
            Arc::new(sock),
            local,
            server,
            tun,
            fast,
        )
        .await;
    }

    let mut send_bufs = StreamSendBufs::new(stream_pool(fast) as usize);
    let mut tun_buf = vec![0u8; tun.mtu() + 128];
    let scratch_len = if fast { SCRATCH_PERF } else { 8192 };
    let mut scratch = vec![0u8; scratch_len];
    let mut reasm: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut out_buf = vec![0u8; MAX_DGRAM];

    let mut last_keepalive = Instant::now();
    let pool = stream_pool(fast);
    let batch = tun_batch_limit(fast);
    let mut diag = TunnelDiag::new("client", fast);

    loop {
        diag.loop_begin();
        {
            let conn = backend.connection_mut();
            if conn.is_closed() {
                diag.emit_exit("conn_closed", 0);
                tracing::info!("PRISM tunnel closed by peer");
                break;
            }
        }

        let mut did_work = false;

        if fast {
            let tun_t0 = Instant::now();
            for _ in 0..TUN_UPLOAD_PERF {
                match tokio::time::timeout(TUN_READ_TIMEOUT, tun.read_packet(&mut tun_buf)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let Some(len) = framed_ip_packet_len(&tun_buf[..n]) else {
                            continue;
                        };
                        let pkt = &tun_buf[..len];
                        let Ok(sid) = prism_tun::pool_stream_id(pkt, pool) else {
                            continue;
                        };
                        send_bufs.queue(sid, pkt);
                        diag.tun_pkts_in += 1;
                        diag.tun_bytes_in += len as u64;
                        did_work = true;
                    }
                    Ok(Ok(_)) => break,
                    Ok(Err(e)) => return Err(QuicError::Backend(format!("tun read: {e}"))),
                    Err(_) => break,
                }
            }
            diag.phase_tun_us += tun_t0.elapsed().as_micros() as u64;

            if send_bufs.flush(&mut backend)? {
                did_work = true;
            }

            let flush_t0 = Instant::now();
            if flush_outbound_burst(
                &mut backend,
                &mut session.morph_up,
                &sock,
                server,
                &mut out_buf,
                true,
                &mut diag,
            )
            .await?
            {
                did_work = true;
            }
            if send_bufs.has_pending() && send_bufs.flush(&mut backend)? {
                did_work = true;
                let _ = flush_outbound_burst(
                    &mut backend,
                    &mut session.morph_up,
                    &sock,
                    server,
                    &mut out_buf,
                    true,
                    &mut diag,
                )
                .await?;
            }
            diag.phase_flush_us += flush_t0.elapsed().as_micros() as u64;

            let recv_t0 = Instant::now();
            let mut round_recv = 0u32;
            {
                let conn = backend.connection_mut();
                pump_recv_burst_for_peer(
                    conn,
                    &sock,
                    local,
                    None,
                    None,
                    pump_recv_max_wait(true),
                    PERF_RECV_BURST,
                    &mut round_recv,
                    Some(PERF_UDP_DRAIN_CAP),
                )
                .await?;
            }
            diag.udp_pkts_recv += round_recv as u64;
            diag.phase_recv_us += recv_t0.elapsed().as_micros() as u64;

            let drain_t0 = Instant::now();
            if drain_to_tun(&mut backend, &mut scratch, &mut reasm, &mut tun).await? {
                did_work = true;
                diag.tun_pkts_out += 1;
            }
            diag.phase_drain_us += drain_t0.elapsed().as_micros() as u64;

            let flush_t1 = Instant::now();
            if flush_outbound_burst(
                &mut backend,
                &mut session.morph_up,
                &sock,
                server,
                &mut out_buf,
                true,
                &mut diag,
            )
            .await?
            {
                did_work = true;
            }
            diag.phase_flush_us += flush_t1.elapsed().as_micros() as u64;
        } else {
            for _ in 0..batch {
                match tokio::time::timeout(TUN_READ_TIMEOUT, tun.read_packet(&mut tun_buf)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let Some(len) = framed_ip_packet_len(&tun_buf[..n]) else {
                            continue;
                        };
                        let pkt = &tun_buf[..len];
                        let Ok(sid) = prism_tun::pool_stream_id(pkt, pool) else {
                            continue;
                        };
                        send_bufs.queue(sid, pkt);
                        diag.tun_pkts_in += 1;
                        diag.tun_bytes_in += len as u64;
                        did_work = true;
                    }
                    Ok(Ok(_)) => break,
                    Ok(Err(e)) => return Err(QuicError::Backend(format!("tun read: {e}"))),
                    Err(_) => break,
                }
            }
            if send_bufs.flush(&mut backend)? {
                did_work = true;
            }
            if flush_outbound_burst(
                &mut backend,
                &mut session.morph_up,
                &sock,
                server,
                &mut out_buf,
                false,
                &mut diag,
            )
            .await?
            {
                did_work = true;
            }

            {
                let conn = backend.connection_mut();
                pump_recv_once(conn, &sock, local).await?;
            }
            if drain_to_tun(&mut backend, &mut scratch, &mut reasm, &mut tun).await? {
                did_work = true;
                diag.tun_pkts_out += 1;
            }

            if send_bufs.has_pending() && send_bufs.flush(&mut backend)? {
                did_work = true;
            }
            if flush_outbound_burst(
                &mut backend,
                &mut session.morph_up,
                &sock,
                server,
                &mut out_buf,
                false,
                &mut diag,
            )
            .await?
            {
                did_work = true;
            }
        }

        if last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
            backend.send_ping()?;
            diag.keepalives += 1;
            let _ = flush_outbound_burst(
                &mut backend,
                &mut session.morph_up,
                &sock,
                server,
                &mut out_buf,
                fast,
                &mut diag,
            )
            .await?;
            last_keepalive = Instant::now();
            did_work = true;
        }

        if !did_work {
            if fast {
                tokio::task::yield_now().await;
            } else {
                sleep(IDLE_POLL).await;
            }
        }
        diag.loop_end(0);
    }

    PrismSession::graceful_close(&mut backend)?;
    {
        let conn = backend.connection_mut();
        flush(conn, &sock).await?;
    }
    Ok(())
}

/// Server outcome for one inbound connection (tunnel mode).
pub enum TunnelServed {
    Prism,
    Decoy {
        first_datagram: Vec<u8>,
        from: SocketAddr,
    },
}

/// Server: accept one PRISM client and relay between TUN and QUIC.
/// `client_ip` is the client's address inside the tunnel (e.g. 172.19.0.2);
/// only TUN packets destined to it are forwarded back.
pub async fn run_server_tunnel(
    bind: SocketAddr,
    shadow_sk: X25519Secret,
    decoy: &str,
    cert: &str,
    key: &str,
    tun: &mut PlatformTun,
    client_ip: std::net::Ipv4Addr,
) -> Result<TunnelServed> {
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| QuicError::Backend(e.to_string()))?;
    if crate::live::prism_perf() || crate::live::env_flag("PRISM_FAST") {
        crate::live::tune_udp_socket_perf(&sock);
    } else {
        crate::live::tune_udp_socket(&sock);
    }
    let local = sock
        .local_addr()
        .map_err(|e| QuicError::Backend(e.to_string()))?;

    let detector = ShadowDetector::new(shadow_sk, decoy);

    let mut buf = [0u8; 2048];
    let (first, from, client_perf) = loop {
        let (n, from) = sock
            .recv_from(&mut buf)
            .await
            .map_err(|e| QuicError::Backend(e.to_string()))?;
        let first = buf[..n].to_vec();

        let decision = match quiche::prism_peek_client_hello(&first) {
            Some(hello) => detector.classify(&hello),
            None => {
                // #region agent log
                agent_debug::log(
                    "B7",
                    "tunnel.rs:accept",
                    "drop non-PRISM Initial",
                    &format!(r#"{{"from":"{from}","len":{n}}}"#),
                );
                // #endregion
                tracing::debug!(%from, len = n, "dropping non-Initial datagram on listen socket");
                continue;
            }
        };
        let client_perf = matches!(
            &decision,
            AuthDecision::Accept {
                client_perf: true,
                ..
            }
        );
        if matches!(decision, AuthDecision::ProxyToDecoy) {
            return Ok(TunnelServed::Decoy {
                first_datagram: first,
                from,
            });
        }
        break (first, from, client_perf);
    };

    let mut cfg = base_config(morph_padding_disabled_server(client_perf))?;
    cfg.load_cert_chain_from_pem_file(cert)
        .map_err(|e| QuicError::Backend(format!("cert: {e:?}")))?;
    cfg.load_priv_key_from_pem_file(key)
        .map_err(|e| QuicError::Backend(format!("key: {e:?}")))?;

    let hdr = quiche::Header::from_slice(&mut first.clone(), quiche::MAX_CONN_ID_LEN)
        .map_err(|e| QuicError::Backend(format!("hdr: {e:?}")))?;
    let scid = rand_cid();
    let mut conn = quiche::accept(&scid, Some(&hdr.dcid), local, from, &mut cfg)
        .map_err(|e| QuicError::Backend(format!("accept: {e:?}")))?;

    let info = quiche::RecvInfo { from, to: local };
    let mut fb = first.clone();
    let _ = conn.recv(&mut fb, info);

    drive_handshake(&mut conn, &sock, local, HANDSHAKE_TIMEOUT).await?;

    tracing::info!(%from, "PRISM tunnel established (server)");

    let fast = morph_padding_disabled_server(client_perf);
    if fast {
        std::env::set_var("PRISM_SESSION_DEBUG", "1");
        crate::agent_debug::announce();
    }
    if crate::live::env_flag("PRISM_FAST") {
        tracing::info!("server fast path: morph size-padding disabled (PRISM_FAST)");
    } else if crate::live::prism_perf() {
        tracing::info!("server PRISM_PERF: fast morph + throughput tuning for all sessions");
    } else if client_perf {
        tracing::info!("client requested perf; server mirroring fast path for session");
    }

    let mut backend = QuicheBackend::from_connection(conn, local, from);
    let mut session = PrismSession::derive(&mut backend, load_cdn_profile(), 0.10, MAX_DGRAM)?;

    if crate::bolt_tunnel::use_bolt_data_plane(fast) {
        tracing::info!(
            %from,
            lanes = ?prism_bolt::BoltLanes::lane_addrs_default(local),
            "server upgrading to PRISM BOLT data plane"
        );
        crate::bolt_tunnel::run_server_bolt(
            backend,
            Arc::new(sock),
            local,
            from,
            tun,
            client_ip,
            fast,
        )
        .await?;
        return Ok(TunnelServed::Prism);
    }

    let mut send_bufs = StreamSendBufs::new(stream_pool(fast) as usize);
    // The server may only send on client-initiated bidi streams the client has
    // already opened. A flow's forward packet always precedes its return
    // packet, so the canonically-hashed stream is open by the time we need it;
    // `open_slots` guards the rare server-originated flow (e.g. ICMP errors).
    let mut tun_buf = vec![0u8; tun.mtu() + 128];
    let scratch_len = if fast { SCRATCH_PERF } else { 8192 };
    let mut scratch = vec![0u8; scratch_len];
    let mut reasm: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut out_buf = vec![0u8; MAX_DGRAM];
    let established_at = Instant::now();
    let mut saw_client_streams = false;
    let mut last_keepalive = Instant::now();
    let mut last_peer_rx = std::time::Instant::now();
    let pool = stream_pool(fast);
    let batch = tun_batch_limit(fast);
    let pool_slots = pool as usize;
    let mut open_slots = vec![false; pool_slots];
    let mut diag = TunnelDiag::new("server", fast);

    'server: loop {
        diag.loop_begin();
        let peer_idle_ms = last_peer_rx.elapsed().as_millis() as u64;
        {
            let conn = backend.connection_mut();
            if conn.is_closed() {
                diag.emit_exit("conn_closed", peer_idle_ms);
                tracing::info!(%from, "PRISM client disconnected");
                break;
            }
        }

        if last_peer_rx.elapsed() >= PEER_IDLE_RELEASE {
            diag.emit_exit("peer_idle", peer_idle_ms);
            tracing::info!(
                %from,
                idle_secs = last_peer_rx.elapsed().as_secs(),
                "peer idle; releasing session for reconnect"
            );
            break;
        }

        if !saw_client_streams && established_at.elapsed() > GHOST_SESSION_TIMEOUT {
            diag.emit_exit("ghost_session", peer_idle_ms);
            tracing::warn!(
                %from,
                "no client QUIC streams after handshake; releasing session for retry"
            );
            break;
        }

        let mut did_work = false;

        if fast {
            for _ in 0..PERF_MICRO_ROUNDS {
                let recv_t0 = Instant::now();
                let mut round_recv = 0u32;
                {
                    let conn = backend.connection_mut();
                    match pump_recv_burst_for_peer(
                        conn,
                        &sock,
                        local,
                        Some(from),
                        Some(&mut last_peer_rx),
                        pump_recv_max_wait(true),
                        PERF_RECV_SLICE,
                        &mut round_recv,
                        Some(PERF_UDP_DRAIN_CAP),
                    )
                    .await?
                    {
                        PeerPumpOutcome::Ok => {}
                        PeerPumpOutcome::ReconnectAttempt => {
                            diag.emit_exit("reconnect_attempt", peer_idle_ms);
                            break 'server;
                        }
                    }
                }
                diag.udp_pkts_recv += round_recv as u64;
                diag.phase_recv_us += recv_t0.elapsed().as_micros() as u64;
                if round_recv > 0 {
                    did_work = true;
                }

                for sid in backend.readable() {
                    saw_client_streams = true;
                    let slot = (sid / 4) as usize;
                    if slot < open_slots.len() {
                        open_slots[slot] = true;
                    }
                }

                let tun_t0 = Instant::now();
                for _ in 0..PERF_TUN_SLICE {
                    match tokio::time::timeout(TUN_READ_TIMEOUT, tun.read_packet(&mut tun_buf)).await
                    {
                        Ok(Ok(n)) if n > 0 => {
                            let Some(len) = framed_ip_packet_len(&tun_buf[..n]) else {
                                continue;
                            };
                            let pkt = &tun_buf[..len];
                            if ipv4_dst(pkt) != Some(client_ip) {
                                continue;
                            }
                            let Ok(sid) = prism_tun::pool_stream_id(pkt, pool) else {
                                continue;
                            };
                            let slot = (sid / 4) as usize % open_slots.len();
                            let sid = if open_slots[slot] {
                                sid
                            } else {
                                match open_slots.iter().position(|&o| o) {
                                    Some(s) => s as u64 * 4,
                                    None => continue,
                                }
                            };
                            send_bufs.queue(sid, pkt);
                            diag.tun_pkts_in += 1;
                            diag.tun_bytes_in += len as u64;
                            did_work = true;
                        }
                        Ok(Ok(_)) => break,
                        Ok(Err(e)) => return Err(QuicError::Backend(format!("tun read: {e}"))),
                        Err(_) => break,
                    }
                }
                diag.phase_tun_us += tun_t0.elapsed().as_micros() as u64;

                if send_bufs.flush(&mut backend)? {
                    did_work = true;
                }

                let flush_t0 = Instant::now();
                if flush_outbound_burst(
                    &mut backend,
                    &mut session.morph_dn,
                    &sock,
                    from,
                    &mut out_buf,
                    true,
                    &mut diag,
                )
                .await?
                {
                    did_work = true;
                }
                diag.phase_flush_us += flush_t0.elapsed().as_micros() as u64;

                let drain_t0 = Instant::now();
                if drain_to_tun(&mut backend, &mut scratch, &mut reasm, tun).await? {
                    did_work = true;
                    diag.tun_pkts_out += 1;
                }
                diag.phase_drain_us += drain_t0.elapsed().as_micros() as u64;

                if send_bufs.has_pending() && send_bufs.flush(&mut backend)? {
                    did_work = true;
                }
                let flush_t1 = Instant::now();
                if flush_outbound_burst(
                    &mut backend,
                    &mut session.morph_dn,
                    &sock,
                    from,
                    &mut out_buf,
                    true,
                    &mut diag,
                )
                .await?
                {
                    did_work = true;
                }
                diag.phase_flush_us += flush_t1.elapsed().as_micros() as u64;
            }
        } else {
            {
                let conn = backend.connection_mut();
                match pump_recv_once_for_peer(
                    conn,
                    &sock,
                    local,
                    Some(from),
                    Some(&mut last_peer_rx),
                    fast,
                )
                    .await?
                {
                    PeerPumpOutcome::Ok => {}
                    PeerPumpOutcome::ReconnectAttempt => {
                        diag.emit_exit("reconnect_attempt", peer_idle_ms);
                        break;
                    }
                }
            }

            for sid in backend.readable() {
                saw_client_streams = true;
                let slot = (sid / 4) as usize;
                if slot < open_slots.len() {
                    open_slots[slot] = true;
                }
            }

            if drain_to_tun(&mut backend, &mut scratch, &mut reasm, tun).await? {
                did_work = true;
                diag.tun_pkts_out += 1;
            }

            for _ in 0..batch {
                match tokio::time::timeout(TUN_READ_TIMEOUT, tun.read_packet(&mut tun_buf)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let Some(len) = framed_ip_packet_len(&tun_buf[..n]) else {
                            continue;
                        };
                        let pkt = &tun_buf[..len];
                        if ipv4_dst(pkt) != Some(client_ip) {
                            continue;
                        }
                        let Ok(sid) = prism_tun::pool_stream_id(pkt, pool) else {
                            continue;
                        };
                        let slot = (sid / 4) as usize % open_slots.len();
                        let sid = if open_slots[slot] {
                            sid
                        } else {
                            match open_slots.iter().position(|&o| o) {
                                Some(s) => s as u64 * 4,
                                None => continue,
                            }
                        };
                        send_bufs.queue(sid, pkt);
                        diag.tun_pkts_in += 1;
                        diag.tun_bytes_in += len as u64;
                        did_work = true;
                    }
                    Ok(Ok(_)) => break,
                    Ok(Err(e)) => return Err(QuicError::Backend(format!("tun read: {e}"))),
                    Err(_) => break,
                }
            }
            if send_bufs.flush(&mut backend)? {
                did_work = true;
            }

            if flush_outbound_burst(
                &mut backend,
                &mut session.morph_dn,
                &sock,
                from,
                &mut out_buf,
                false,
                &mut diag,
            )
            .await?
            {
                did_work = true;
            }

            if send_bufs.has_pending() && send_bufs.flush(&mut backend)? {
                did_work = true;
            }
            if flush_outbound_burst(
                &mut backend,
                &mut session.morph_dn,
                &sock,
                from,
                &mut out_buf,
                false,
                &mut diag,
            )
            .await?
            {
                did_work = true;
            }
        }

        if last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
            backend.send_ping()?;
            diag.keepalives += 1;
            let _ = flush_outbound_burst(
                &mut backend,
                &mut session.morph_dn,
                &sock,
                from,
                &mut out_buf,
                fast,
                &mut diag,
            )
            .await?;
            last_keepalive = Instant::now();
            did_work = true;
        }

        if !did_work {
            if fast {
                tokio::task::yield_now().await;
            } else {
                sleep(IDLE_POLL).await;
            }
        }
        diag.loop_end(peer_idle_ms);
    }

    Ok(TunnelServed::Prism)
}

/// Flush outbound datagrams. Perf mode runs multiple quiche `send` rounds per tick.
async fn flush_outbound_burst(
    backend: &mut QuicheBackend,
    morph: &mut MorphEngine,
    sock: &UdpSocket,
    peer: SocketAddr,
    out: &mut [u8],
    fast: bool,
    diag: &mut TunnelDiag,
) -> Result<bool> {
    if !fast {
        let (sent, pkts, bytes) = flush_morph(backend, morph, sock, peer, out, false).await?;
        diag.udp_pkts_sent += pkts;
        diag.udp_bytes_sent += bytes;
        return Ok(sent);
    }
    let mut sent = false;
    for _ in 0..PERF_FLUSH_ROUNDS {
        let (s, pkts, bytes) = flush_morph(backend, morph, sock, peer, out, true).await?;
        diag.udp_pkts_sent += pkts;
        diag.udp_bytes_sent += bytes;
        if s {
            sent = true;
        } else {
            break;
        }
    }
    Ok(sent)
}

/// Drain all queued QUIC data into datagrams and send them. Returns
/// `(anything_sent, packet_count, total_bytes)`.
async fn flush_morph(
    backend: &mut QuicheBackend,
    morph: &mut MorphEngine,
    sock: &UdpSocket,
    peer: SocketAddr,
    out: &mut [u8],
    fast: bool,
) -> Result<(bool, u64, u64)> {
    let mut sent = false;
    let mut pkts = 0u64;
    let mut bytes = 0u64;
    loop {
        let n = if fast {
            backend.set_morph_target(0);
            backend.send(out)?
        } else {
            fill_datagram(backend, morph, out)?
        };
        if n == 0 {
            break;
        }
        sock.send_to(&out[..n], peer)
            .await
            .map_err(|e| QuicError::Backend(e.to_string()))?;
        sent = true;
        pkts += 1;
        bytes += n as u64;
        if fast && pkts >= PERF_DGRAM_SEND_CAP as u64 {
            break;
        }
    }
    Ok((sent, pkts, bytes))
}

/// Returns `true` if at least one IP packet was written to the TUN device.
async fn drain_to_tun(
    backend: &mut QuicheBackend,
    scratch: &mut [u8],
    reasm: &mut HashMap<u64, Vec<u8>>,
    tun: &mut PlatformTun,
) -> Result<bool> {
    let mut touched: Vec<u64> = Vec::new();
    let mut finished: Vec<u64> = Vec::new();
    {
        let mut dec = crate::mcc::MccDecoder::new(backend);
        dec.drain(scratch, |sid, bytes, fin| {
            if !bytes.is_empty() {
                reasm.entry(sid).or_default().extend_from_slice(bytes);
                if !touched.contains(&sid) {
                    touched.push(sid);
                }
            }
            if fin {
                finished.push(sid);
                if !touched.contains(&sid) {
                    touched.push(sid);
                }
            }
        })?;
    }

    // Streams carry length-delimited IP packets (multiple flows share each
    // pool stream). Pop each complete IP datagram (length from the IP header)
    // and write it individually; keep any trailing partial packet buffered.
    let mut wrote = false;
    for sid in touched {
        let Some(buf) = reasm.get_mut(&sid) else {
            continue;
        };
        loop {
            let Some(len) = framed_ip_packet_len(buf) else {
                break;
            };
            let pkt: Vec<u8> = buf.drain(..len).collect();
            tun.write_packet(&pkt)
                .await
                .map_err(|e| QuicError::Backend(format!("tun write: {e}")))?;
            wrote = true;
        }
        let drop_buf = if finished.contains(&sid) || buf.is_empty() {
            // On FIN any leftover bytes cannot form a packet.
            true
        } else {
            let v = buf[0] >> 4;
            // A healthy buffer always starts at an IPv4/IPv6 header and an IP
            // packet is at most 65535 bytes; anything else means the stream
            // framing desynced — recover by discarding the buffer.
            if (v != 4 && v != 6) || buf.len() > 70_000 {
                tracing::warn!(
                    sid,
                    len = buf.len(),
                    "desynced stream reassembly buffer; dropping"
                );
                true
            } else {
                false
            }
        };
        if drop_buf {
            reasm.remove(&sid);
        }
    }
    Ok(wrote)
}

/// Destination address of an IPv4 packet (`None` for IPv6 / malformed).
pub(crate) fn ipv4_dst(pkt: &[u8]) -> Option<std::net::Ipv4Addr> {
    if pkt.len() >= 20 && pkt[0] >> 4 == 4 {
        Some(std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
    } else {
        None
    }
}

/// Length of the complete IP datagram at the front of `buf`, or `None` if the
/// buffer does not yet hold a full packet.
pub(crate) fn framed_ip_packet_len(buf: &[u8]) -> Option<usize> {
    if buf.is_empty() {
        return None;
    }
    match buf[0] >> 4 {
        4 => {
            if buf.len() < 20 {
                return None;
            }
            let ihl = (buf[0] & 0x0f) as usize * 4;
            if ihl < 20 {
                return None;
            }
            let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            if total_len < ihl || buf.len() < total_len {
                return None;
            }
            Some(total_len)
        }
        6 => {
            if buf.len() < 40 {
                return None;
            }
            let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
            let total = 40 + payload_len;
            if buf.len() < total {
                return None;
            }
            Some(total)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn morph_padding_mode_matrix() {
        std::env::remove_var("PRISM_FAST");
        std::env::remove_var("PRISM_PERF");
        assert!(!morph_padding_disabled_client(), "client default keeps padding");
        assert!(
            !morph_padding_disabled_server(false),
            "server default keeps padding"
        );

        std::env::set_var("PRISM_PERF", "1");
        assert!(
            morph_padding_disabled_client(),
            "PRISM_PERF disables padding on client"
        );
        assert!(
            morph_padding_disabled_server(false),
            "PRISM_PERF on server disables padding for all sessions"
        );
        assert!(
            morph_padding_disabled_server(true),
            "client perf handshake mirrors fast morph on server"
        );

        std::env::set_var("PRISM_FAST", "1");
        assert!(morph_padding_disabled_client());
        assert!(morph_padding_disabled_server(false));

        std::env::remove_var("PRISM_FAST");
        std::env::remove_var("PRISM_PERF");
    }
}
