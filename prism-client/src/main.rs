//! PRISM client binary — native UDP transport.
//!
//! Connects to a PRISM server over real UDP, performs the Reality handshake,
//! then sends VPN packets as morph-shaped, AEAD-protected datagrams. In this
//! build the server echoes streams back, so the client verifies the round trip.
//!
//! Usage:
//!   prism-client --server HOST:PORT --shadow-pk HEX [--decoy www.cloudflare.com] [--count N]
//!   prism-client --selftest        # run an in-process server over loopback UDP
//!
//! Lifecycle (spec 5.4): PRECONFIG -> HANDSHAKE (Reality INIT) -> DATA -> CLOSE.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use prism_core::crypto::X25519Public;
#[allow(unused_imports)]
use prism_core::crypto::X25519Secret;

/// Ask Windows for 1 ms timer granularity. The default (~15.6 ms) inflates
/// every tokio `sleep`/`timeout` in the tunnel event loop (idle poll, QUIC
/// loss/PTO timers), delaying loss recovery and idle-to-burst transitions.
#[cfg(windows)]
fn raise_timer_resolution() {
    // Safety: plain WinMM call; the OS restores the period on process exit.
    unsafe {
        windows_sys::Win32::Media::timeBeginPeriod(1);
    }
}

#[cfg(not(windows))]
fn raise_timer_resolution() {}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    raise_timer_resolution();

    let args = Args::parse()?;

    let perf = args.perf || env_flag("PRISM_PERF");
    if perf {
        std::env::set_var("PRISM_PERF", "1");
        tracing::info!("performance mode enabled (--perf / PRISM_PERF=1): morph size-padding off, quiche pacing off; BOLT data plane auto-enabled when fast session active");
    }
    #[cfg(feature = "quiche-backend")]
    prism_quic::agent_debug::announce();

    if args.selftest {
        return run_selftest(args.count).await;
    }

    let server: SocketAddr = args.server.context("--server is required (or use --selftest)")?;
    let shadow_pk_hex = args
        .shadow_pk
        .as_deref()
        .context("--shadow-pk is required (or use --selftest)")?;
    let shadow_pk =
        X25519Public::from_bytes(&decode_hex(shadow_pk_hex)?).context("bad --shadow-pk")?;

    if args.tun {
        return run_tun(server, shadow_pk, &args.decoy, &args).await;
    }

    if let Some(secs) = args.bulk {
        return run_bulk(server, shadow_pk, &args.decoy, secs).await;
    }

    run_client(server, shadow_pk, &args.decoy, args.count).await
}

/// Full TUN VPN mode (Windows wintun + quiche backend).
#[cfg(feature = "tunnel")]
async fn run_tun(
    server: SocketAddr,
    shadow_pk: X25519Public,
    decoy: &str,
    args: &Args,
) -> Result<()> {
    tracing::info!(
        %server,
        tun = %args.tun_name,
        cidr = %args.tun_cidr,
        "PRISM TUN tunnel starting"
    );

    prism_quic::tunnel::run_client_tunnel(
        server,
        shadow_pk,
        decoy,
        &args.tun_name,
        args.mtu,
        &args.tun_cidr,
    )
    .await
    .context("tunnel")?;

    tracing::info!("PRISM TUN tunnel stopped");
    Ok(())
}

#[cfg(not(feature = "tunnel"))]
async fn run_tun(
    _server: SocketAddr,
    _shadow_pk: X25519Public,
    _decoy: &str,
    _args: &Args,
) -> Result<()> {
    anyhow::bail!("--tun requires building with --features tunnel,quiche-backend")
}

/// Sustained traffic generator: stream morph-shaped datagrams for `secs` so a
/// packet capture sees a representative size / inter-arrival distribution. Only
/// meaningful with the quiche backend (the native data plane).
#[cfg(feature = "quiche-backend")]
async fn run_bulk(server: SocketAddr, shadow_pk: X25519Public, decoy: &str, secs: u64) -> Result<()> {
    use std::time::Duration;
    let stats =
        prism_quic::live::run_client_bulk(server, shadow_pk, decoy, Duration::from_secs(secs)).await?;
    tracing::info!(
        datagrams = stats.datagrams_sent,
        app_bytes = stats.bytes_app,
        echoes = stats.echoes,
        "BULK done: streamed morph-shaped traffic"
    );
    Ok(())
}

#[cfg(not(feature = "quiche-backend"))]
async fn run_bulk(_server: SocketAddr, _shadow_pk: X25519Public, _decoy: &str, _secs: u64) -> Result<()> {
    anyhow::bail!("--bulk requires the quiche-backend feature (native data plane)")
}

/// Build the demo VPN payloads sent on each stream.
fn demo_payloads(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| format!("prism-vpn-packet-#{i}").into_bytes())
        .collect()
}

/// Pure-Rust `prism-transport` client (default build).
#[cfg(not(feature = "quiche-backend"))]
async fn run_client(server: SocketAddr, shadow_pk: X25519Public, decoy: &str, count: usize) -> Result<()> {
    use std::time::Duration;
    use prism_transport::{ClientConfig, ClientConnection};

    let mut cli = ClientConnection::connect(ClientConfig::new(server, shadow_pk, decoy)).await?;
    tracing::info!(%server, "handshake done; sending {count} VPN packets");

    let payloads = demo_payloads(count);
    for (i, p) in payloads.iter().enumerate() {
        cli.send_packet((i as u64) * 4, true, p).await?;
        tracing::info!(stream = i * 4, bytes = p.len(), "sent VPN packet");
    }

    let mut received = 0usize;
    for _ in 0..payloads.len() {
        match cli.recv_chunks(Duration::from_secs(2)).await {
            Ok(chunks) => {
                for c in chunks {
                    received += 1;
                    tracing::info!(stream = c.stream_id, bytes = c.data.len(), "received echo");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "no more echoes");
                break;
            }
        }
    }

    if received == payloads.len() {
        tracing::info!("SUCCESS: all {received} packets round-tripped over real UDP");
        Ok(())
    } else {
        anyhow::bail!("only {received}/{} packets round-tripped", payloads.len());
    }
}

/// Native quiche + BoringSSL client (`--features quiche-backend`).
#[cfg(feature = "quiche-backend")]
async fn run_client(server: SocketAddr, shadow_pk: X25519Public, decoy: &str, count: usize) -> Result<()> {
    tracing::info!(%server, "quiche backend: connecting and sending {count} VPN packets");
    let payloads = demo_payloads(count);
    let received = prism_quic::live::run_client(server, shadow_pk, decoy, &payloads).await?;

    for (i, r) in received.iter().enumerate() {
        tracing::info!(idx = i, bytes = r.len(), "received echo");
    }
    if received.len() == payloads.len() {
        tracing::info!("SUCCESS: all {} packets round-tripped over real UDP (quiche)", received.len());
        Ok(())
    } else {
        anyhow::bail!("only {}/{} packets round-tripped", received.len(), payloads.len());
    }
}

/// Spin up an in-process server on loopback and run the client against it over
/// real UDP sockets — a one-command end-to-end test.
#[cfg(not(feature = "quiche-backend"))]
async fn run_selftest(count: usize) -> Result<()> {
    use std::time::Duration;
    use prism_transport::{Server, ServerConfig};

    let shadow_sk = X25519Secret::generate();
    let shadow_pk = shadow_sk.public();
    let decoy = "www.cloudflare.com";

    let server = Server::bind(ServerConfig::new("127.0.0.1:0".parse().unwrap(), shadow_sk, decoy)).await?;
    let addr = server.local_addr()?;
    tracing::info!(%addr, "selftest: in-process PRISM server bound on loopback UDP");

    tokio::spawn(async move {
        if let Err(e) = server.run().await {
            tracing::error!(error = %e, "server stopped");
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    run_client(addr, shadow_pk, decoy, count).await
}

/// quiche-backend selftest: spawn a single-connection live server on loopback
/// and run the live client against it. Requires PRISM_TEST_CERT / PRISM_TEST_KEY
/// PEM paths (e.g. quiche's `examples/cert.crt` / `cert.key`).
#[cfg(feature = "quiche-backend")]
async fn run_selftest(count: usize) -> Result<()> {
    use std::time::Duration;
    use prism_quic::live::run_server_once;

    let cert = std::env::var("PRISM_TEST_CERT")
        .context("selftest (quiche): set PRISM_TEST_CERT to a server cert PEM")?;
    let key = std::env::var("PRISM_TEST_KEY")
        .context("selftest (quiche): set PRISM_TEST_KEY to a server key PEM")?;

    let shadow_sk = X25519Secret::generate();
    let shadow_pk = shadow_sk.public();
    let decoy = "www.cloudflare.com";
    let bind: SocketAddr = "127.0.0.1:48700".parse().unwrap();

    tokio::spawn(async move {
        if let Err(e) = run_server_once(bind, shadow_sk, decoy, &cert, &key).await {
            tracing::error!(error = %e, "selftest server stopped");
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    run_client(bind, shadow_pk, decoy, count).await
}

struct Args {
    server: Option<SocketAddr>,
    shadow_pk: Option<String>,
    decoy: String,
    count: usize,
    selftest: bool,
    bulk: Option<u64>,
    tun: bool,
    tun_name: String,
    tun_cidr: String,
    mtu: usize,
    perf: bool,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut server = None;
        let mut shadow_pk = None;
        let mut decoy = "www.cloudflare.com".to_string();
        let mut count = 5usize;
        let mut selftest = false;
        let mut bulk = None;
        let mut tun = false;
        let mut tun_name = "Anarac-PRISM".to_string();
        let mut tun_cidr = "172.19.0.2/30".to_string();
        let mut mtu = 1280usize;
        let mut perf = false;

        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            match flag.as_str() {
                "--server" => server = Some(next(&mut it, "--server")?.parse().context("bad --server")?),
                "--shadow-pk" => shadow_pk = Some(next(&mut it, "--shadow-pk")?),
                "--decoy" => decoy = next(&mut it, "--decoy")?,
                "--count" => count = next(&mut it, "--count")?.parse().context("bad --count")?,
                "--bulk" => bulk = Some(next(&mut it, "--bulk")?.parse().context("bad --bulk")?),
                "--tun" => tun = true,
                "--tun-name" => tun_name = next(&mut it, "--tun-name")?,
                "--tun-cidr" => tun_cidr = next(&mut it, "--tun-cidr")?,
                "--mtu" => mtu = next(&mut it, "--mtu")?.parse().context("bad --mtu")?,
                "--perf" => perf = true,
                "--selftest" => selftest = true,
                "-h" | "--help" => {
                    println!(
                        "prism-client --server HOST:PORT --shadow-pk HEX \
                         [--decoy www.cloudflare.com] [--count N] [--bulk SECONDS]\n\
                         prism-client --tun --server HOST:PORT --shadow-pk HEX \
                         [--tun-name Anarac-PRISM] [--tun-cidr 172.19.0.2/30] [--mtu 1280] [--perf]\n\
                         prism-client --selftest [--count N]\n\
                         --perf (or PRISM_PERF=1): throughput mode — BBR2 congestion control,\n\
                         morph size-padding disabled (reduces stealth; set on the server too)"
                    );
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown argument: {other}"),
            }
        }
        Ok(Self {
            server,
            shadow_pk,
            decoy,
            count,
            selftest,
            bulk,
            tun,
            tun_name,
            tun_cidr,
            mtu,
            perf,
        })
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn next(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    it.next().with_context(|| format!("{flag} requires a value"))
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(s.len() % 2 == 0, "hex string has odd length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("invalid hex"))
        .collect()
}
