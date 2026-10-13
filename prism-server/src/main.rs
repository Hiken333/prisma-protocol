//! PRISM server binary — native UDP transport.
//!
//! Listens on UDP, runs the Reality handshake on each client's INIT, and either
//! establishes a PRISM session (echoing VPN streams, the place where a real
//! deployment would write to a server-side TUN / forward upstream) or hands the
//! traffic to the decoy. No code path produces a distinguishable rejection.
//!
//! Usage:
//!   prism-server [--listen 0.0.0.0:4433] [--shadow-sk HEX] [--decoy www.cloudflare.com]
//!                [--decoy-origin HOST:PORT]
//!
//! If `--shadow-sk` is omitted, a fresh key is generated and its public half is
//! printed for use in the client's `--shadow-pk`.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use prism_core::crypto::X25519Secret;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse()?;

    let perf = args.perf || env_flag("PRISM_PERF");
    if perf {
        std::env::set_var("PRISM_PERF", "1");
        tracing::info!("PRISM_PERF on server process: client CC tuning only; downlink fast morph follows client handshake perf cap");
    }
    #[cfg(feature = "quiche-backend")]
    prism_quic::agent_debug::announce();

    let shadow_sk = match &args.shadow_sk {
        Some(hex) => X25519Secret::from_bytes(&decode_hex(hex)?)
            .context("invalid --shadow-sk")?,
        None => {
            let sk = X25519Secret::generate();
            tracing::warn!("no --shadow-sk given; generated an ephemeral shadow key for this run");
            sk
        }
    };

    let shadow_pk = shadow_sk.public();
    tracing::info!(
        shadow_pk = %encode_hex(shadow_pk.as_bytes()),
        "publish this shadow_pk in the client subscription (client --shadow-pk)"
    );

    serve(args, shadow_sk).await
}

/// Pure-Rust `prism-transport` server (default build).
#[cfg(not(feature = "quiche-backend"))]
async fn serve(args: Args, shadow_sk: X25519Secret) -> Result<()> {
    use prism_decoy::DecoyProxy;
    use prism_transport::{Server, ServerConfig};

    let mut cfg = ServerConfig::new(args.listen, shadow_sk, args.decoy.clone());
    if let Some(origin) = &args.decoy_origin {
        cfg.decoy = Some(DecoyProxy::resolve(origin).context("invalid --decoy-origin")?);
        tracing::info!(%origin, "decoy proxy enabled for rejected clients");
    }

    let server = Server::bind(cfg).await?;
    tracing::info!("server ready; press Ctrl+C to stop");
    server.run().await?;
    Ok(())
}

/// Native quiche + BoringSSL server (`--features quiche-backend`). Accepts one
/// PRISM connection at a time; non-PRISM handshakes are reported for decoy
/// relay. Requires `--cert` / `--key` PEM files for the TLS server identity.
#[cfg(feature = "quiche-backend")]
async fn serve(args: Args, shadow_sk: X25519Secret) -> Result<()> {
    let cert = args
        .cert
        .as_deref()
        .context("--cert is required with the quiche backend")?
        .to_owned();
    let key = args
        .key
        .as_deref()
        .context("--key is required with the quiche backend")?
        .to_owned();
    let seed = shadow_sk.to_seed_bytes();

    if args.tun {
        #[cfg(feature = "tunnel")]
        {
            return serve_tunnel(args, seed, &cert, &key).await;
        }
        #[cfg(not(feature = "tunnel"))]
        anyhow::bail!("--tun requires building with --features tunnel,quiche-backend");
    }

    use prism_quic::live::{run_server_once, Served};

    tracing::info!(listen = %args.listen, "quiche backend: server ready; press Ctrl+C to stop");
    loop {
        let sk = X25519Secret::from_bytes(&seed).expect("valid shadow seed");
        match run_server_once(args.listen, sk, &args.decoy, &cert, &key).await {
            Ok(Served::Prism { echoed }) => {
                tracing::info!(echoed, "PRISM client served; echoed mirror cells");
            }
            Ok(Served::Decoy { from, .. }) => {
                tracing::warn!(%from, "non-PRISM handshake; would relay to decoy origin");
            }
            Err(e) => {
                tracing::warn!(error = %e, "connection attempt failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

#[cfg(all(feature = "quiche-backend", feature = "tunnel"))]
async fn serve_tunnel(args: Args, seed: [u8; 32], cert: &str, key: &str) -> Result<()> {
    use prism_quic::tunnel::{run_server_tunnel, TunnelServed};
    use prism_tun::PlatformTun;

    let mut tun = PlatformTun::open(&args.tun_name, args.mtu, &args.tun_cidr)
        .await
        .context("open server TUN")?;

    let client_ip = client_tun_ip(&args.tun_cidr).context("derive client IP from --tun-cidr")?;

    tracing::info!(
        listen = %args.listen,
        tun = %args.tun_name,
        cidr = %args.tun_cidr,
        %client_ip,
        "quiche backend: TUN server ready; press Ctrl+C to stop"
    );

    loop {
        let sk = X25519Secret::from_bytes(&seed).expect("valid shadow seed");
        match run_server_tunnel(args.listen, sk, &args.decoy, cert, key, &mut tun, client_ip).await
        {
            Ok(TunnelServed::Prism) => {
                tracing::info!("PRISM tunnel session ended");
            }
            Ok(TunnelServed::Decoy { from, .. }) => {
                tracing::warn!(%from, "non-PRISM handshake; would relay to decoy origin");
            }
            Err(e) => {
                tracing::warn!(error = %e, "tunnel session failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// The client tunnel address: server address in `--tun-cidr` plus one
/// (e.g. 172.19.0.1/30 -> 172.19.0.2). Only TUN packets destined to it are
/// forwarded back through the tunnel.
#[cfg(all(feature = "quiche-backend", feature = "tunnel"))]
fn client_tun_ip(cidr: &str) -> Result<std::net::Ipv4Addr> {
    let ip_str = cidr.split('/').next().unwrap_or(cidr);
    let ip: std::net::Ipv4Addr = ip_str.parse().context("invalid --tun-cidr address")?;
    let mut o = ip.octets();
    o[3] = o[3].wrapping_add(1);
    Ok(std::net::Ipv4Addr::from(o))
}

struct Args {
    listen: SocketAddr,
    shadow_sk: Option<String>,
    decoy: String,
    #[cfg_attr(feature = "quiche-backend", allow(dead_code))]
    decoy_origin: Option<String>,
    #[cfg_attr(not(feature = "quiche-backend"), allow(dead_code))]
    cert: Option<String>,
    #[cfg_attr(not(feature = "quiche-backend"), allow(dead_code))]
    key: Option<String>,
    #[cfg_attr(not(feature = "tunnel"), allow(dead_code))]
    tun: bool,
    #[cfg_attr(not(feature = "tunnel"), allow(dead_code))]
    tun_name: String,
    #[cfg_attr(not(feature = "tunnel"), allow(dead_code))]
    tun_cidr: String,
    #[cfg_attr(not(feature = "tunnel"), allow(dead_code))]
    mtu: usize,
    perf: bool,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut listen: SocketAddr = "0.0.0.0:4433".parse().unwrap();
        let mut shadow_sk = None;
        let mut decoy = "www.cloudflare.com".to_string();
        let mut decoy_origin = None;
        let mut cert = None;
        let mut key = None;
        let mut tun = false;
        let mut tun_name = "prism0".to_string();
        let mut tun_cidr = "172.19.0.1/30".to_string();
        let mut mtu = 1280usize;
        let mut perf = false;

        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            match flag.as_str() {
                "--listen" => listen = next(&mut it, "--listen")?.parse().context("bad --listen")?,
                "--shadow-sk" => shadow_sk = Some(next(&mut it, "--shadow-sk")?),
                "--decoy" => decoy = next(&mut it, "--decoy")?,
                "--decoy-origin" => decoy_origin = Some(next(&mut it, "--decoy-origin")?),
                "--cert" => cert = Some(next(&mut it, "--cert")?),
                "--key" => key = Some(next(&mut it, "--key")?),
                "--tun" => tun = true,
                "--tun-name" => tun_name = next(&mut it, "--tun-name")?,
                "--tun-cidr" => tun_cidr = next(&mut it, "--tun-cidr")?,
                "--mtu" => mtu = next(&mut it, "--mtu")?.parse().context("bad --mtu")?,
                "--perf" => perf = true,
                "-h" | "--help" => {
                    println!(
                        "prism-server [--listen 0.0.0.0:4433] [--shadow-sk HEX] \
                         [--decoy www.cloudflare.com] [--decoy-origin HOST:PORT] \
                         [--cert cert.pem --key key.pem] [--tun] \
                         [--tun-name prism0] [--tun-cidr 172.19.0.1/30] [--mtu 1280] [--perf]\n\
                         --perf (or PRISM_PERF=1): throughput mode — BBR2 congestion control,\n\
                         morph size-padding disabled (reduces stealth; enable on clients too)"
                    );
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown argument: {other}"),
            }
        }
        Ok(Self {
            listen,
            shadow_sk,
            decoy,
            decoy_origin,
            cert,
            key,
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

fn encode_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
