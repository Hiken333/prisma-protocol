//! End-to-end PRISM data-plane test over the real quiche + BoringSSL fork.
//!
//! Establishes a quiche client<->server connection, derives the PRISM session
//! from the TLS exporter on both ends, then round-trips a VPN packet as a
//! Mirror Cell (a STREAM frame body) inside morph-padded datagrams produced by
//! the fork's `set_prism_min_send_size`. This is the whole PRISM stack short of
//! the OS sockets / TUN device.
//!
//! ```text
//! $env:PRISM_TEST_CERT = "third_party/quiche/quiche/examples/cert.crt"
//! $env:PRISM_TEST_KEY  = "third_party/quiche/quiche/examples/cert.key"
//! cargo test -p prism-quic --features quiche-backend --test quiche_live
//! ```
#![cfg(feature = "quiche-backend")]

use std::net::SocketAddr;

use prism_core::crypto::X25519Secret;
use prism_morph::CdnProfile;
use prism_quic::backend::QuicBackend;
use prism_quic::datagram::fill_datagram;
use prism_quic::quiche;
use prism_quic::quiche_backend::QuicheBackend;
use prism_quic::{MccDecoder, MccEncoder, PrismSession};

const C_ADDR: &str = "127.0.0.1:48400";
const S_ADDR: &str = "127.0.0.1:48443";

fn test_cert_paths() -> Option<(String, String)> {
    let cert = std::env::var("PRISM_TEST_CERT").ok()?;
    let key = std::env::var("PRISM_TEST_KEY").ok()?;
    (std::path::Path::new(&cert).exists() && std::path::Path::new(&key).exists())
        .then_some((cert, key))
}

fn base_config() -> quiche::Config {
    let mut c = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    c.set_application_protos(&[b"prism"]).unwrap();
    c.verify_peer(false);
    c.set_max_idle_timeout(5_000);
    c.set_initial_max_data(1_000_000);
    c.set_initial_max_stream_data_bidi_local(100_000);
    c.set_initial_max_stream_data_bidi_remote(100_000);
    c.set_initial_max_streams_bidi(16);
    c.set_max_recv_udp_payload_size(1350);
    c.set_max_send_udp_payload_size(1350);
    c
}

/// Drain everything `from` wants to send and feed it into `to`.
fn pump(from: &mut QuicheBackend, to: &mut QuicheBackend) {
    let mut buf = [0u8; 1500];
    loop {
        match from.send(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let _ = to.recv(&mut buf[..n]);
            }
            Err(_) => break,
        }
    }
}

#[test]
fn prism_vpn_packet_round_trips_over_quiche_fork() {
    let Some((cert, key)) = test_cert_paths() else {
        eprintln!("skipping: set PRISM_TEST_CERT / PRISM_TEST_KEY to run");
        return;
    };

    let c_addr: SocketAddr = C_ADDR.parse().unwrap();
    let s_addr: SocketAddr = S_ADDR.parse().unwrap();

    let mut cc = base_config();
    let mut sc = base_config();
    sc.load_cert_chain_from_pem_file(&cert).unwrap();
    sc.load_priv_key_from_pem_file(&key).unwrap();

    let scid = quiche::ConnectionId::from_ref(&[0x21; 16]);
    let dcid = quiche::ConnectionId::from_ref(&[0x43; 16]);

    let mut client_conn =
        quiche::connect(Some("www.example.com"), &scid, c_addr, s_addr, &mut cc).unwrap();
    let server_conn = quiche::accept(&dcid, None, s_addr, c_addr, &mut sc).unwrap();

    // PRISM client injects the Reality ephemeral before the ClientHello.
    let ephemeral = X25519Secret::generate();
    client_conn.set_prism_x25519_offer_seed(&ephemeral.to_seed_bytes());

    let mut client = QuicheBackend::from_connection(client_conn, c_addr, s_addr);
    let mut server = QuicheBackend::from_connection(server_conn, s_addr, c_addr);

    // Complete the handshake.
    let mut established = false;
    for _ in 0..40 {
        pump(&mut client, &mut server);
        pump(&mut server, &mut client);
        if client.is_established() && server.is_established() {
            established = true;
            break;
        }
    }
    assert!(established, "handshake did not complete");

    // Derive the PRISM session (morph engines + congestion gate) from the
    // exporter on both ends.
    let mut client_sess =
        PrismSession::derive(&mut client, CdnProfile::synthetic_chrome(), 0.10, 1350).unwrap();
    let _server_sess =
        PrismSession::derive(&mut server, CdnProfile::synthetic_chrome(), 0.10, 1350).unwrap();

    // Client sends a VPN packet as a Mirror Cell on stream 4, inside a
    // morph-padded datagram.
    let ip_packet = b"\x45\x00\x00\x3c PRISM mirror-cell VPN payload over quiche+BoringSSL";
    {
        let mut enc = MccEncoder::new(&mut client);
        let n = enc.write_ip_packet(4, ip_packet).unwrap();
        assert_eq!(n, ip_packet.len());
    }

    let mut out = vec![0u8; 1500];
    let mut sent_any = false;
    loop {
        let n = fill_datagram(&mut client, &mut client_sess.morph_up, &mut out).unwrap();
        if n == 0 {
            break;
        }
        sent_any = true;
        // Morph padding must have grown the datagram toward the CDN target.
        assert!(n >= ip_packet.len());
        let _ = server.recv(&mut out[..n]);
    }
    assert!(sent_any, "client produced no data datagram");

    // Server reads the mirror cell back into the VPN packet.
    let mut scratch = vec![0u8; 4096];
    let mut got = Vec::new();
    {
        let mut dec = MccDecoder::new(&mut server);
        dec.drain(&mut scratch, |sid, bytes, _fin| {
            assert_eq!(sid, 4);
            got.extend_from_slice(bytes);
        })
        .unwrap();
    }

    assert_eq!(
        got, ip_packet,
        "VPN packet did not survive the MCC round trip"
    );

    // Flush server ACKs so the connection stays healthy, then close gracefully.
    pump(&mut server, &mut client);
    PrismSession::graceful_close(&mut client).unwrap();
    pump(&mut client, &mut server);
}
