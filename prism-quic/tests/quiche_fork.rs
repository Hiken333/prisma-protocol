//! Integration tests for the PRISM quiche + BoringSSL fork.
//!
//! Run with the native backend and point at a cert/key (the vendored quiche
//! ships test certs):
//!
//! ```text
//! $env:PRISM_TEST_CERT = "third_party/quiche/quiche/examples/cert.crt"
//! $env:PRISM_TEST_KEY  = "third_party/quiche/quiche/examples/cert.key"
//! cargo test -p prism-quic --features quiche-backend --test quiche_fork
//! ```
//!
//! These exercise the three fork capabilities end-to-end against a real
//! BoringSSL build: the TLS exporter, the X25519 key_share ephemeral injection
//! (which also proves dalek and BoringSSL agree on X25519), and that a full
//! handshake still completes with an injected ephemeral.
#![cfg(feature = "quiche-backend")]

use std::net::SocketAddr;

use prism_auth::client_hello::RealityClientHello;
use prism_auth::server::{AuthDecision, ShadowDetector};
use prism_core::crypto::{X25519Public, X25519Secret};
use prism_quic::quiche;

// Exported by the vendored BoringSSL (OPENSSL_EXPORT). Linked statically into
// this test binary via quiche, so we can compare its X25519 base-point multiply
// against x25519-dalek for the same raw scalar.
extern "C" {
    fn X25519_public_from_private(out_public: *mut u8, private_key: *const u8);
}

fn boringssl_public(seed: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { X25519_public_from_private(out.as_mut_ptr(), seed.as_ptr()) };
    out
}

#[test]
fn dalek_and_boringssl_agree_on_x25519_public() {
    // The Reality auth tag is computed in Rust (dalek) but the on-wire key_share
    // is produced by BoringSSL from the injected seed. They must derive the same
    // public value (both apply RFC 7748 clamping) or the server's tag check
    // would never match.
    for i in 0..16u8 {
        let secret = X25519Secret::generate();
        let seed = secret.to_seed_bytes();
        let dalek_pub = *secret.public().as_bytes();
        let bssl_pub = boringssl_public(&seed);
        assert_eq!(dalek_pub, bssl_pub, "mismatch on iteration {i}");
    }
}

fn test_cert_paths() -> Option<(String, String)> {
    let cert = std::env::var("PRISM_TEST_CERT").ok()?;
    let key = std::env::var("PRISM_TEST_KEY").ok()?;
    if std::path::Path::new(&cert).exists() && std::path::Path::new(&key).exists() {
        Some((cert, key))
    } else {
        None
    }
}

fn client_config() -> quiche::Config {
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

fn server_config(cert: &str, key: &str) -> quiche::Config {
    let mut c = client_config();
    c.load_cert_chain_from_pem_file(cert).unwrap();
    c.load_priv_key_from_pem_file(key).unwrap();
    c
}

/// Drive both connections to completion by shuttling datagrams between them.
fn complete_handshake(client: &mut quiche::Connection, server: &mut quiche::Connection) {
    let c_addr: SocketAddr = "127.0.0.1:44400".parse().unwrap();
    let s_addr: SocketAddr = "127.0.0.1:44443".parse().unwrap();
    let mut buf = [0u8; 1500];

    for _ in 0..40 {
        // Client -> server.
        loop {
            match client.send(&mut buf) {
                Ok((len, _)) => {
                    let info = quiche::RecvInfo {
                        from: c_addr,
                        to: s_addr,
                    };
                    server.recv(&mut buf[..len], info).unwrap();
                }
                Err(quiche::Error::Done) => break,
                Err(e) => panic!("client.send: {e:?}"),
            }
        }
        // Server -> client.
        loop {
            match server.send(&mut buf) {
                Ok((len, _)) => {
                    let info = quiche::RecvInfo {
                        from: s_addr,
                        to: c_addr,
                    };
                    client.recv(&mut buf[..len], info).unwrap();
                }
                Err(quiche::Error::Done) => break,
                Err(e) => panic!("server.send: {e:?}"),
            }
        }
        if client.is_established() && server.is_established() {
            return;
        }
    }
    panic!("handshake did not complete");
}

#[test]
fn exporter_matches_on_both_ends_and_seed_injection_works() {
    let Some((cert, key)) = test_cert_paths() else {
        eprintln!("skipping: set PRISM_TEST_CERT / PRISM_TEST_KEY to run");
        return;
    };

    let c_addr: SocketAddr = "127.0.0.1:44400".parse().unwrap();
    let s_addr: SocketAddr = "127.0.0.1:44443".parse().unwrap();

    let mut cc = client_config();
    let mut sc = server_config(&cert, &key);

    let scid = quiche::ConnectionId::from_ref(&[0xab; 16]);
    let dcid = quiche::ConnectionId::from_ref(&[0xcd; 16]);

    let mut client =
        quiche::connect(Some("www.example.com"), &scid, c_addr, s_addr, &mut cc).unwrap();
    let mut server = quiche::accept(&dcid, None, s_addr, c_addr, &mut sc).unwrap();

    // Inject the PRISM client ephemeral and Reality auth tag (GREASE 0x0A0A)
    // before the ClientHello is produced. The handshake must still complete.
    let ephemeral = X25519Secret::generate();
    client.set_prism_x25519_offer_seed(&ephemeral.to_seed_bytes());
    client.set_prism_auth_tag(&[0x5au8; 32]);

    complete_handshake(&mut client, &mut server);

    // The TLS exporter must yield identical material on both peers — this is the
    // PRISM master secret used to seed morphing / congestion control.
    let mut c_out = [0u8; 48];
    let mut s_out = [0u8; 48];
    client
        .export_keying_material(&mut c_out, b"prism/master", b"")
        .unwrap();
    server
        .export_keying_material(&mut s_out, b"prism/master", b"")
        .unwrap();
    assert_eq!(c_out, s_out, "exporter material diverged");
    assert_ne!(c_out, [0u8; 48], "exporter returned all-zero material");

    // A different label must produce different material.
    let mut other = [0u8; 48];
    client
        .export_keying_material(&mut other, b"prism/other", b"")
        .unwrap();
    assert_ne!(c_out, other);
}

/// Full server-side Reality path against a real quiche-produced Initial:
/// inject the ephemeral + auth tag on the client, capture its first datagram,
/// decrypt + reassemble the ClientHello with the fork helper, and classify it
/// with the shadow detector. A matching SNI is accepted; a wrong one is proxied.
#[test]
fn server_classifies_real_initial_clienthello() {
    let decoy_sni = "www.cloudflare.com";
    let shadow_sk = X25519Secret::generate();
    let shadow_pk = shadow_sk.public();

    // Client side: derive the Reality values and wire them into quiche.
    let ch = RealityClientHello::build(&shadow_pk, decoy_sni);

    let c_addr: SocketAddr = "127.0.0.1:44400".parse().unwrap();
    let s_addr: SocketAddr = "127.0.0.1:44443".parse().unwrap();
    let mut cc = client_config();
    let scid = quiche::ConnectionId::from_ref(&[0x11; 16]);
    let mut client = quiche::connect(Some(decoy_sni), &scid, c_addr, s_addr, &mut cc).unwrap();
    client.set_prism_x25519_offer_seed(&ch.offer_seed());
    client.set_prism_auth_tag(ch.grease_ext_value());

    // Capture the client's first datagram (the Initial carrying the ClientHello).
    let mut buf = [0u8; 1500];
    let (len, _) = client.send(&mut buf).unwrap();

    // Server side: peek the ClientHello straight off the wire.
    let hello = quiche::prism_peek_client_hello(&buf[..len])
        .expect("should decrypt+reassemble the Initial ClientHello");

    // The injected key_share public must equal the dalek ephemeral public.
    let view = prism_auth::parse::parse_client_hello(&hello).unwrap();
    assert_eq!(
        view.x25519_keyshare(),
        Some(ch.key_share_pub),
        "on-wire key_share must match the injected ephemeral public"
    );
    assert_eq!(
        view.grease_auth(),
        Some(ch.auth_tag.as_slice()),
        "GREASE 0x0A0A must carry the auth tag"
    );

    // Correct shadow secret + SNI => accept, and the recovered ephemeral matches.
    let detector = ShadowDetector::new(
        X25519Secret::from_bytes(&shadow_sk.to_seed_bytes()).unwrap(),
        decoy_sni,
    );
    match detector.classify(&hello) {
        AuthDecision::Accept { client_eph_pk, .. } => {
            assert_eq!(client_eph_pk, X25519Public(ch.key_share_pub));
        }
        AuthDecision::ProxyToDecoy => panic!("valid PRISM client was proxied"),
    }

    // A detector bound to a different decoy SNI must fall through to the decoy.
    let wrong = ShadowDetector::new(
        X25519Secret::from_bytes(&shadow_sk.to_seed_bytes()).unwrap(),
        "not-the-decoy.example",
    );
    assert!(matches!(wrong.classify(&hello), AuthDecision::ProxyToDecoy));
}
