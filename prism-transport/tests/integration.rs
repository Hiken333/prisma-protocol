//! Integration tests for PrismSession, TransportBackend and reliability paths.

use std::time::Duration;

use bytes::Bytes;
use prism_core::config::FecMode;
use prism_core::crypto::X25519Secret;
use prism_morph::CdnProfile;
use prism_transport::{
    backend::TransportBackend, ConnectionState, PrismSession, Server, ServerConfig, Side,
};

#[tokio::test]
async fn prism_session_echo_over_udp() {
    let shadow_sk = X25519Secret::generate();
    let shadow_pk = shadow_sk.public();
    let decoy = "www.cloudflare.com";

    let mut srv = Server::bind(ServerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        shadow_sk,
        decoy,
    ))
    .await
    .unwrap();
    let server_addr = srv.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        for _ in 0..6 {
            srv.serve_once().await.unwrap();
        }
    });

    let session = PrismSession::connect(
        server_addr,
        shadow_pk,
        decoy,
        CdnProfile::synthetic_chrome(),
        0.0,
        1400,
        true,
    )
    .await
    .unwrap();

    session
        .send_on_stream(8, true, Bytes::from_static(b"prism-session-api"))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(400)).await;

    let mut buf = [0u8; 256];
    let (n, fin) = session.read_stream(8, &mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"prism-session-api");
    assert!(fin);

    drop(session);
    server_task.await.unwrap();
}

#[tokio::test]
async fn transport_backend_stream_round_trip() {
    let server_sk = X25519Secret::generate();
    let client_sk = X25519Secret::generate();
    let c_shared = client_sk.diffie_hellman(&server_sk.public());
    let s_shared = server_sk.diffie_hellman(&client_sk.public());
    let ck = prism_transport::crypto::SessionKeys::derive(&c_shared, true).unwrap();
    let sk = prism_transport::crypto::SessionKeys::derive(&s_shared, false).unwrap();
    let prof = CdnProfile::synthetic_chrome();

    let mut client = ConnectionState::with_options(
        ck,
        Side::Client,
        prof.clone(),
        0.0,
        1400,
        true,
        FecMode::Auto,
    )
    .unwrap();
    let mut server = ConnectionState::with_options(
        sk,
        Side::Server,
        prof,
        0.0,
        1400,
        true,
        FecMode::Auto,
    )
    .unwrap();

    let payload = b"transport-backend";
    client.stream_send(4, payload, true).unwrap();
    let dgram = client.build_datagram().unwrap().expect("data datagram");
    server.open_datagram(&dgram).await.unwrap();

    let mut out = [0u8; 64];
    let (n, fin) = server.stream_recv(4, &mut out).unwrap();
    assert_eq!(&out[..n], payload);
    assert!(fin);
}
