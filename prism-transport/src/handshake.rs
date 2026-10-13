//! Reality-style handshake over the native UDP transport.
//!
//! The client's INIT datagram embeds its X25519 ephemeral public key and a
//! `HMAC(shared, decoy_sni)` auth tag — exactly the values `prism-auth` builds
//! for the BoringSSL ClientHello, but carried in a native datagram. The server
//! reproduces the shared secret with its shadow private key and constant-time
//! compares the tag.

use prism_auth::RealityClientHello;
use prism_core::crypto::{ct_eq, hmac_sha256, SharedSecret, X25519Public, X25519Secret};

use crate::error::{Result, TransportError};
use crate::wire::{MAGIC, TYPE_INIT, VERSION};

/// Layout: MAGIC(4) | VERSION(1) | TYPE(1) | eph_pub(32) | auth_tag(32).
const INIT_FIXED_LEN: usize = 4 + 1 + 1 + 32 + 32;

/// Client handshake state: keeps the shared secret so session keys can be
/// derived once the INIT is sent.
pub struct ClientHandshake {
    pub shared: SharedSecret,
    init_packet: Vec<u8>,
}

impl ClientHandshake {
    /// Build the INIT datagram for `shadow_pk` / `decoy_sni`, padded to `pad_to`
    /// bytes (morph target) with trailing zeros.
    pub fn new(shadow_pk: &X25519Public, decoy_sni: &str, pad_to: usize) -> Self {
        let ch = RealityClientHello::build(shadow_pk, decoy_sni);
        // Reproduce the shared secret the auth tag was computed from.
        // (RealityClientHello consumed the ephemeral internally, so recompute via
        // the same ephemeral public is not possible; instead derive shared here.)
        let shared = reproduce_shared(&ch, shadow_pk);

        let mut pkt = Vec::with_capacity(pad_to.max(INIT_FIXED_LEN));
        pkt.extend_from_slice(&MAGIC);
        pkt.push(VERSION);
        pkt.push(TYPE_INIT);
        pkt.extend_from_slice(&ch.key_share_pub);
        pkt.extend_from_slice(&ch.auth_tag);
        if pkt.len() < pad_to {
            pkt.resize(pad_to, 0);
        }
        Self { shared, init_packet: pkt }
    }

    pub fn init_packet(&self) -> &[u8] {
        &self.init_packet
    }
}

/// Recompute `X25519(ephemeral, shadow_pk)` for a freshly built ClientHello.
///
/// `RealityClientHello` keeps the ephemeral secret; we expose the shared secret
/// by re-deriving it from that secret and the shadow public key.
fn reproduce_shared(ch: &RealityClientHello, shadow_pk: &X25519Public) -> SharedSecret {
    ch.ephemeral.diffie_hellman(shadow_pk)
}

/// Parsed INIT as seen by the server.
pub struct InitView {
    pub eph_pub: X25519Public,
    pub auth_tag: [u8; 32],
}

/// Parse a client INIT datagram (validates magic/version/type and length).
pub fn parse_init(datagram: &[u8]) -> Result<InitView> {
    if datagram.len() < INIT_FIXED_LEN {
        return Err(TransportError::Malformed("INIT too short".into()));
    }
    if datagram[0..4] != MAGIC || datagram[4] != VERSION || datagram[5] != TYPE_INIT {
        return Err(TransportError::Malformed("bad INIT header".into()));
    }
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&datagram[6..38]);
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&datagram[38..70]);
    Ok(InitView { eph_pub: X25519Public(eph), auth_tag: tag })
}

/// Server decision after inspecting an INIT.
pub enum ServerAuth {
    /// Authenticated: carries the shared secret for key derivation.
    Accept { shared: SharedSecret },
    /// Not ours: proxy to decoy (or drop).
    Reject,
}

/// Verify a client INIT against the server's shadow key and decoy SNI.
///
/// Any mismatch yields `Reject` with no distinguishable difference (§3.3).
pub fn server_classify(
    shadow_sk: &X25519Secret,
    decoy_sni: &str,
    init: &InitView,
) -> ServerAuth {
    let shared = shadow_sk.diffie_hellman(&init.eph_pub);
    let expected = hmac_sha256(shared.as_bytes(), decoy_sni.as_bytes());
    if ct_eq(&expected, &init.auth_tag) {
        ServerAuth::Accept { shared }
    } else {
        ServerAuth::Reject
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_handshake_round_trip() {
        let shadow_sk = X25519Secret::generate();
        let shadow_pk = shadow_sk.public();
        let decoy = "www.cloudflare.com";

        let hs = ClientHandshake::new(&shadow_pk, decoy, 1200);
        assert_eq!(hs.init_packet().len(), 1200);

        let view = parse_init(hs.init_packet()).unwrap();
        match server_classify(&shadow_sk, decoy, &view) {
            ServerAuth::Accept { shared } => {
                // Server's shared must match the client's.
                assert_eq!(shared.as_bytes(), hs.shared.as_bytes());
            }
            ServerAuth::Reject => panic!("valid client rejected"),
        }
    }

    #[test]
    fn wrong_sni_rejected() {
        let shadow_sk = X25519Secret::generate();
        let shadow_pk = shadow_sk.public();
        let hs = ClientHandshake::new(&shadow_pk, "real.example", 1200);
        let view = parse_init(hs.init_packet()).unwrap();
        assert!(matches!(
            server_classify(&shadow_sk, "different.example", &view),
            ServerAuth::Reject
        ));
    }

    #[test]
    fn garbage_is_rejected_at_parse() {
        assert!(parse_init(b"not a prism init").is_err());
    }
}
