//! Server-side Reality shadow-key detection (§3.2).
//!
//! Runs *before* the QUIC backend starts a standard TLS handshake: parse the
//! ClientHello, recompute the shadow shared secret, and constant-time compare
//! the GREASE auth tag. On any mismatch the server returns [`AuthDecision::ProxyToDecoy`]
//! so that probes see an indistinguishable, genuine decoy response.

use prism_core::crypto::{ct_eq, hmac_sha256, X25519Public, X25519Secret};

use crate::client_hello::grease_auth_core;
use crate::error::AuthError;
use crate::parse::{parse_client_hello, ClientHelloView};

/// Outcome of classifying an inbound handshake.
#[derive(Debug)]
pub enum AuthDecision {
    /// Authenticated PRISM client. Carries the verified ephemeral public key and
    /// whether the client signaled perf mode in GREASE `0x0A0A`.
    Accept {
        client_eph_pk: X25519Public,
        client_perf: bool,
    },
    /// Not ours (probe, replay, or genuine browser): proxy to the decoy origin.
    ProxyToDecoy,
}

/// Holds the long-lived server shadow secret and the decoy SNI used as HMAC data.
pub struct ShadowDetector {
    shadow_sk: X25519Secret,
    decoy_sni: String,
}

impl ShadowDetector {
    pub fn new(shadow_sk: X25519Secret, decoy_sni: impl Into<String>) -> Self {
        Self { shadow_sk, decoy_sni: decoy_sni.into() }
    }

    /// Classify a reassembled, decrypted TLS ClientHello.
    ///
    /// Any parse failure or tag mismatch resolves to `ProxyToDecoy`: there is no
    /// distinguishable rejection path (§3.3).
    pub fn classify(&self, handshake: &[u8]) -> AuthDecision {
        match parse_client_hello(handshake) {
            Ok(view) => self.classify_view(&view),
            Err(_) => AuthDecision::ProxyToDecoy,
        }
    }

    /// Classify an already-parsed view (used by the QUIC backend which parses
    /// the ClientHello itself).
    pub fn classify_view(&self, view: &ClientHelloView) -> AuthDecision {
        let (Some(eph_bytes), Some(tag)) = (view.x25519_keyshare(), view.grease_auth()) else {
            return AuthDecision::ProxyToDecoy;
        };

        let Some(tag_core) = grease_auth_core(tag) else {
            return AuthDecision::ProxyToDecoy;
        };

        let eph_pk = X25519Public(eph_bytes);
        let shared = self.shadow_sk.diffie_hellman(&eph_pk);
        let expected = hmac_sha256(shared.as_bytes(), self.decoy_sni.as_bytes());

        // Constant-time comparison on the 32-byte HMAC; optional trailing perf
        // capability byte does not affect authentication.
        if ct_eq(&expected, tag_core) {
            AuthDecision::Accept {
                client_eph_pk: eph_pk,
                client_perf: view.client_perf,
            }
        } else {
            AuthDecision::ProxyToDecoy
        }
    }

    /// Recompute the auth tag this server expects for `eph_pk` (test/diagnostic).
    pub fn expected_tag(&self, eph_pk: &X25519Public) -> [u8; 32] {
        let shared = self.shadow_sk.diffie_hellman(eph_pk);
        hmac_sha256(shared.as_bytes(), self.decoy_sni.as_bytes())
    }
}

/// Try to parse and classify a raw handshake, surfacing parse errors for logging.
pub fn try_classify(detector: &ShadowDetector, handshake: &[u8]) -> Result<AuthDecision, AuthError> {
    let view = parse_client_hello(handshake)?;
    Ok(detector.classify_view(&view))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_hello::RealityClientHello;

    #[test]
    fn valid_client_is_accepted() {
        let shadow_sk = X25519Secret::generate();
        let shadow_pk = shadow_sk.public();
        let detector = ShadowDetector::new(shadow_sk, "www.cloudflare.com");

        let ch = RealityClientHello::build(&shadow_pk, "www.cloudflare.com");
        let view = ClientHelloView {
            random: [0u8; 32],
            x25519_key_share: Some(ch.key_share_pub),
            auth_tag: Some(ch.auth_tag.to_vec()),
            client_perf: false,
        };
        assert!(matches!(
            detector.classify_view(&view),
            AuthDecision::Accept {
                client_perf: false,
                ..
            }
        ));
    }

    #[test]
    fn valid_client_with_perf_cap_is_accepted() {
        let shadow_sk = X25519Secret::generate();
        let shadow_pk = shadow_sk.public();
        let detector = ShadowDetector::new(shadow_sk, "www.cloudflare.com");

        let ch = RealityClientHello::build(&shadow_pk, "www.cloudflare.com");
        let mut wire = ch.auth_tag.to_vec();
        wire.push(crate::client_hello::GREASE_PERF_CAP);
        let view = ClientHelloView {
            random: [0u8; 32],
            x25519_key_share: Some(ch.key_share_pub),
            auth_tag: Some(wire),
            client_perf: true,
        };
        assert!(matches!(
            detector.classify_view(&view),
            AuthDecision::Accept {
                client_perf: true,
                ..
            }
        ));
    }

    #[test]
    fn wrong_sni_is_proxied() {
        let shadow_sk = X25519Secret::generate();
        let shadow_pk = shadow_sk.public();
        let detector = ShadowDetector::new(shadow_sk, "www.cloudflare.com");

        // Client computed its tag against a different SNI.
        let ch = RealityClientHello::build(&shadow_pk, "evil.example");
        let view = ClientHelloView {
            random: [0u8; 32],
            x25519_key_share: Some(ch.key_share_pub),
            auth_tag: Some(ch.auth_tag.to_vec()),
            client_perf: false,
        };
        assert!(matches!(detector.classify_view(&view), AuthDecision::ProxyToDecoy));
    }

    #[test]
    fn replayed_clienthello_without_tag_is_proxied() {
        let shadow_sk = X25519Secret::generate();
        let detector = ShadowDetector::new(shadow_sk, "www.cloudflare.com");
        let view = ClientHelloView {
            random: [1u8; 32],
            x25519_key_share: Some([7u8; 32]),
            auth_tag: None,
            client_perf: false,
        };
        assert!(matches!(detector.classify_view(&view), AuthDecision::ProxyToDecoy));
    }
}
