//! Client-side Reality ClientHello construction.
//!
//! The wire-visible TLS handshake is produced by the PRISM quiche + BoringSSL
//! fork (so the fingerprint stays a real BoringSSL ClientHello). PRISM:
//!
//! 1. generates a per-handshake X25519 ephemeral here and injects its private
//!    scalar into BoringSSL via `Connection::set_prism_x25519_offer_seed`, so
//!    the on-wire `key_share` public is exactly [`RealityClientHello::key_share_pub`];
//! 2. computes `client_share = X25519(ephemeral, shadow_pk)` and binds it to the
//!    decoy SNI as `auth_tag = HMAC-SHA256(client_share, decoy_sni)`, which the
//!    server reproduces with its shadow private key against the wire `key_share`;
//! 3. carries `auth_tag` in GREASE extension `0x0A0A`, with an optional trailing
//!    capability byte (`0x01` = perf / full-speed morph) when the client enables
//!    `PRISM_PERF` / `--perf`.
//!
//! This module is pure logic (no native dependency): it produces the seed to
//! inject and the tag to carry. The actual quiche wiring lives in `prism-quic` /
//! `prism-client`, which depend on the fork.

use prism_core::crypto::{hmac_sha256, X25519Public, X25519Secret};

/// GREASE extension codepoint carrying the auth tag (spec §3.2).
pub const GREASE_AUTH_EXT: u16 = 0x0A0A;

/// HMAC auth tag length inside GREASE `0x0A0A`.
pub const AUTH_TAG_LEN: usize = 32;

/// Trailing capability byte: client requests perf mode (server may mirror fast morph).
pub const GREASE_PERF_CAP: u8 = 0x01;

/// Wire length when perf is signaled (32-byte tag + capability byte).
pub const GREASE_WIRE_LEN_PERF: usize = AUTH_TAG_LEN + 1;

/// The supported-groups ordering Chrome 124 advertises (X25519 first).
pub const CHROME_GROUPS: &str = "X25519:P-256:P-384";

/// Per-handshake ephemeral plus the precomputed Reality values.
pub struct RealityClientHello {
    pub ephemeral: X25519Secret,
    /// Public bytes that BoringSSL will place into the X25519 `key_share` entry
    /// (after the fork injects [`offer_seed`](Self::offer_seed)).
    pub key_share_pub: [u8; 32],
    /// `HMAC-SHA256(client_share, decoy_sni)` — the GREASE 0x0A0A value.
    pub auth_tag: [u8; 32],
}

impl RealityClientHello {
    /// Build the Reality values for a connection to `decoy_sni` using the
    /// subscription `shadow_pk`.
    ///
    /// `client_share = X25519(ephemeral, shadow_pk)` is the shared secret the
    /// server reproduces with its shadow private key; the ephemeral *public*
    /// key is what goes on the wire in `key_share`.
    pub fn build(shadow_pk: &X25519Public, decoy_sni: &str) -> Self {
        let ephemeral = X25519Secret::generate();
        let key_share_pub = ephemeral.public().0;
        let client_share = ephemeral.diffie_hellman(shadow_pk);
        let auth_tag = hmac_sha256(client_share.as_bytes(), decoy_sni.as_bytes());
        Self { ephemeral, key_share_pub, auth_tag }
    }

    /// Raw 32-byte ephemeral private scalar to feed to
    /// `Connection::set_prism_x25519_offer_seed`. BoringSSL derives the matching
    /// public (RFC 7748), which equals [`key_share_pub`](Self::key_share_pub).
    pub fn offer_seed(&self) -> [u8; 32] {
        self.ephemeral.to_seed_bytes()
    }

    /// The GREASE `0x0A0A` extension value to attach to the ClientHello.
    pub fn grease_ext_value(&self) -> &[u8; 32] {
        &self.auth_tag
    }

    /// GREASE `0x0A0A` wire bytes: auth tag, plus optional perf capability byte.
    pub fn grease_ext_wire<'a>(
        &self,
        perf: bool,
        out: &'a mut [u8; GREASE_WIRE_LEN_PERF],
    ) -> &'a [u8] {
        out[..AUTH_TAG_LEN].copy_from_slice(&self.auth_tag);
        if perf {
            out[AUTH_TAG_LEN] = GREASE_PERF_CAP;
            &out[..GREASE_WIRE_LEN_PERF]
        } else {
            &out[..AUTH_TAG_LEN]
        }
    }
}

/// First `AUTH_TAG_LEN` bytes of a GREASE `0x0A0A` body (the HMAC tag).
pub fn grease_auth_core(wire: &[u8]) -> Option<&[u8]> {
    if wire.len() >= AUTH_TAG_LEN {
        Some(&wire[..AUTH_TAG_LEN])
    } else {
        None
    }
}

/// Whether the GREASE `0x0A0A` body signals client perf mode.
pub fn grease_perf_from_wire(wire: &[u8]) -> bool {
    wire.len() == GREASE_WIRE_LEN_PERF && wire[AUTH_TAG_LEN] == GREASE_PERF_CAP
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_wire_encodes_perf_cap() {
        let shadow_sk = X25519Secret::generate();
        let ch = RealityClientHello::build(&shadow_sk.public(), "cdn.example");
        let mut buf = [0u8; GREASE_WIRE_LEN_PERF];
        assert_eq!(ch.grease_ext_wire(false, &mut buf).len(), AUTH_TAG_LEN);
        assert!(!grease_perf_from_wire(ch.grease_ext_wire(false, &mut buf)));
        let wire = ch.grease_ext_wire(true, &mut buf);
        assert_eq!(wire.len(), GREASE_WIRE_LEN_PERF);
        assert_eq!(wire[AUTH_TAG_LEN], GREASE_PERF_CAP);
        assert!(grease_perf_from_wire(wire));
        assert_eq!(grease_auth_core(wire), Some(ch.auth_tag.as_slice()));
    }

    #[test]
    fn build_is_reproducible_on_server_side() {
        // Server holds shadow_sk; client embeds ephemeral pub + tag derived from
        // X25519(ephemeral, shadow_pk). The server recomputes the same secret
        // with X25519(shadow_sk, ephemeral_pub).
        let shadow_sk = X25519Secret::generate();
        let shadow_pk = shadow_sk.public();

        let ch = RealityClientHello::build(&shadow_pk, "www.cloudflare.com");
        let eph_pub = X25519Public(ch.key_share_pub);
        let server_shared = shadow_sk.diffie_hellman(&eph_pub);
        let expected = hmac_sha256(server_shared.as_bytes(), b"www.cloudflare.com");
        assert_eq!(expected, ch.auth_tag);
    }
}
