//! Offline crypto primitives used by PRISM.
//!
//! These primitives are deliberately *not* on the wire-visible TLS path (that is
//! handled by BoringSSL inside the QUIC backend). They cover the Reality
//! shadow-key Diffie-Hellman, the HKDF key schedule for PRISM-specific secrets,
//! and the GREASE-extension HMAC tag.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{CoreError, Result};

/// X25519 public key (32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519Public(pub [u8; 32]);

impl X25519Public {
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = b
            .try_into()
            .map_err(|_| CoreError::InvalidKeyLength { expected: 32, got: b.len() })?;
        Ok(Self(arr))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// X25519 secret key. Used for both the long-lived server shadow secret and the
/// per-handshake client ephemeral.
pub struct X25519Secret(StaticSecret);

impl X25519Secret {
    /// Generate a fresh random secret (client ephemeral or server shadow key).
    pub fn generate() -> Self {
        Self(StaticSecret::random_from_rng(rand::rngs::OsRng))
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = b
            .try_into()
            .map_err(|_| CoreError::InvalidKeyLength { expected: 32, got: b.len() })?;
        Ok(Self(StaticSecret::from(arr)))
    }

    pub fn public(&self) -> X25519Public {
        X25519Public(PublicKey::from(&self.0).to_bytes())
    }

    /// Raw 32-byte private scalar (pre-clamping), as stored. Used to inject the
    /// PRISM client ephemeral into BoringSSL's `key_share` (the fork applies the
    /// standard RFC 7748 clamping, so this yields the same public key as
    /// [`public`](Self::public)). Handle as secret key material.
    pub fn to_seed_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Raw X25519 Diffie-Hellman: `DH(self, peer) -> shared secret`.
    pub fn diffie_hellman(&self, peer: &X25519Public) -> SharedSecret {
        let shared = self.0.diffie_hellman(&PublicKey::from(peer.0));
        SharedSecret(shared.to_bytes())
    }
}

/// Result of an X25519 exchange. Treated as opaque key material.
#[derive(Clone)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        // Best-effort zeroization of derived shared material.
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

/// HMAC-SHA256 over `data` with `key`. Used for the GREASE auth tag.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Constant-time comparison of two byte slices of equal length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// TLS 1.3 `HKDF-Expand-Label` (RFC 8446 §7.1), used to derive PRISM secrets
/// from the TLS exporter. The `label` is automatically prefixed with `tls13 `.
pub fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let full_label = [b"tls13 ".as_slice(), label].concat();

    // struct HkdfLabel { uint16 length; opaque label<7..255>; opaque context<0..255>; }
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let hk = Hkdf::<Sha256>::from_prk(secret).map_err(|_| CoreError::HkdfExpand)?;
    let mut okm = vec![0u8; out_len];
    hk.expand(&info, &mut okm).map_err(|_| CoreError::HkdfExpand)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_is_symmetric() {
        let server = X25519Secret::generate();
        let client = X25519Secret::generate();
        let s1 = server.diffie_hellman(&client.public());
        let s2 = client.diffie_hellman(&server.public());
        assert_eq!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    fn hmac_is_deterministic() {
        let a = hmac_sha256(b"key", b"data");
        let b = hmac_sha256(b"key", b"data");
        assert!(ct_eq(&a, &b));
        let c = hmac_sha256(b"key2", b"data");
        assert!(!ct_eq(&a, &c));
    }

    #[test]
    fn expand_label_length() {
        let secret = [7u8; 32];
        let out = hkdf_expand_label(&secret, b"prism/test", b"", 48).unwrap();
        assert_eq!(out.len(), 48);
        // Determinism.
        let out2 = hkdf_expand_label(&secret, b"prism/test", b"", 48).unwrap();
        assert_eq!(out, out2);
    }
}
