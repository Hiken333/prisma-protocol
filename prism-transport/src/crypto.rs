//! AEAD session keys and datagram protection.
//!
//! Both peers derive identical key material from the Reality shadow shared
//! secret (`shared = X25519(eph, shadow_pk) = X25519(shadow_sk, eph_pub)`), so
//! no extra key-exchange packets are needed. Each direction uses its own key to
//! keep nonce spaces disjoint.
//!
//! Note: this is the *native* PRISM transport. It is wire-compatible with itself,
//! not byte-identical to Chrome QUIC — that requires the `quiche-backend`
//! (BoringSSL) path. The AEAD here protects the VPN payload over real UDP.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use prism_core::crypto::{hkdf_expand_label, SharedSecret};
use prism_core::PrismExporter;

use crate::error::{Result, TransportError};

/// Direction of an AEAD key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// Client-to-server.
    C2s,
    /// Server-to-client.
    S2c,
}

impl Dir {
    fn nonce_salt(self) -> [u8; 4] {
        match self {
            Dir::C2s => *b"c2s\0",
            Dir::S2c => *b"s2c\0",
        }
    }
}

/// All key material derived from one handshake.
pub struct SessionKeys {
    seal: ChaCha20Poly1305,
    open: ChaCha20Poly1305,
    /// Salt for the directions we seal / open with.
    seal_salt: [u8; 4],
    open_salt: [u8; 4],
    /// The PRISM exporter, used to seed BBR and the morph engines.
    pub exporter: PrismExporter,
}

impl SessionKeys {
    /// Derive session keys from the shadow shared secret.
    ///
    /// `am_client` selects which directional key is used for sealing (the client
    /// seals C2S and opens S2C; the server is the mirror image).
    pub fn derive(shared: &SharedSecret, am_client: bool) -> Result<Self> {
        let key_c2s = hkdf_expand_label(shared.as_bytes(), b"prism/udp/key/c2s", b"", 32)?;
        let key_s2c = hkdf_expand_label(shared.as_bytes(), b"prism/udp/key/s2c", b"", 32)?;

        let aead_c2s = ChaCha20Poly1305::new_from_slice(&key_c2s).map_err(|_| TransportError::Aead)?;
        let aead_s2c = ChaCha20Poly1305::new_from_slice(&key_s2c).map_err(|_| TransportError::Aead)?;

        let mut raw = [0u8; prism_core::EXPORTER_LEN];
        let okm = hkdf_expand_label(shared.as_bytes(), b"prism/master", b"", prism_core::EXPORTER_LEN)?;
        raw.copy_from_slice(&okm);
        let exporter = PrismExporter::from_raw(raw);

        let (seal, open, seal_salt, open_salt) = if am_client {
            (aead_c2s, aead_s2c, Dir::C2s.nonce_salt(), Dir::S2c.nonce_salt())
        } else {
            (aead_s2c, aead_c2s, Dir::S2c.nonce_salt(), Dir::C2s.nonce_salt())
        };

        Ok(Self { seal, open, seal_salt, open_salt, exporter })
    }

    fn nonce(salt: [u8; 4], pn: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[0..4].copy_from_slice(&salt);
        n[4..12].copy_from_slice(&pn.to_be_bytes());
        *Nonce::from_slice(&n)
    }

    /// Seal `plaintext` for packet number `pn`, returning the ciphertext+tag.
    pub fn seal(&self, pn: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Self::nonce(self.seal_salt, pn);
        self.seal.encrypt(&nonce, plaintext).map_err(|_| TransportError::Aead)
    }

    /// Open a ciphertext sealed for packet number `pn`.
    pub fn open(&self, pn: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Self::nonce(self.open_salt, pn);
        self.open.decrypt(&nonce, ciphertext).map_err(|_| TransportError::Aead)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_core::crypto::X25519Secret;

    fn shared_pair() -> (SharedSecret, SharedSecret) {
        let server = X25519Secret::generate();
        let client = X25519Secret::generate();
        let s = server.diffie_hellman(&client.public());
        let c = client.diffie_hellman(&server.public());
        (c, s)
    }

    #[test]
    fn client_and_server_interop() {
        let (client_shared, server_shared) = shared_pair();
        let client = SessionKeys::derive(&client_shared, true).unwrap();
        let server = SessionKeys::derive(&server_shared, false).unwrap();

        // Client seals C2S; server opens it.
        let ct = client.seal(1, b"vpn payload").unwrap();
        let pt = server.open(1, &ct).unwrap();
        assert_eq!(pt, b"vpn payload");

        // Server seals S2C; client opens it.
        let ct2 = server.seal(7, b"downlink").unwrap();
        let pt2 = client.open(7, &ct2).unwrap();
        assert_eq!(pt2, b"downlink");
    }

    #[test]
    fn wrong_pn_fails_to_open() {
        let (c, s) = shared_pair();
        let client = SessionKeys::derive(&c, true).unwrap();
        let server = SessionKeys::derive(&s, false).unwrap();
        let ct = client.seal(1, b"x").unwrap();
        assert!(server.open(2, &ct).is_err());
    }

    #[test]
    fn both_sides_derive_same_exporter() {
        let (c, s) = shared_pair();
        let client = SessionKeys::derive(&c, true).unwrap();
        let server = SessionKeys::derive(&s, false).unwrap();
        assert_eq!(client.exporter.bbr_seed().unwrap(), server.exporter.bbr_seed().unwrap());
    }
}
