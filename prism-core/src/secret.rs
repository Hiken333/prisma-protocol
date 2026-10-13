//! Derivation of PRISM secrets from the TLS 1.3 exporter.
//!
//! A single TLS handshake yields the `prism_exporter`, from which every
//! transport-level seed is derived deterministically. Because both peers derive
//! the same exporter, their BBR seed and morphing PRNG streams are identical
//! without any extra key-exchange packets.

use crate::crypto::hkdf_expand_label;
use crate::error::Result;

/// Length of the master exporter, matching `TLS_KeySchedule_Exporter("prism/master", 48)`.
pub const EXPORTER_LEN: usize = 48;

/// The 48-byte master exporter secret for a PRISM session.
#[derive(Clone)]
pub struct PrismExporter([u8; EXPORTER_LEN]);

impl PrismExporter {
    /// Wrap raw exporter bytes (e.g. obtained from
    /// `quiche::Connection::export_keying_material(b"prism/master", &[], buf)`).
    pub fn from_raw(bytes: [u8; EXPORTER_LEN]) -> Self {
        Self(bytes)
    }

    /// Deterministic 32-byte seed for the BBRv3-PRISM controller.
    ///
    /// `seed[0..4]` quantizes the initial `BtlBw`, `seed[4..8]` the initial
    /// `RTprop` (decoded against the preloaded decoy CDN profile).
    pub fn bbr_seed(&self) -> Result<[u8; 32]> {
        self.expand(b"prism/bbr/seed")
    }

    /// PRNG seed for the **upload** morphing stream.
    pub fn morph_up_seed(&self) -> Result<[u8; 32]> {
        self.expand(b"prism/morph/up")
    }

    /// PRNG seed for the **download** morphing stream (independent of upload).
    pub fn morph_dn_seed(&self) -> Result<[u8; 32]> {
        self.expand(b"prism/morph/dn")
    }

    /// Key used to encrypt/decrypt the `prism_tp` session-ticket extension (0xFF01).
    pub fn ticket_key(&self) -> Result<[u8; 32]> {
        self.expand(b"prism/ticket")
    }

    /// BOLT uplink AEAD key (client → server).
    pub fn bolt_up_key(&self) -> Result<[u8; 32]> {
        self.expand(b"prism/bolt/up")
    }

    /// BOLT downlink AEAD key (server → client).
    pub fn bolt_dn_key(&self) -> Result<[u8; 32]> {
        self.expand(b"prism/bolt/dn")
    }

    fn expand(&self, label: &[u8]) -> Result<[u8; 32]> {
        let v = hkdf_expand_label(&self.0, label, b"", 32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

impl Drop for PrismExporter {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_are_distinct_and_deterministic() {
        let exp = PrismExporter::from_raw([0x42; EXPORTER_LEN]);
        let bbr = exp.bbr_seed().unwrap();
        let up = exp.morph_up_seed().unwrap();
        let dn = exp.morph_dn_seed().unwrap();
        assert_ne!(bbr, up);
        assert_ne!(up, dn);
        assert_ne!(bbr, dn);
        // Both peers derive identical seeds.
        let exp2 = PrismExporter::from_raw([0x42; EXPORTER_LEN]);
        assert_eq!(bbr, exp2.bbr_seed().unwrap());
    }
}
