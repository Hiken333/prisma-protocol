//! Per-connection PRISM session state.
//!
//! Ties together the pieces that are all derived from one TLS handshake:
//! the `PrismExporter`, the BBRv3-PRISM controller (via `CcGate`), and the two
//! independent (up / down) morph engines.

use prism_cc::{BbrPrism, CcGate};
use prism_core::{PrismExporter, EXPORTER_LEN};
use prism_morph::{CdnProfile, EntropyRegulator, MorphEngine};

use crate::backend::QuicBackend;
use crate::error::Result;

/// Direction of a morph engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Up,
    Down,
}

/// Everything a live PRISM connection needs after the handshake completes.
pub struct PrismSession {
    pub gate: CcGate,
    pub morph_up: MorphEngine,
    pub morph_dn: MorphEngine,
    pub entropy_up: EntropyRegulator,
    pub entropy_dn: EntropyRegulator,
}

impl PrismSession {
    /// Derive all transport state from the backend's TLS exporter.
    ///
    /// Called by both peers once `is_established()` is true; identical exporters
    /// yield identical BBR seeds and morph streams without extra packets.
    pub fn derive<B: QuicBackend + ?Sized>(
        backend: &mut B,
        profile: CdnProfile,
        jitter_pct: f64,
        mtu: usize,
    ) -> Result<Self> {
        let mut raw = [0u8; EXPORTER_LEN];
        backend.export_keying_material(b"prism/master", &[], &mut raw)?;
        let exporter = PrismExporter::from_raw(raw);

        let bbr = BbrPrism::from_seed(exporter.bbr_seed()?);
        let gate = CcGate::new(Box::new(bbr));

        let morph_up =
            MorphEngine::from_seed(exporter.morph_up_seed()?, profile.clone(), jitter_pct, mtu);
        let morph_dn = MorphEngine::from_seed(exporter.morph_dn_seed()?, profile, jitter_pct, mtu);

        Ok(Self {
            gate,
            morph_up,
            morph_dn,
            entropy_up: EntropyRegulator::with_default_period(),
            entropy_dn: EntropyRegulator::with_default_period(),
        })
    }

    /// Graceful close: QUIC CONNECTION_CLOSE with application code `0x00` and an
    /// empty reason — no VPN-specific close frame (§5.4 Phase 3).
    pub fn graceful_close<B: QuicBackend + ?Sized>(backend: &mut B) -> Result<()> {
        backend.close(false, 0x00, b"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::LoopbackBackend;

    #[test]
    fn derives_symmetric_state() {
        let mut back = LoopbackBackend::new();
        let s1 =
            PrismSession::derive(&mut back, CdnProfile::synthetic_chrome(), 0.1, 1400).unwrap();
        let s2 =
            PrismSession::derive(&mut back, CdnProfile::synthetic_chrome(), 0.1, 1400).unwrap();
        // Both derivations of the same exporter produce identical morph streams.
        let mut a = s1.morph_up;
        let mut b = s2.morph_up;
        assert_eq!(a.target_size(100), b.target_size(100));
    }
}
