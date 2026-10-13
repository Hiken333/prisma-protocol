//! Datagram assembly with morph padding.
//!
//! Chooses the morph target size for the next datagram, hands it to the backend
//! (which pads inside the AEAD plaintext via the quiche fork's
//! `set_prism_min_send_size`), then emits the datagram. Sampling the target
//! *before* `send` is what lets the PADDING frames land inside the sealed
//! payload rather than as observable trailing bytes.

use prism_morph::MorphEngine;

use crate::backend::QuicBackend;
use crate::error::{QuicError, Result};

/// Build the next datagram into `out`, applying morph padding.
///
/// Returns `Ok(0)` when the backend has nothing to send.
pub fn fill_datagram<B: QuicBackend + ?Sized>(
    backend: &mut B,
    morph: &mut MorphEngine,
    out: &mut [u8],
) -> Result<usize> {
    // Sample the target up front. `target_size`'s only dependence on the
    // current size is a floor, so passing 0 yields the raw sampled bucket; the
    // backend will simply not pad below what it actually serializes.
    let target = morph.target_size(0).min(out.len());
    backend.set_morph_target(target);

    match backend.send(out) {
        Ok(0) => try_unpadded_send(backend, out),
        Ok(n) => Ok(n),
        Err(QuicError::Done) => try_unpadded_send(backend, out),
        Err(e) => Err(e),
    }
}

/// When a morph-padded send returns nothing, the fork has already consumed the
/// morph target. Retry once without padding so ACKs / keepalives cannot deadlock
/// the tunnel (observed as zero packets in standard stealth mode).
fn try_unpadded_send<B: QuicBackend + ?Sized>(backend: &mut B, out: &mut [u8]) -> Result<usize> {
    backend.set_morph_target(0);
    match backend.send(out) {
        Ok(0) => Ok(0),
        Ok(n) => Ok(n),
        Err(QuicError::Done) => Ok(0),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::LoopbackBackend;
    use prism_morph::CdnProfile;

    #[test]
    fn datagram_is_padded_to_morph_target() {
        let mut back = LoopbackBackend::new();
        {
            let mut enc = crate::mcc::MccEncoder::new(&mut back);
            enc.write_ip_packet(0, b"hello").unwrap();
        }
        let mut morph =
            MorphEngine::from_seed([1u8; 32], CdnProfile::synthetic_chrome(), 0.1, 1400);
        let mut out = [0u8; 1500];
        let n = fill_datagram(&mut back, &mut morph, &mut out).unwrap();
        assert!(
            n >= 200,
            "padded datagram should reach the morph floor, got {n}"
        );
        assert!(n <= 1400 - 48);
    }
}
