//! Deterministic per-session PRNG built on ChaCha20.
//!
//! Both peers seed identical streams from the TLS exporter, so morphing
//! decisions are reproducible without synchronization traffic. Crucially, the
//! PRNG only drives *local send decisions* (sizes / timings); it never feeds
//! decode logic, so a divergence cannot break the connection.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// A seeded morphing PRNG stream. Wraps `ChaCha20Rng` with helpers used by the
/// morph engine.
pub struct PrismRng(ChaCha20Rng);

impl PrismRng {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(ChaCha20Rng::from_seed(seed))
    }

    /// Uniform float in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        self.0.gen::<f64>()
    }

    /// Uniform float in `[lo, hi)`.
    pub fn range(&mut self, lo: f64, hi: f64) -> f64 {
        self.0.gen_range(lo..hi)
    }

    /// Symmetric jitter multiplier in `[1 - pct, 1 + pct)`.
    pub fn jitter(&mut self, pct: f64) -> f64 {
        1.0 + self.range(-pct, pct)
    }

    /// Weighted index selection over `weights` (sum need not be 1.0).
    pub fn choice_weighted(&mut self, weights: &[f64]) -> usize {
        let total: f64 = weights.iter().sum();
        if total <= 0.0 {
            return 0;
        }
        let mut x = self.unit() * total;
        for (i, w) in weights.iter().enumerate() {
            if x < *w {
                return i;
            }
            x -= *w;
        }
        weights.len() - 1
    }

    /// Borrow the underlying RNG for crate-internal use (e.g. distributions).
    pub fn inner(&mut self) -> &mut ChaCha20Rng {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_seed() {
        let mut a = PrismRng::from_seed([1u8; 32]);
        let mut b = PrismRng::from_seed([1u8; 32]);
        for _ in 0..1000 {
            assert_eq!(a.unit(), b.unit());
        }
    }

    #[test]
    fn weighted_choice_respects_zero_weight() {
        let mut rng = PrismRng::from_seed([9u8; 32]);
        let weights = [0.0, 1.0, 0.0];
        for _ in 0..100 {
            assert_eq!(rng.choice_weighted(&weights), 1);
        }
    }
}
