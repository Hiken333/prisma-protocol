//! Per-session `MorphEngine`: samples sizes / delays / bursts from a `CdnProfile`
//! using the deterministic exporter-seeded PRNG.

use std::time::Duration;

use prism_core::PrismRng;
use rand_distr::{Distribution, Normal};

use crate::profile::CdnProfile;

/// Lower bound on morph target size (spec clamps to `[200, MTU-48]`).
const MIN_SIZE: usize = 200;

/// One direction's morphing engine. Upload and download use independent seeds
/// (`exporter || "up"` / `exporter || "dn"`) so their timings decorrelate.
pub struct MorphEngine {
    profile: CdnProfile,
    rng: PrismRng,
    jitter_pct: f64,
    mtu: usize,
}

impl MorphEngine {
    pub fn from_seed(seed: [u8; 32], profile: CdnProfile, jitter_pct: f64, mtu: usize) -> Self {
        Self { profile, rng: PrismRng::from_seed(seed), jitter_pct, mtu }
    }

    pub fn profile(&self) -> &CdnProfile {
        &self.profile
    }

    pub fn set_profile(&mut self, profile: CdnProfile) {
        self.profile = profile;
    }

    /// Choose a target datagram size given the current (pre-pad) size.
    ///
    /// Never shrinks below `current` (we cannot drop already-queued payload),
    /// and clamps to `[200, MTU - 48]` to avoid fragmentation (§5 risks).
    pub fn target_size(&mut self, current: usize) -> usize {
        let idx = self.rng.choice_weighted(&self.profile.size_hist.weights());
        let bucket = self.profile.size_hist.bucket(idx);
        let normal = Normal::new(0.0, bucket.sigma).unwrap_or_else(|_| Normal::new(0.0, 1.0).unwrap());
        let jitter = normal.sample(self.rng.inner());
        let target = (bucket.midpoint() + jitter) as i64;
        let hi = self.mtu.saturating_sub(48).max(MIN_SIZE);
        (target.max(MIN_SIZE as i64) as usize).clamp(MIN_SIZE, hi).max(current)
    }

    /// Inter-packet delay, including the ±jitter_pct timing jitter (§4.5).
    pub fn delay(&mut self) -> Duration {
        let idx = self.rng.choice_weighted(&self.profile.iat_hist.weights());
        let bucket = self.profile.iat_hist.bucket(idx);
        let base_ms = bucket.midpoint();
        let jittered = base_ms * self.rng.jitter(self.jitter_pct);
        Duration::from_secs_f64((jittered.max(0.0)) / 1000.0)
    }

    /// Pick a burst pattern: `(packet_count, inter_burst_pause)`.
    pub fn burst(&mut self) -> (u32, Duration) {
        if self.profile.bursts.is_empty() {
            return (1, Duration::ZERO);
        }
        let weights: Vec<f64> = self.profile.bursts.iter().map(|b| b.weight).collect();
        let idx = self.rng.choice_weighted(&weights);
        let b = &self.profile.bursts[idx];
        (b.packets.max(1), b.inter_burst_pause())
    }

    /// Bytes to send before the next forced morph pause (`MorphBudget` reload).
    pub fn next_budget(&mut self) -> u64 {
        // Roughly one burst worth of average-sized datagrams.
        let (count, _) = self.burst();
        let avg = self
            .profile
            .size_hist
            .buckets
            .iter()
            .map(|b| b.midpoint() * b.weight)
            .sum::<f64>()
            .max(512.0);
        (count as f64 * avg) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> MorphEngine {
        MorphEngine::from_seed([3u8; 32], CdnProfile::synthetic_chrome(), 0.10, 1400)
    }

    #[test]
    fn target_size_within_bounds() {
        let mut e = engine();
        for _ in 0..10_000 {
            let t = e.target_size(100);
            assert!(t >= MIN_SIZE, "target {t} below min");
            assert!(t <= 1400 - 48, "target {t} above mtu-48");
        }
    }

    #[test]
    fn target_size_never_shrinks_below_current() {
        let mut e = engine();
        for _ in 0..1000 {
            let t = e.target_size(900);
            assert!(t >= 900);
        }
    }

    #[test]
    fn deterministic_for_same_seed() {
        let mut a = engine();
        let mut b = engine();
        for _ in 0..100 {
            assert_eq!(a.target_size(100), b.target_size(100));
            assert_eq!(a.delay(), b.delay());
        }
    }
}
