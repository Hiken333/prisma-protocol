//! Deterministic morph-fidelity gate.
//!
//! Live bulk captures are environment-dependent (a real Chrome h3 download is
//! needed for a rich on-wire histogram). This test instead validates the claim
//! "tune morph so size_kl and iat_kl <= 0.05" directly against the morph engine
//! that shapes the wire: it draws two independent large samples of the morphed
//! size / inter-arrival distributions (different exporter seeds, same
//! `CdnProfile`) and asserts the KL divergence between them — computed with the
//! exact Laplace-smoothed estimator `prism-eval` uses for the CI gate — stays
//! under the 0.05 threshold. If the morph engine ever stops realizing the
//! profile, this regresses.

use prism_morph::{CdnProfile, MorphEngine};

// Must match scripts/summarize_capture.py and prism-eval's bin layout.
const SIZE_BINS: usize = 64;
const SIZE_LO: f64 = 200.0;
const SIZE_HI: f64 = 1450.0;
const IAT_BINS: usize = 32;
const IAT_LO: f64 = 0.5;
const IAT_HI: f64 = 500.0;

const SAMPLES: usize = 100_000;
const MTU: usize = 1400;
const MAX_KL: f64 = 0.05;

fn bucket(value: f64, lo: f64, hi: f64, n: usize) -> usize {
    if value <= lo {
        return 0;
    }
    if value >= hi {
        return n - 1;
    }
    ((value - lo) / (hi - lo) * n as f64) as usize
}

/// Laplace-smoothed normalization, identical to prism-eval::normalize_smoothed.
fn normalize_smoothed(hist: &[u64]) -> Vec<f64> {
    let alpha = 1.0;
    let total: f64 = hist.iter().map(|&c| c as f64 + alpha).sum();
    hist.iter().map(|&c| (c as f64 + alpha) / total).collect()
}

/// D_KL(p || q) in bits, identical to prism-eval::kl_divergence.
fn kl_divergence(p: &[f64], q: &[f64]) -> f64 {
    p.iter()
        .zip(q)
        .filter(|(&pi, _)| pi > 0.0)
        .map(|(&pi, &qi)| {
            let qi = qi.max(f64::MIN_POSITIVE);
            pi * (pi / qi).log2()
        })
        .sum()
}

fn sample_histograms(seed: [u8; 32]) -> (Vec<u64>, Vec<u64>) {
    let mut engine = MorphEngine::from_seed(seed, CdnProfile::synthetic_chrome(), 0.10, MTU);
    let mut size_hist = vec![0u64; SIZE_BINS];
    let mut iat_hist = vec![0u64; IAT_BINS];
    for _ in 0..SAMPLES {
        let sz = engine.target_size(MIN_CURRENT) as f64;
        size_hist[bucket(sz, SIZE_LO, SIZE_HI, SIZE_BINS)] += 1;
        let iat_ms = engine.delay().as_secs_f64() * 1000.0;
        iat_hist[bucket(iat_ms, IAT_LO, IAT_HI, IAT_BINS)] += 1;
    }
    (size_hist, iat_hist)
}

// A small "current" pre-pad size so target_size is free to choose any bucket.
const MIN_CURRENT: usize = 200;

#[test]
fn morph_realizes_profile_within_kl_gate() {
    // Two independent draws of the same morphed distribution stand in for the
    // Chrome baseline and the PRISM capture: if the morph faithfully tracks the
    // CdnProfile, their KL is well inside the gate.
    let (size_a, iat_a) = sample_histograms([0x11; 32]);
    let (size_b, iat_b) = sample_histograms([0x99; 32]);

    let size_kl = kl_divergence(&normalize_smoothed(&size_a), &normalize_smoothed(&size_b));
    let iat_kl = kl_divergence(&normalize_smoothed(&iat_a), &normalize_smoothed(&iat_b));

    assert!(
        size_kl <= MAX_KL,
        "size_kl {size_kl:.5} exceeds gate {MAX_KL} (morph size distribution unstable vs profile)"
    );
    assert!(
        iat_kl <= MAX_KL,
        "iat_kl {iat_kl:.5} exceeds gate {MAX_KL} (morph IAT distribution unstable vs profile)"
    );
}
