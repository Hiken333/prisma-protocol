//! Statistical metrics for comparing a PRISM capture against a Chrome baseline
//! (spec §4.1 distributions and the test plan).

/// Shannon entropy in bits/byte of a payload sample.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Normalize a histogram to a probability distribution, with Laplace smoothing
/// so empty buckets do not produce infinities in KL divergence.
pub fn normalize_smoothed(hist: &[u64]) -> Vec<f64> {
    let alpha = 1.0; // Laplace smoothing
    let total: f64 = hist.iter().map(|&c| c as f64 + alpha).sum();
    hist.iter().map(|&c| (c as f64 + alpha) / total).collect()
}

/// KL divergence `D_KL(p || q)` in bits. Inputs must be same-length, normalized.
pub fn kl_divergence(p: &[f64], q: &[f64]) -> f64 {
    assert_eq!(p.len(), q.len());
    p.iter()
        .zip(q)
        .filter(|(&pi, _)| pi > 0.0)
        .map(|(&pi, &qi)| {
            let qi = qi.max(f64::MIN_POSITIVE);
            pi * (pi / qi).log2()
        })
        .sum()
}

/// Pearson chi-squared statistic between observed and expected histograms.
pub fn chi_squared(observed: &[u64], expected: &[f64]) -> f64 {
    let total: f64 = observed.iter().map(|&c| c as f64).sum();
    observed
        .iter()
        .zip(expected)
        .map(|(&o, &e_prob)| {
            let e = (e_prob * total).max(1e-9);
            let d = o as f64 - e;
            d * d / e
        })
        .sum()
}

/// Pass/fail thresholds for the CI gate.
#[derive(Clone, Copy, Debug)]
pub struct Thresholds {
    pub max_size_kl: f64,
    pub max_iat_kl: f64,
    pub min_entropy: f64,
    pub max_entropy: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        // Entropy band calibrated against a measured Chrome QUIC capture
        // (www.google.com h3): on-wire payload entropy is ~7.96 bits/byte, i.e.
        // near the 8.0 ceiling because QUIC payloads are AEAD ciphertext. The
        // old 7.2..7.9 band rejected Chrome itself. The lower bound stays well
        // above plaintext/structured traffic (~<6) to still catch a regression
        // that leaks low-entropy bytes onto the wire.
        Self { max_size_kl: 0.05, max_iat_kl: 0.05, min_entropy: 7.5, max_entropy: 8.01 }
    }
}

/// Result of comparing a PRISM capture to a Chrome baseline.
#[derive(Clone, Copy, Debug)]
pub struct Comparison {
    pub size_kl: f64,
    pub iat_kl: f64,
    pub entropy: f64,
}

impl Comparison {
    pub fn passes(&self, t: &Thresholds) -> bool {
        self.size_kl <= t.max_size_kl
            && self.iat_kl <= t.max_iat_kl
            && self.entropy >= t.min_entropy
            && self.entropy <= t.max_entropy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_distributions_have_zero_kl() {
        let p = normalize_smoothed(&[10, 20, 30, 40]);
        let q = normalize_smoothed(&[10, 20, 30, 40]);
        assert!(kl_divergence(&p, &q).abs() < 1e-9);
    }

    #[test]
    fn divergent_distributions_have_positive_kl() {
        let p = normalize_smoothed(&[100, 0, 0, 0]);
        let q = normalize_smoothed(&[0, 0, 0, 100]);
        assert!(kl_divergence(&p, &q) > 0.5);
    }

    #[test]
    fn random_bytes_have_high_entropy() {
        let bytes: Vec<u8> = (0..=255u16).map(|x| x as u8).collect();
        let e = shannon_entropy(&bytes);
        assert!((e - 8.0).abs() < 1e-9, "uniform bytes should be ~8 bits/byte, got {e}");
    }

    #[test]
    fn constant_bytes_have_zero_entropy() {
        assert_eq!(shannon_entropy(&[7u8; 1000]), 0.0);
    }
}
