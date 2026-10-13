//! Weighted histograms used by the CDN profile.

use serde::{Deserialize, Serialize};

/// A single histogram bucket: a value range with a sampling weight and the
/// per-bucket gaussian sigma used to dither samples within the bucket.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Bucket {
    pub lo: f64,
    pub hi: f64,
    pub weight: f64,
    pub sigma: f64,
}

impl Bucket {
    pub fn midpoint(&self) -> f64 {
        (self.lo + self.hi) / 2.0
    }
}

/// A weighted histogram over `Bucket`s. Generic over an array length so the
/// `size_hist[64]` / `iat_hist[32]` shapes from the spec are encoded in the type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Histogram {
    pub buckets: Vec<Bucket>,
}

impl Histogram {
    pub fn new(buckets: Vec<Bucket>) -> Self {
        Self { buckets }
    }

    /// The vector of weights, for `PrismRng::choice_weighted`.
    pub fn weights(&self) -> Vec<f64> {
        self.buckets.iter().map(|b| b.weight).collect()
    }

    pub fn bucket(&self, idx: usize) -> &Bucket {
        &self.buckets[idx.min(self.buckets.len() - 1)]
    }

    /// Shift the weight mass toward smaller (or larger) buckets by `delta`
    /// fraction. Positive `delta` favors larger buckets, negative favors smaller.
    pub fn shift_weights(&self, delta: f64) -> Self {
        let n = self.buckets.len() as f64;
        let buckets = self
            .buckets
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let pos = i as f64 / n; // 0..1 across buckets
                let factor = (1.0 + delta * (pos - 0.5) * 2.0).max(0.05);
                Bucket { weight: b.weight * factor, ..*b }
            })
            .collect();
        Self { buckets }
    }
}
