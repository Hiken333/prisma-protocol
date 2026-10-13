//! `CdnProfile` — histogram profile of real decoy-origin traffic (§4.2).

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::MorphError;
use crate::histogram::{Bucket, Histogram};

/// A typical burst (e.g. a video segment): a packet count and the pause that
/// follows it.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct BurstPattern {
    pub packets: u32,
    pub inter_burst_pause_ms: f64,
    pub weight: f64,
}

impl BurstPattern {
    pub fn inter_burst_pause(&self) -> Duration {
        Duration::from_secs_f64(self.inter_burst_pause_ms / 1000.0)
    }
}

/// Captured CDN traffic profile. Loaded from `CaptureDecoyTraffic(decoy_origin, 24h)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CdnProfile {
    /// Datagram size distribution (buckets 200..1450 bytes).
    pub size_hist: Histogram,
    /// Inter-arrival-time distribution (buckets 0.5..500 ms).
    pub iat_hist: Histogram,
    /// Typical burst lengths.
    pub bursts: Vec<BurstPattern>,
    /// Up/down byte ratio over 1s (for reference / down-side shaping).
    pub direction_ratio: f64,
}

impl CdnProfile {
    pub fn load(path: &Path) -> Result<Self, MorphError> {
        let bytes = std::fs::read(path).map_err(|e| MorphError::Load(e.to_string()))?;
        serde_json::from_slice(&bytes).map_err(|e| MorphError::Parse(e.to_string()))
    }

    pub fn save(&self, path: &Path) -> Result<(), MorphError> {
        let json = serde_json::to_vec_pretty(self).map_err(|e| MorphError::Parse(e.to_string()))?;
        std::fs::write(path, json).map_err(|e| MorphError::Load(e.to_string()))
    }

    /// Conservative variant: shift size mass toward smaller datagrams (used when
    /// throttling is suspected).
    pub fn conservative(&self) -> Self {
        Self { size_hist: self.size_hist.shift_weights(-0.4), ..self.clone() }
    }

    /// Aggressive variant: larger, more video-like bursts (used under high loss).
    pub fn aggressive(&self) -> Self {
        let bursts = self
            .bursts
            .iter()
            .map(|b| BurstPattern {
                packets: (b.packets as f64 * 1.4) as u32,
                ..*b
            })
            .collect();
        Self {
            size_hist: self.size_hist.shift_weights(0.3),
            bursts,
            ..self.clone()
        }
    }

    /// A minimal synthetic Chrome-like profile, useful for tests / cold start
    /// before a real capture is available.
    pub fn synthetic_chrome() -> Self {
        let size_hist = Histogram::new(vec![
            Bucket { lo: 200.0, hi: 400.0, weight: 0.10, sigma: 40.0 },
            Bucket { lo: 400.0, hi: 800.0, weight: 0.15, sigma: 60.0 },
            Bucket { lo: 800.0, hi: 1200.0, weight: 0.25, sigma: 80.0 },
            Bucket { lo: 1200.0, hi: 1452.0, weight: 0.50, sigma: 30.0 },
        ]);
        let iat_hist = Histogram::new(vec![
            Bucket { lo: 0.5, hi: 2.0, weight: 0.50, sigma: 0.3 },
            Bucket { lo: 2.0, hi: 10.0, weight: 0.30, sigma: 2.0 },
            Bucket { lo: 10.0, hi: 50.0, weight: 0.15, sigma: 8.0 },
            Bucket { lo: 50.0, hi: 500.0, weight: 0.05, sigma: 50.0 },
        ]);
        let bursts = vec![
            BurstPattern { packets: 8, inter_burst_pause_ms: 15.0, weight: 0.5 },
            BurstPattern { packets: 24, inter_burst_pause_ms: 40.0, weight: 0.3 },
            BurstPattern { packets: 64, inter_burst_pause_ms: 120.0, weight: 0.2 },
        ];
        Self { size_hist, iat_hist, bursts, direction_ratio: 0.12 }
    }
}
