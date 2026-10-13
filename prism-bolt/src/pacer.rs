//! Adaptive pulse pacer + env helpers.

use std::time::{Duration, Instant};

/// Default ceiling if `PRISM_BOLT_MBPS` is unset (Phase 2).
const DEFAULT_MBPS: f64 = 300.0;
const MAX_MBPS: f64 = 500.0;
const PULSE_BOOST: f64 = 1.25;

pub fn bolt_turbo_from_env() -> bool {
    std::env::var("PRISM_BOLT_TURBO")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or_else(|_| {
            std::env::var("PRISM_PERF")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
        })
}

pub fn bolt_mbps_from_env() -> f64 {
    std::env::var("PRISM_BOLT_MBPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&m| m > 0.0)
        .unwrap_or(DEFAULT_MBPS)
        .min(MAX_MBPS)
}

pub fn bolt_lanes_from_env() -> usize {
    std::env::var("PRISM_BOLT_LANES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| (2..=8).contains(&n))
        .unwrap_or(8)
}

/// Bytes-per-second token bucket with adaptive ceiling (Pulse).
pub struct BrutalPacer {
    rate_bps: f64,
    ceiling_bps: f64,
    tokens: f64,
    last: Instant,
    window_start: Instant,
    window_bytes: u64,
    measured_peak_bps: f64,
    turbo: bool,
}

impl BrutalPacer {
    pub fn from_env() -> Self {
        Self::new_with_turbo(bolt_mbps_from_env(), bolt_turbo_from_env())
    }

    /// Perf/BOLT sessions pass `force_turbo` so the server need not set `PRISM_PERF` in env.
    pub fn new_with_turbo(mbps: f64, turbo: bool) -> Self {
        let mbps = mbps.min(MAX_MBPS);
        let rate_bps = mbps * 1_000_000.0 / 8.0;
        Self {
            rate_bps,
            ceiling_bps: rate_bps,
            tokens: rate_bps,
            last: Instant::now(),
            window_start: Instant::now(),
            window_bytes: 0,
            measured_peak_bps: 0.0,
            turbo,
        }
    }

    pub fn new(mbps: f64) -> Self {
        Self::new_with_turbo(mbps, bolt_turbo_from_env())
    }

    pub fn is_turbo(&self) -> bool {
        self.turbo
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate_bps).min(self.rate_bps * 0.5);
    }

    /// Record a successful send; every ~1 s bump rate toward measured goodput.
    pub fn pulse(&mut self, nbytes: usize) {
        self.window_bytes += nbytes as u64;
        let elapsed = self.window_start.elapsed().as_secs_f64();
        if elapsed < 1.0 {
            return;
        }
        let measured = self.window_bytes as f64 / elapsed;
        if measured > self.measured_peak_bps {
            self.measured_peak_bps = measured;
            let target = (measured * PULSE_BOOST).min(self.ceiling_bps);
            if target > self.rate_bps {
                self.rate_bps = target;
            }
        }
        self.window_start = Instant::now();
        self.window_bytes = 0;
    }

    pub async fn await_bytes(&mut self, n: usize) {
        if self.turbo {
            return;
        }
        let need = n as f64;
        loop {
            self.refill();
            if self.tokens >= need {
                self.tokens -= need;
                return;
            }
            let deficit = need - self.tokens;
            let wait = Duration::from_secs_f64(deficit / self.rate_bps);
            tokio::time::sleep(wait.max(Duration::from_micros(20))).await;
        }
    }

    pub fn rate_mbps(&self) -> f64 {
        self.rate_bps * 8.0 / 1_000_000.0
    }

    pub fn peak_mbps(&self) -> f64 {
        self.measured_peak_bps * 8.0 / 1_000_000.0
    }
}
