//! Morph budget: forces a CDN-like pause after every `N` bytes (§2.2 step 5).
//!
//! `N` is drawn from the morph PRNG; the controller asks the budget whether it
//! is currently in a forced pause and feeds it bytes on every send.

use std::time::{Duration, Instant};

/// Tracks remaining bytes until the next forced morph pause.
pub struct MorphBudget {
    remaining: i64,
    pause_until: Option<Instant>,
    /// Scaling factor applied to budgets (reduced on throttle detection).
    scale: f64,
}

impl MorphBudget {
    pub fn new(initial_budget: u64) -> Self {
        Self { remaining: initial_budget as i64, pause_until: None, scale: 1.0 }
    }

    /// Whether sending is currently permitted (not inside a forced pause).
    pub fn allows(&self, now: Instant) -> bool {
        self.pause_until.map_or(true, |t| now >= t)
    }

    /// Account for `bytes` just sent. When the budget is exhausted, arm a pause
    /// of `pause` and reload the budget with `next_budget`.
    pub fn consume(&mut self, now: Instant, bytes: usize, pause: Duration, next_budget: u64) {
        self.remaining -= bytes as i64;
        if self.remaining <= 0 {
            self.pause_until = Some(now + pause);
            self.remaining = (next_budget as f64 * self.scale) as i64;
        }
    }

    /// Time until the current pause ends, if any.
    pub fn pause_remaining(&self, now: Instant) -> Option<Duration> {
        self.pause_until
            .filter(|&t| t > now)
            .map(|t| t.duration_since(now))
    }

    /// Apply a multiplicative scale to future budgets (throttle adaptation).
    pub fn set_scale(&mut self, scale: f64) {
        self.scale = scale.clamp(0.1, 4.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arms_pause_when_exhausted() {
        let now = Instant::now();
        let mut b = MorphBudget::new(1000);
        assert!(b.allows(now));
        b.consume(now, 600, Duration::from_millis(50), 1000);
        assert!(b.allows(now)); // still has budget
        b.consume(now, 600, Duration::from_millis(50), 1000);
        // Budget exhausted -> paused.
        assert!(!b.allows(now));
        assert!(b.allows(now + Duration::from_millis(60)));
    }
}
