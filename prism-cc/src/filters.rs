//! Windowed max/min filters used by BBR for `BtlBw` and `RTprop`.
//!
//! A simple time-windowed implementation: samples older than the window are
//! evicted. BBR uses a max filter over ~10 RTT for bandwidth and a min filter
//! over ~10 s for RTT.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Max filter over a time window.
pub struct WindowedMaxFilter {
    window: Duration,
    samples: VecDeque<(Instant, u64)>,
}

impl WindowedMaxFilter {
    pub fn new(window: Duration) -> Self {
        Self { window, samples: VecDeque::new() }
    }

    pub fn update(&mut self, now: Instant, value: u64) {
        self.evict(now);
        // Monotonic deque: drop tail entries smaller than the new value.
        while matches!(self.samples.back(), Some(&(_, v)) if v <= value) {
            self.samples.pop_back();
        }
        self.samples.push_back((now, value));
    }

    pub fn max(&self) -> u64 {
        self.samples.front().map(|&(_, v)| v).unwrap_or(0)
    }

    fn evict(&mut self, now: Instant) {
        while matches!(self.samples.front(), Some(&(t, _)) if now.duration_since(t) > self.window) {
            self.samples.pop_front();
        }
    }
}

/// Min filter over a time window.
pub struct WindowedMinFilter {
    window: Duration,
    samples: VecDeque<(Instant, Duration)>,
}

impl WindowedMinFilter {
    pub fn new(window: Duration) -> Self {
        Self { window, samples: VecDeque::new() }
    }

    pub fn update(&mut self, now: Instant, value: Duration) {
        self.evict(now);
        while matches!(self.samples.back(), Some(&(_, v)) if v >= value) {
            self.samples.pop_back();
        }
        self.samples.push_back((now, value));
    }

    pub fn min(&self) -> Option<Duration> {
        self.samples.front().map(|&(_, v)| v)
    }

    fn evict(&mut self, now: Instant) {
        while matches!(self.samples.front(), Some(&(t, _)) if now.duration_since(t) > self.window) {
            self.samples.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_filter_evicts_old() {
        let mut f = WindowedMaxFilter::new(Duration::from_millis(100));
        let t0 = Instant::now();
        f.update(t0, 100);
        assert_eq!(f.max(), 100);
        // A later, larger sample dominates.
        f.update(t0 + Duration::from_millis(10), 200);
        assert_eq!(f.max(), 200);
        // After the window expires, only recent samples remain.
        f.update(t0 + Duration::from_millis(200), 50);
        assert_eq!(f.max(), 50);
    }

    #[test]
    fn min_filter_tracks_minimum() {
        let mut f = WindowedMinFilter::new(Duration::from_secs(10));
        let t0 = Instant::now();
        f.update(t0, Duration::from_millis(50));
        f.update(t0 + Duration::from_millis(1), Duration::from_millis(30));
        assert_eq!(f.min(), Some(Duration::from_millis(30)));
    }
}
