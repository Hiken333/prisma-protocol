//! Entropy regularization (§4.3).
//!
//! Encrypted payload sits near 8 bits/byte; real compressed HTTP/3 AppData is
//! ~7.2–7.8 bits/byte. Every ~8 KiB of payload we inject a steganographic dummy
//! frame (QUIC PING + PADDING, mimicking H3 SETTINGS / MAX_DATA) to correct the
//! joint entropy profile without carrying VPN data.

/// Default dummy-injection period in bytes.
pub const DEFAULT_DUMMY_PERIOD: usize = 8 * 1024;

/// Tracks how much payload has been sent since the last dummy frame.
pub struct EntropyRegulator {
    since_dummy: usize,
    period: usize,
}

impl EntropyRegulator {
    pub fn new(period: usize) -> Self {
        Self { since_dummy: 0, period: period.max(1024) }
    }

    pub fn with_default_period() -> Self {
        Self::new(DEFAULT_DUMMY_PERIOD)
    }

    /// Account for `bytes` of payload sent and report whether a dummy frame
    /// should be injected now.
    pub fn should_inject(&mut self, bytes: usize) -> bool {
        self.since_dummy += bytes;
        if self.since_dummy >= self.period {
            self.since_dummy = 0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_every_period() {
        let mut r = EntropyRegulator::new(8192);
        assert!(!r.should_inject(4000));
        assert!(!r.should_inject(4000));
        assert!(r.should_inject(200)); // crossed 8192
        assert!(!r.should_inject(100)); // reset
    }
}
