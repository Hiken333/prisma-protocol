//! 0-RTT anti-replay (§2.4).
//!
//! A time-bucketed bloom filter over `(client_id, packet_number)` covering the
//! last ~10 seconds. 0-RTT VPN data is only accepted after the ticket age is
//! validated (`< 604800 s`) elsewhere; this structure rejects replays within the
//! acceptance window.

use std::time::{Duration, Instant};

const NUM_HASHES: usize = 4;
const TICKET_MAX_AGE: Duration = Duration::from_secs(604_800);

/// A pair of bloom filters rotated every `window/2` so the effective coverage is
/// always at least `window/2` and at most `window`.
pub struct ReplayFilter {
    bits: usize,
    current: Vec<u64>,
    previous: Vec<u64>,
    rotate_at: Instant,
    half_window: Duration,
}

impl ReplayFilter {
    /// `window` is the total replay-protection horizon (spec: 10 s).
    pub fn new(window: Duration, bits: usize) -> Self {
        let words = bits.div_ceil(64).max(1);
        Self {
            bits: words * 64,
            current: vec![0u64; words],
            previous: vec![0u64; words],
            rotate_at: Instant::now() + window / 2,
            half_window: window / 2,
        }
    }

    /// Check-and-set: returns `true` if `(client_id, pn)` is a likely replay.
    pub fn check_and_record(&mut self, now: Instant, client_id: &[u8], pn: u64) -> bool {
        self.maybe_rotate(now);
        let mut seen = true;
        for i in 0..NUM_HASHES {
            let idx = self.index(client_id, pn, i as u64);
            let word = idx / 64;
            let bit = 1u64 << (idx % 64);
            let in_current = self.current[word] & bit != 0;
            let in_previous = self.previous[word] & bit != 0;
            if !(in_current || in_previous) {
                seen = false;
            }
            self.current[word] |= bit;
        }
        seen
    }

    /// Whether a ticket of the given age is still acceptable for 0-RTT.
    pub fn ticket_age_ok(age: Duration) -> bool {
        age < TICKET_MAX_AGE
    }

    fn maybe_rotate(&mut self, now: Instant) {
        if now >= self.rotate_at {
            std::mem::swap(&mut self.current, &mut self.previous);
            self.current.iter_mut().for_each(|w| *w = 0);
            self.rotate_at = now + self.half_window;
        }
    }

    fn index(&self, client_id: &[u8], pn: u64, salt: u64) -> usize {
        // FNV-1a over (salt, client_id, pn), reduced to bit range.
        let mut h: u64 = 0xcbf29ce484222325 ^ salt.wrapping_mul(0x100000001b3);
        for &b in client_id {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        for b in pn.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        (h as usize) % self.bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_replay_within_window() {
        let mut f = ReplayFilter::new(Duration::from_secs(10), 1 << 16);
        let now = Instant::now();
        assert!(!f.check_and_record(now, b"client-a", 42));
        // Same tuple again -> replay.
        assert!(f.check_and_record(now, b"client-a", 42));
        // Different pn -> not a replay.
        assert!(!f.check_and_record(now, b"client-a", 43));
    }

    #[test]
    fn ticket_age_bound() {
        assert!(ReplayFilter::ticket_age_ok(Duration::from_secs(1000)));
        assert!(!ReplayFilter::ticket_age_ok(Duration::from_secs(700_000)));
    }
}
