//! Weighted fair queuing send scheduler across streams.

use std::collections::HashMap;

/// Per-stream scheduling weight (interactive > bulk).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamPriority {
    Interactive = 8,
    Normal = 4,
    Bulk = 1,
}

impl From<StreamPriority> for u32 {
    fn from(p: StreamPriority) -> u32 {
        p as u32
    }
}

/// Weighted round-robin picker for streams with pending data.
#[derive(Debug, Default)]
pub struct SendScheduler {
    credits: HashMap<u64, i64>,
    last_pick: Option<u64>,
}

impl SendScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pick the next stream to send from, adding `weight` credits each round.
    pub fn pick(&mut self, candidates: &[(u64, u32)]) -> Option<u64> {
        if candidates.is_empty() {
            return None;
        }
        for (id, w) in candidates {
            *self.credits.entry(*id).or_insert(0) += *w as i64;
        }
        let mut best: Option<(u64, i64)> = None;
        for (id, _) in candidates {
            let c = *self.credits.get(id).unwrap_or(&0);
            if best.map(|(_, bc)| c > bc).unwrap_or(true) {
                best = Some((*id, c));
            }
        }
        let (id, _) = best?;
        if let Some(c) = self.credits.get_mut(&id) {
            *c -= 100;
        }
        self.last_pick = Some(id);
        Some(id)
    }

    pub fn last_picked(&self) -> Option<u64> {
        self.last_pick
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interactive_wins_over_bulk() {
        let mut s = SendScheduler::new();
        let c = [(0u64, 1u32), (4, 8)];
        let first = s.pick(&c).unwrap();
        assert_eq!(first, 4);
    }
}
