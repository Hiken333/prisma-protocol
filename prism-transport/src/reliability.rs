//! ACK tracking, loss detection, fast retransmit and RTO.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use prism_cc::{Acked, CcGate, Lost};

use crate::frame;

/// A packet we sent and are waiting to be ACKed.
#[derive(Clone, Debug)]
pub struct SentEntry {
    pub pn: u64,
    pub bytes: usize,
    pub wire: Vec<u8>,
    pub sent_at: Instant,
    pub ack_eliciting: bool,
}

/// Receive-side PN tracking for generating ACKs.
#[derive(Default, Debug)]
struct RecvPnState {
    largest: u64,
    contiguous_from: u64,
}

impl RecvPnState {
    fn on_received(&mut self, pn: u64) {
        if pn == 0 {
            return;
        }
        if self.largest == 0 {
            self.largest = pn;
            self.contiguous_from = pn;
            return;
        }
        if pn == self.largest + 1 {
            self.largest = pn;
            return;
        }
        if pn > self.largest + 1 {
            // Gap — ACK will report contiguous range only up to last in-order.
            return;
        }
        if pn == self.contiguous_from.saturating_sub(1) || pn < self.contiguous_from {
            self.contiguous_from = pn;
        }
    }

    fn ack_range(&self) -> u64 {
        if self.largest == 0 {
            return 0;
        }
        self.largest.saturating_sub(self.contiguous_from) + 1
    }
}

/// Send-side reliability state.
#[derive(Debug)]
pub struct ReliabilityState {
    sent: BTreeMap<u64, SentEntry>,
    recv_pn: RecvPnState,
    largest_acked: u64,
    dup_ack_count: u32,
    last_ack_pn: u64,
    rto: Duration,
    pending_ack: bool,
    ack_delay_start: Option<Instant>,
    lost_events: u64,
    ack_events: u64,
}

impl Default for ReliabilityState {
    fn default() -> Self {
        Self {
            sent: BTreeMap::new(),
            recv_pn: RecvPnState::default(),
            largest_acked: 0,
            dup_ack_count: 0,
            last_ack_pn: 0,
            rto: Duration::from_millis(200),
            pending_ack: false,
            ack_delay_start: None,
            lost_events: 0,
            ack_events: 0,
        }
    }
}

impl ReliabilityState {
    pub fn on_sent(&mut self, entry: SentEntry) {
        self.sent.insert(entry.pn, entry);
    }

    pub fn on_pn_received(&mut self, pn: u64) {
        self.recv_pn.on_received(pn);
        self.pending_ack = true;
        if self.ack_delay_start.is_none() {
            self.ack_delay_start = Some(Instant::now());
        }
    }

    pub fn take_ack_frame(&mut self) -> Option<Vec<u8>> {
        if !self.pending_ack || self.recv_pn.largest == 0 {
            return None;
        }
        let delay_us = self
            .ack_delay_start
            .map(|t| t.elapsed().as_micros() as u64)
            .unwrap_or(0);
        let mut out = Vec::with_capacity(16);
        frame::encode_ack(
            &mut out,
            self.recv_pn.largest,
            self.recv_pn.ack_range(),
            delay_us,
        );
        self.pending_ack = false;
        self.ack_delay_start = None;
        Some(out)
    }

    pub fn sent_entry(&self, pn: u64) -> Option<&SentEntry> {
        self.sent.get(&pn)
    }

    /// Remove ACKed packets and return lost PN list.
    pub fn process_ack_loss_only(&mut self, largest: u64, first_range: u64, now: Instant) -> Vec<u64> {
        if largest == 0 || first_range == 0 {
            return Vec::new();
        }

        if largest == self.last_ack_pn {
            self.dup_ack_count += 1;
        } else {
            self.dup_ack_count = 0;
            self.last_ack_pn = largest;
        }

        let first_pn = largest.saturating_sub(first_range - 1);
        for pn in first_pn..=largest {
            self.sent.remove(&pn);
            self.ack_events += 1;
        }

        if largest > self.largest_acked {
            self.largest_acked = largest;
        }

        self.detect_loss(now)
    }

    pub fn remove_acked(&mut self, pn: u64) -> Option<SentEntry> {
        self.sent.remove(&pn)
    }

    fn detect_loss(&mut self, now: Instant) -> Vec<u64> {
        let mut lost = Vec::new();

        if self.dup_ack_count >= 3 {
            if let Some(&oldest_pn) = self.sent.keys().next() {
                lost.push(oldest_pn);
            }
            self.dup_ack_count = 0;
        }

        for (&pn, entry) in &self.sent {
            if now.duration_since(entry.sent_at) > self.rto {
                lost.push(pn);
            }
        }
        lost.sort_unstable();
        lost.dedup();
        self.lost_events += lost.len() as u64;
        lost
    }

    pub fn loss_rate(&self) -> f64 {
        let total = self.lost_events + self.ack_events;
        if total == 0 {
            return 0.0;
        }
        self.lost_events as f64 / total as f64
    }

    pub fn detect_loss_for_retransmit(&mut self, now: Instant) -> Vec<u64> {
        self.detect_loss(now)
    }

    pub fn retransmits(&self, lost_pns: &[u64]) -> Vec<Vec<u8>> {
        lost_pns
            .iter()
            .filter_map(|pn| self.sent.get(pn).map(|e| e.wire.clone()))
            .collect()
    }

    pub fn update_rto(&mut self, sample: Duration) {
        self.rto = sample.saturating_mul(2).max(Duration::from_millis(50));
    }

    pub fn in_flight_bytes(&self) -> usize {
        self.sent.values().map(|e| e.bytes).sum()
    }

    pub fn oldest_unacked(&self) -> Option<u64> {
        self.sent.keys().next().copied()
    }

    pub fn unacked_count(&self) -> usize {
        self.sent.len()
    }

    /// Async helper to notify CcGate after processing ACK frames.
    pub async fn notify_ack(
        gate: &CcGate,
        acked_entries: &[(u64, usize, Instant)],
        lost_entries: &[(u64, usize)],
        now: Instant,
    ) {
        if !acked_entries.is_empty() {
            let acked: Vec<Acked> = acked_entries
                .iter()
                .map(|(pn, bytes, sent_at)| Acked {
                    packet_number: *pn,
                    bytes: *bytes,
                    sent_at: *sent_at,
                    delivered: 0,
                    delivered_at: now,
                })
                .collect();
            let rtt = now.saturating_duration_since(acked_entries[0].2);
            let acked_bytes: usize = acked_entries.iter().map(|(_, b, _)| b).sum();
            gate.on_ack(&acked, rtt, acked_bytes).await;
        }
        if !lost_entries.is_empty() {
            let lost: Vec<Lost> = lost_entries
                .iter()
                .map(|(pn, bytes)| Lost {
                    packet_number: *pn,
                    bytes: *bytes,
                })
                .collect();
            let lost_bytes: usize = lost_entries.iter().map(|(_, b)| b).sum();
            gate.on_loss(&lost, lost_bytes).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recv_pn_tracks_largest() {
        let mut r = ReliabilityState::default();
        r.on_pn_received(1);
        r.on_pn_received(2);
        let ack = r.take_ack_frame().unwrap();
        assert!(!ack.is_empty());
    }
}
