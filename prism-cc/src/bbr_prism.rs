//! BBRv3-PRISM congestion controller.
//!
//! Implements the ACK cycle from spec §2.2: windowed `BtlBw`/`RTprop` estimates,
//! a BBRv3-style pacing-gain schedule, deterministic initialization from the TLS
//! exporter seed, and a Hysteria-2-style "brutal mode" fallback under loss.

use std::time::{Duration, Instant};

use crate::filters::{WindowedMaxFilter, WindowedMinFilter};
use crate::morph_budget::MorphBudget;
use crate::traits::{Acked, CongestionControl, Lost, SentPacket};

const BTLBW_WINDOW: Duration = Duration::from_secs(10); // ~10 RTT proxy
const RTPROP_WINDOW: Duration = Duration::from_secs(10);
const MIN_CWND: usize = 4 * 1452;
const STARTUP_GAIN: f64 = 2.885; // 2/ln(2)
const BRUTAL_GAIN: f64 = 2.0;
const BRUTAL_LOSS_THRESHOLD: f64 = 0.02;
const RECOVER_LOSS_THRESHOLD: f64 = 0.01;

/// BBR phase machine (probe cycle simplified to the parts PRISM relies on).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BbrPhase {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

/// Hysteria-2-style brutal mode: fixed gain, ignore delay-based backoff.
#[derive(Clone, Copy, Debug)]
struct BrutalMode {
    gain: f64,
}

/// The BBRv3-PRISM controller.
pub struct BbrPrism {
    btlbw: WindowedMaxFilter,
    rtprop: WindowedMinFilter,
    cwnd: usize,
    phase: BbrPhase,
    pacing_gain: f64,
    cwnd_gain: f64,
    morph_budget: MorphBudget,
    brutal: Option<BrutalMode>,

    // Loss tracking (EWMA over a single RTT bucket).
    loss_ewma: f64,
    acked_in_round: u64,
    lost_in_round: u64,
    btlbw_prev: u64,

    // ProbeBw gain cycling.
    cycle_index: usize,
    cycle_stamp: Instant,
}

/// Standard BBR ProbeBw pacing-gain cycle.
const PROBE_BW_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

impl BbrPrism {
    /// Deterministic initialization from a 32-byte exporter-derived seed.
    ///
    /// `seed[0..4]` quantizes the initial `BtlBw`, `seed[4..8]` the initial
    /// `RTprop`, both decoded against the preloaded decoy CDN bandwidth/RTT range.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let now = Instant::now();
        let btlbw0 = decode_quantized_bw(&seed[0..4]);
        let rtprop0 = decode_quantized_rtt(&seed[4..8]);

        let mut btlbw = WindowedMaxFilter::new(BTLBW_WINDOW);
        btlbw.update(now, btlbw0);
        let mut rtprop = WindowedMinFilter::new(RTPROP_WINDOW);
        rtprop.update(now, rtprop0);

        let bdp = bdp_bytes(btlbw0, rtprop0);
        let initial_budget = btlbw0.max(64 * 1024); // ~1s worth, floor 64 KiB

        Self {
            btlbw,
            rtprop,
            cwnd: (bdp as f64 * STARTUP_GAIN).max(MIN_CWND as f64) as usize,
            phase: BbrPhase::Startup,
            pacing_gain: STARTUP_GAIN,
            cwnd_gain: STARTUP_GAIN,
            morph_budget: MorphBudget::new(initial_budget),
            brutal: None,
            loss_ewma: 0.0,
            acked_in_round: 0,
            lost_in_round: 0,
            btlbw_prev: btlbw0,
            cycle_index: 0,
            cycle_stamp: now,
        }
    }

    /// Mutable access to the morph budget so the send loop can arm pauses.
    pub fn morph_budget_mut(&mut self) -> &mut MorphBudget {
        &mut self.morph_budget
    }

    pub fn phase(&self) -> BbrPhase {
        self.phase
    }

    pub fn loss_rate(&self) -> f64 {
        self.loss_ewma
    }

    pub fn in_brutal_mode(&self) -> bool {
        self.brutal.is_some()
    }

    /// Recompute the congestion window after BtlBw/RTprop updates.
    fn recompute_cwnd(&mut self, now: Instant) {
        // Brutal mode: fixed gain, ignore delay-based backoff (Hy2 semantics).
        if self.loss_ewma > BRUTAL_LOSS_THRESHOLD && self.btlbw.max() < self.btlbw_prev / 2 {
            self.brutal.get_or_insert(BrutalMode { gain: BRUTAL_GAIN });
        } else if self.loss_ewma < RECOVER_LOSS_THRESHOLD {
            self.brutal = None;
        }

        let gain = match self.brutal {
            Some(b) => b.gain,
            None => self.cwnd_gain,
        };

        let rt = self.rtprop.min().unwrap_or(Duration::from_millis(50));
        let bdp = bdp_bytes(self.btlbw.max(), rt);
        self.cwnd = ((bdp as f64) * gain).max(MIN_CWND as f64) as usize;

        // Advance the ProbeBw gain cycle every RTprop.
        if self.phase == BbrPhase::ProbeBw && now.duration_since(self.cycle_stamp) >= rt {
            self.cycle_index = (self.cycle_index + 1) % PROBE_BW_GAINS.len();
            self.pacing_gain = PROBE_BW_GAINS[self.cycle_index];
            self.cycle_stamp = now;
        }
    }

    /// Roll the per-round loss EWMA when an RTT round completes.
    fn maybe_close_round(&mut self) {
        let total = self.acked_in_round + self.lost_in_round;
        if total >= 16 {
            let round_loss = self.lost_in_round as f64 / total as f64;
            // EWMA with alpha = 0.25.
            self.loss_ewma = 0.75 * self.loss_ewma + 0.25 * round_loss;
            self.acked_in_round = 0;
            self.lost_in_round = 0;
        }
    }

    fn transition_phase(&mut self) {
        match self.phase {
            BbrPhase::Startup => {
                // Leave startup once bandwidth growth plateaus.
                if self.btlbw.max() <= (self.btlbw_prev as f64 * 1.05) as u64 {
                    self.phase = BbrPhase::Drain;
                    self.pacing_gain = 1.0 / STARTUP_GAIN;
                    self.cwnd_gain = STARTUP_GAIN;
                }
            }
            BbrPhase::Drain => {
                self.phase = BbrPhase::ProbeBw;
                self.pacing_gain = 1.0;
                self.cwnd_gain = 2.0;
            }
            _ => {}
        }
    }
}

impl CongestionControl for BbrPrism {
    fn on_packet_sent(&mut self, _now: Instant, _sent: &SentPacket) {
        // Budget consumption is driven by the send loop (it knows the morph
        // pause/next-budget values from the morph engine).
    }

    fn on_ack(&mut self, now: Instant, acked: &[Acked], rtt: Duration) {
        if acked.is_empty() {
            return;
        }
        self.rtprop.update(now, rtt);

        // Delivery rate = delivered bytes / elapsed since their send-time mark.
        let mut sample_bw = 0u64;
        for a in acked {
            let interval = now.saturating_duration_since(a.delivered_at);
            if interval > Duration::ZERO {
                let bw = (a.delivered as f64 / interval.as_secs_f64()) as u64;
                sample_bw = sample_bw.max(bw);
            }
            self.acked_in_round += 1;
        }
        if sample_bw > 0 {
            self.btlbw.update(now, sample_bw);
        }

        self.maybe_close_round();
        self.transition_phase();
        self.recompute_cwnd(now);
        self.btlbw_prev = self.btlbw.max();
    }

    fn on_loss(&mut self, now: Instant, lost: &[Lost]) {
        self.lost_in_round += lost.len() as u64;
        self.maybe_close_round();
        self.recompute_cwnd(now);
    }

    fn cwnd(&self) -> usize {
        self.cwnd
    }

    fn pacing_rate(&self) -> u64 {
        let gain = self.brutal.map(|b| b.gain).unwrap_or(self.pacing_gain);
        (self.btlbw.max() as f64 * gain) as u64
    }

    fn can_send(&self, in_flight: usize) -> bool {
        in_flight < self.cwnd && self.morph_budget.allows(Instant::now())
    }

    fn rtprop(&self) -> Duration {
        self.rtprop.min().unwrap_or(Duration::from_millis(50))
    }
}

/// Decode a quantized bandwidth (bytes/s) from 4 seed bytes.
///
/// Maps the 32-bit value onto a log range `[64 KiB/s, 256 MiB/s]` so the
/// deterministic start is plausible for a CDN edge and never zero.
pub fn decode_quantized_bw(b: &[u8]) -> u64 {
    let raw = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as f64 / u32::MAX as f64;
    let lo = (64.0 * 1024.0f64).ln();
    let hi = (256.0 * 1024.0 * 1024.0f64).ln();
    (lo + raw * (hi - lo)).exp() as u64
}

/// Decode a quantized RTT from 4 seed bytes, mapped onto `[5 ms, 300 ms]`.
pub fn decode_quantized_rtt(b: &[u8]) -> Duration {
    let raw = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as f64 / u32::MAX as f64;
    let ms = 5.0 + raw * (300.0 - 5.0);
    Duration::from_micros((ms * 1000.0) as u64)
}

fn bdp_bytes(btlbw: u64, rtprop: Duration) -> u64 {
    (btlbw as f64 * rtprop.as_secs_f64()) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_init_from_seed() {
        let a = BbrPrism::from_seed([5u8; 32]);
        let b = BbrPrism::from_seed([5u8; 32]);
        assert_eq!(a.cwnd(), b.cwnd());
        assert_eq!(a.rtprop(), b.rtprop());
    }

    #[test]
    fn cwnd_never_below_minimum() {
        let bbr = BbrPrism::from_seed([0u8; 32]);
        assert!(bbr.cwnd() >= MIN_CWND);
    }

    #[test]
    fn brutal_mode_triggers_on_loss_and_bw_collapse() {
        let mut bbr = BbrPrism::from_seed([200u8; 32]);
        let now = Instant::now();
        // Inflate prev bandwidth, then force heavy loss with collapsed bandwidth.
        bbr.btlbw_prev = 10_000_000;
        bbr.loss_ewma = 0.10;
        // Advance past the BtlBw window so the seed sample is evicted and max()
        // reflects only the collapsed delivery rate.
        let later = now + BTLBW_WINDOW + Duration::from_millis(1);
        bbr.btlbw.update(later, 1_000);
        bbr.recompute_cwnd(later);
        assert!(bbr.in_brutal_mode());
        // Recovery clears brutal mode.
        bbr.loss_ewma = 0.005;
        bbr.recompute_cwnd(now);
        assert!(!bbr.in_brutal_mode());
    }
}
