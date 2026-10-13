//! Throttle detection and profile adaptation (§4.4).
//!
//! A policer (rather than congestion) is suspected when RTT spikes far above
//! `RTprop` while loss stays low for several consecutive RTTs. On detection the
//! engine shifts to a conservative profile and shrinks the morph budget; under
//! genuine high loss it switches to an aggressive, video-like profile.

use std::time::Duration;

/// Recommended adaptation action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Adaptation {
    None,
    /// Suspected throttling: go conservative, scale budget down.
    Conservative,
    /// High loss: go aggressive (larger bursts).
    Aggressive,
}

/// Stateful throttle detector.
pub struct ThrottleDetector {
    consecutive_spikes: u32,
    /// Number of consecutive spiking RTTs required to declare throttling.
    threshold_rtts: u32,
}

impl ThrottleDetector {
    pub fn new() -> Self {
        Self { consecutive_spikes: 0, threshold_rtts: 3 }
    }

    /// Feed one RTT's worth of telemetry and get the recommended adaptation.
    ///
    /// * `rtt` — latest smoothed RTT
    /// * `rtprop` — min RTT estimate
    /// * `loss_rate` — EWMA loss over the last RTT
    pub fn observe(&mut self, rtt: Duration, rtprop: Duration, loss_rate: f64) -> Adaptation {
        if loss_rate > 0.05 {
            self.consecutive_spikes = 0;
            return Adaptation::Aggressive;
        }

        let spiking = rtt > rtprop.saturating_mul(2) && loss_rate < 0.01;
        if spiking {
            self.consecutive_spikes += 1;
        } else {
            self.consecutive_spikes = 0;
        }

        if self.consecutive_spikes >= self.threshold_rtts {
            self.consecutive_spikes = 0;
            Adaptation::Conservative
        } else {
            Adaptation::None
        }
    }
}

impl Default for ThrottleDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_loss_goes_aggressive() {
        let mut d = ThrottleDetector::new();
        let a = d.observe(Duration::from_millis(50), Duration::from_millis(40), 0.08);
        assert_eq!(a, Adaptation::Aggressive);
    }

    #[test]
    fn sustained_rtt_spike_goes_conservative() {
        let mut d = ThrottleDetector::new();
        let rtprop = Duration::from_millis(20);
        let spike = Duration::from_millis(60); // > 2x rtprop
        assert_eq!(d.observe(spike, rtprop, 0.0), Adaptation::None);
        assert_eq!(d.observe(spike, rtprop, 0.0), Adaptation::None);
        assert_eq!(d.observe(spike, rtprop, 0.0), Adaptation::Conservative);
    }

    #[test]
    fn normal_rtt_resets() {
        let mut d = ThrottleDetector::new();
        let rtprop = Duration::from_millis(20);
        d.observe(Duration::from_millis(60), rtprop, 0.0);
        d.observe(Duration::from_millis(60), rtprop, 0.0);
        // Recovery resets the counter.
        assert_eq!(d.observe(Duration::from_millis(22), rtprop, 0.0), Adaptation::None);
        assert_eq!(d.observe(Duration::from_millis(60), rtprop, 0.0), Adaptation::None);
    }
}
