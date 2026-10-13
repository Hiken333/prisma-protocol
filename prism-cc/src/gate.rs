//! Async pacing gate around a [`CongestionControl`].
//!
//! When the quiche fork's `set_custom_congestion_control` is unavailable, the
//! controller cannot influence quiche internals directly. Instead the send loop
//! awaits [`CcGate::acquire`], which blocks until both the congestion window and
//! the morph budget permit another packet, and paces according to `pacing_rate`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::traits::CongestionControl;

/// Shared, async-friendly handle to the congestion controller.
#[derive(Clone)]
pub struct CcGate {
    inner: Arc<Mutex<GateState>>,
}

struct GateState {
    cc: Box<dyn CongestionControl>,
    in_flight: usize,
    last_send: Instant,
}

impl CcGate {
    pub fn new(cc: Box<dyn CongestionControl>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(GateState {
                cc,
                in_flight: 0,
                last_send: Instant::now(),
            })),
        }
    }

    /// Block until a `bytes`-sized packet may be sent, honoring both the
    /// congestion window and the pacing rate. Returns once the caller may send.
    pub async fn acquire(&self, bytes: usize) {
        loop {
            let wait = {
                let st = self.inner.lock().await;
                if !st.cc.can_send(st.in_flight) {
                    Some(st.cc.rtprop().min(Duration::from_millis(20)))
                } else {
                    pacing_wait(&*st.cc, st.last_send, bytes)
                }
            };
            match wait {
                Some(d) if d > Duration::ZERO => tokio::time::sleep(d).await,
                _ => break,
            }
        }
        let mut st = self.inner.lock().await;
        st.in_flight += bytes;
        st.last_send = Instant::now();
    }

    /// Record an ACK; reduces the in-flight estimate.
    pub async fn on_ack(
        &self,
        acked: &[crate::traits::Acked],
        rtt: Duration,
        acked_bytes: usize,
    ) {
        let mut st = self.inner.lock().await;
        st.in_flight = st.in_flight.saturating_sub(acked_bytes);
        let now = Instant::now();
        st.cc.on_ack(now, acked, rtt);
    }

    /// Record loss.
    pub async fn on_loss(&self, lost: &[crate::traits::Lost], lost_bytes: usize) {
        let mut st = self.inner.lock().await;
        st.in_flight = st.in_flight.saturating_sub(lost_bytes);
        st.cc.on_loss(Instant::now(), lost);
    }
}

/// Compute how long to wait to respect the pacing rate, if any.
fn pacing_wait(cc: &dyn CongestionControl, last_send: Instant, bytes: usize) -> Option<Duration> {
    let rate = cc.pacing_rate();
    if rate == 0 {
        return None;
    }
    let min_interval = Duration::from_secs_f64(bytes as f64 / rate as f64);
    let elapsed = last_send.elapsed();
    if elapsed >= min_interval {
        None
    } else {
        Some(min_interval - elapsed)
    }
}
