//! The morph-aware send loop (spec §4.2 SendLoop).
//!
//! For each burst drawn from the CDN profile, it sends `burst_count` datagrams
//! spaced by `MorphDelay()` (with ±jitter), gated by the congestion window /
//! pacing rate via [`CcGate`], injects entropy-regularizing dummy frames, then
//! sleeps the inter-burst pause. The server adds a small clock-skew offset to
//! mimic CDN edge variance (§4.5).

use std::time::Duration;

use prism_cc::CcGate;
use prism_morph::{EntropyRegulator, MorphEngine};
use tokio::net::UdpSocket;

use crate::backend::QuicBackend;
use crate::datagram::fill_datagram;
use crate::error::Result;

/// Whether this endpoint mimics CDN-edge clock skew on its responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Configuration for one direction's send loop.
pub struct SendLoopCtx {
    pub role: Role,
    pub max_clock_skew: Duration,
}

impl Default for SendLoopCtx {
    fn default() -> Self {
        Self {
            role: Role::Client,
            max_clock_skew: Duration::from_millis(50),
        }
    }
}

/// Run the send loop until the connection closes.
///
/// `backend` is the QUIC connection, `morph` the per-direction engine, `gate`
/// the shared congestion gate, `entropy` the dummy-frame regulator.
pub async fn run_send_loop<B: QuicBackend + ?Sized>(
    sock: &UdpSocket,
    backend: &mut B,
    morph: &mut MorphEngine,
    gate: &CcGate,
    entropy: &mut EntropyRegulator,
    ctx: &SendLoopCtx,
) -> Result<()> {
    let mut out = vec![0u8; 1500];

    loop {
        if backend.is_closed() {
            return Ok(());
        }

        // Clock-skew mimicry: the server jitters the start of each burst.
        if ctx.role == Role::Server && !ctx.max_clock_skew.is_zero() {
            let skew = morph.delay().min(ctx.max_clock_skew);
            tokio::time::sleep(skew).await;
        }

        let (burst_count, burst_pause) = morph.burst();
        for _ in 0..burst_count {
            let n = fill_datagram(backend, morph, &mut out)?;
            if n == 0 {
                break; // nothing queued; fall through to pause and re-poll
            }

            // Respect cwnd + pacing before the datagram hits the wire.
            gate.acquire(n).await;
            sock.send(&out[..n])
                .await
                .map_err(|e| crate::error::QuicError::Backend(e.to_string()))?;

            // Entropy regularization: a dummy PING+PADDING every ~8 KiB.
            if entropy.should_inject(n) {
                backend.send_ping()?;
            }

            tokio::time::sleep(morph.delay()).await;
        }

        tokio::time::sleep(burst_pause).await;
    }
}
