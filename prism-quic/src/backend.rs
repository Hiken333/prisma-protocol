//! `QuicBackend` — the seam between PRISM and the underlying QUIC stack.
//!
//! Everything PRISM needs from QUIC is expressed here so that:
//! * the pure-logic crates (MCC encoder, send loop) compile and unit-test
//!   without a native BoringSSL/quiche build;
//! * the real `quiche` backend (feature `quiche-backend`) and a future
//!   `s2n-quic` backend slot behind the same trait.
//!
//! ## Morph padding note
//!
//! PRISM pads *inside* the AEAD plaintext (PADDING frame `0x00`) so the encrypted
//! datagram reaches the morph target without IP-level fragmentation. Stock quiche
//! does not expose frame-level padding to an arbitrary size, which is the main
//! reason PRISM ships a thin quiche fork. The fork adds
//! `Connection::set_prism_min_send_size`, surfaced here as
//! [`QuicBackend::set_morph_target`]: the target is set *before* `send()` so the
//! PADDING frames land inside the sealed payload. The in-memory test backend
//! emulates the same behaviour in its own `send()`.

use std::time::Duration;

use crate::error::Result;

/// Result of acknowledgement processing surfaced to the congestion controller.
#[derive(Clone, Debug, Default)]
pub struct AckReport {
    pub acked: Vec<prism_cc::Acked>,
    pub lost: Vec<prism_cc::Lost>,
    pub latest_rtt: Option<Duration>,
    pub acked_bytes: usize,
    pub lost_bytes: usize,
}

/// Minimal QUIC connection surface used by PRISM.
pub trait QuicBackend: Send {
    /// Queue VPN payload on `stream_id` at the implicit next offset; returns the
    /// number of bytes accepted (may be `< data.len()` under flow control).
    fn stream_send(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<usize>;

    /// Read available bytes from `stream_id`. Returns `(n, fin)`.
    fn stream_recv(&mut self, stream_id: u64, out: &mut [u8]) -> Result<(usize, bool)>;

    /// Streams with data available to read.
    fn readable(&self) -> Vec<u64>;

    /// Set the morph target (on-wire UDP datagram size) for the *next*
    /// short-header datagram produced by [`send`](Self::send). The backend pads
    /// with PADDING frames inside the AEAD plaintext up to this size; the
    /// request is consumed after one datagram. Best-effort: ignored for
    /// handshake packets and capped by the available buffer / pacing budget.
    fn set_morph_target(&mut self, target: usize);

    /// Emit the next datagram into `out`. Returns `Ok(0)` when there is nothing
    /// to send (quiche's `Done`). If a morph target was set via
    /// [`set_morph_target`](Self::set_morph_target) it is applied here.
    fn send(&mut self, out: &mut [u8]) -> Result<usize>;

    /// Feed a received datagram into the connection.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Inject a steganographic dummy frame (QUIC PING + PADDING).
    fn send_ping(&mut self) -> Result<()>;

    /// Export keying material (`prism/master`) once the handshake completes.
    /// Takes `&mut self` because BoringSSL's `SSL_export_keying_material`
    /// operates on a mutable `SSL*`.
    fn export_keying_material(
        &mut self,
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<()>;

    /// Drain ACK/loss information accumulated since the last call.
    fn take_ack_report(&mut self) -> AckReport;

    /// Bytes currently in flight (sent but unacked).
    fn bytes_in_flight(&self) -> usize;

    fn is_established(&self) -> bool;
    fn is_closed(&self) -> bool;

    /// Graceful close with a QUIC CONNECTION_CLOSE (code 0x00, empty reason).
    fn close(&mut self, app: bool, err: u64, reason: &[u8]) -> Result<()>;
}
