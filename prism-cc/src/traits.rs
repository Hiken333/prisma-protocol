//! Congestion-control trait that the QUIC backend drives.
//!
//! This mirrors the small `pub trait CongestionControl` we expose in the quiche
//! fork (`set_custom_congestion_control`). Keeping it here lets `BbrPrism` be
//! unit-tested without any QUIC dependency, and lets the same controller be
//! reused by the external `CcGate` fallback when the fork is unavailable.

use std::time::{Duration, Instant};

/// Metadata for a packet that has been put on the wire.
#[derive(Clone, Copy, Debug)]
pub struct SentPacket {
    pub packet_number: u64,
    pub bytes: usize,
    pub sent_at: Instant,
    /// Delivered byte count at send time (for delivery-rate estimation).
    pub delivered: u64,
    pub delivered_at: Instant,
    /// Whether the connection was application-limited when this was sent.
    pub app_limited: bool,
}

/// A newly acknowledged packet.
#[derive(Clone, Copy, Debug)]
pub struct Acked {
    pub packet_number: u64,
    pub bytes: usize,
    pub sent_at: Instant,
    pub delivered: u64,
    pub delivered_at: Instant,
}

/// A packet declared lost.
#[derive(Clone, Copy, Debug)]
pub struct Lost {
    pub packet_number: u64,
    pub bytes: usize,
}

/// Pluggable congestion controller. Implemented by [`crate::BbrPrism`].
pub trait CongestionControl: Send {
    /// Called when a packet is handed to the socket.
    fn on_packet_sent(&mut self, now: Instant, sent: &SentPacket);

    /// Called once per ACK frame with the freshly acknowledged packets and the
    /// latest RTT sample.
    fn on_ack(&mut self, now: Instant, acked: &[Acked], rtt: Duration);

    /// Called when loss detection declares packets lost.
    fn on_loss(&mut self, now: Instant, lost: &[Lost]);

    /// Current congestion window in bytes.
    fn cwnd(&self) -> usize;

    /// Pacing rate in bytes/second (`0` means "no pacing limit").
    fn pacing_rate(&self) -> u64;

    /// Whether another `bytes`-sized packet may be sent given `in_flight`.
    fn can_send(&self, in_flight: usize) -> bool;

    /// Smoothed RTT estimate (`RTprop`).
    fn rtprop(&self) -> Duration;
}
