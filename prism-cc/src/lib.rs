//! `prism-cc` — BBRv3-PRISM congestion control.
//!
//! The controller is deterministically seeded from the TLS exporter, runs the
//! standard BBR ACK cycle (windowed `BtlBw` / `RTprop`, pacing-gain schedule),
//! falls back to a Hysteria-2-style brutal mode under loss, and integrates a
//! `MorphBudget` that forces CDN-like pauses.

pub mod bbr_prism;
pub mod filters;
pub mod gate;
pub mod morph_budget;
pub mod traits;

pub use bbr_prism::{BbrPhase, BbrPrism};
pub use gate::CcGate;
pub use morph_budget::MorphBudget;
pub use traits::{Acked, CongestionControl, Lost, SentPacket};
