//! `prism-eval` — indistinguishability evaluation toolkit.
//!
//! Compares a PRISM packet capture against a Chrome HTTP/3 baseline to the same
//! decoy origin, computing:
//! * KL divergence of the datagram-size distribution `P(size)`,
//! * KL divergence of the inter-arrival-time distribution `P(Δt)`,
//! * Shannon entropy of payload samples,
//! and (via the external JA4 tooling described in the README) verifies that the
//! TLS handshake fingerprint matches the frozen `chrome_124` profile.

pub mod metrics;
pub mod sample;

pub use metrics::{
    chi_squared, kl_divergence, normalize_smoothed, shannon_entropy, Comparison, Thresholds,
};
pub use sample::{CaptureSummary, FlowDirection};
