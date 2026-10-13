//! `prism-core` — shared types, crypto primitives, exporter derivation and the
//! seeded PRNG used across the PRISM workspace.
//!
//! Nothing in this crate touches the wire-visible TLS handshake (that is owned
//! by BoringSSL inside the QUIC backend). It only provides the offline crypto
//! and deterministic state derivation that PRISM layers depend on.

pub mod config;
pub mod crypto;
pub mod error;
pub mod prng;
pub mod secret;

pub use config::PrismConfig;
pub use crypto::{ct_eq, hkdf_expand_label, hmac_sha256, SharedSecret, X25519Public, X25519Secret};
pub use error::{CoreError, Result};
pub use prng::PrismRng;
pub use secret::{PrismExporter, EXPORTER_LEN};

/// Default MTU assumption for size clamping (matches typical Ethernet path MTU).
pub const DEFAULT_MTU: usize = 1400;

/// Minimum on-wire overhead of a PRISM short-header packet (§5.2):
/// 1 (header) + 8 (CID) + 1 (pn) + 16 (AEAD tag) = 26 bytes.
pub const WIRE_OVERHEAD: usize = 26;
