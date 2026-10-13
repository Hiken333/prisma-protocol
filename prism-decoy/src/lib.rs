//! `prism-decoy` — active-probing resistance via transparent decoy proxying.
//!
//! When the server cannot authenticate a handshake (probe, replay, or a genuine
//! browser), it must behave *exactly* like the real decoy origin. This crate
//! provides byte-for-byte relays for the three probe surfaces (§3.3):
//!
//! * UDP/QUIC: forward the original Initial datagram to `decoy_origin:443` and
//!   splice the bidirectional flow.
//! * TCP/443: splice to the real nginx/caddy termination.
//! * QUIC Version Negotiation: reply with the decoy's advertised version list.
//!
//! Crucially, there is no PRISM-specific rejection: every failure path yields a
//! genuine decoy response.

pub mod error;
pub mod proxy;
pub mod version;

pub use error::DecoyError;
pub use proxy::DecoyProxy;
pub use version::version_negotiation;
