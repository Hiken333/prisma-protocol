//! `prism-quic` — the bridge between PRISM and the QUIC wire.
//!
//! * [`backend::QuicBackend`] abstracts the QUIC stack (real `quiche` behind the
//!   `quiche-backend` feature, plus an in-memory test backend).
//! * [`mcc`] implements Mirror-Cell Carrying: VPN packets as STREAM frame bodies
//!   with zero VPN-header overhead.
//! * [`datagram`] and [`send_loop`] assemble morph-padded datagrams and pace them
//!   according to the CDN profile and congestion controller.
//! * [`session`] derives all per-connection transport state from the TLS exporter.

pub mod backend;
pub mod datagram;
pub mod error;
pub mod mcc;
pub mod send_loop;
pub mod session;

#[cfg(feature = "transport-backend")]
pub mod transport_adapter;

#[cfg(feature = "quiche-backend")]
pub mod quiche_backend;

#[cfg(feature = "quiche-backend")]
pub mod agent_debug;

#[cfg(feature = "quiche-backend")]
pub mod live;

#[cfg(feature = "tunnel")]
pub mod bolt_tunnel;

#[cfg(feature = "tunnel")]
pub mod tunnel;

// Re-export the (forked) quiche so integration tests and binaries can drive the
// connection directly through the PRISM fork API.
#[cfg(feature = "quiche-backend")]
pub use quiche;

// In-memory backend for unit tests and downstream integration tests
// (`--features test-backend`). Never used in production.
#[cfg(any(test, feature = "test-backend"))]
pub mod testing;

pub use backend::{AckReport, QuicBackend};
pub use error::{QuicError, Result};
pub use mcc::{Cell, MccDecoder, MccEncoder};
pub use send_loop::{run_send_loop, Role, SendLoopCtx};
pub use session::{Direction, PrismSession};

#[cfg(feature = "transport-backend")]
pub use transport_adapter::QuicTransportAdapter;
