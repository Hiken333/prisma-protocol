//! PRISM BOLT MVP — parallel encrypted UDP lanes for bulk IP relay.
//!
//! After the Reality/QUIC handshake both peers derive lane keys from the TLS
//! exporter and switch the data plane to fixed-size AES-GCM frames on dedicated
//! UDP ports (base+1, base+2). QUIC stays alive for keepalive only.

pub mod aggregator;
pub mod crypto;
pub mod frame;
pub mod lanes;
pub mod pacer;
pub mod session;

pub use aggregator::PacketAggregator;
pub use crypto::{BoltCipher, BoltDirection};
pub use frame::{wire_layout_from_env, BoltFrame, WireLayout, WIRE_SIZE, WIRE_SIZE_MAX};
pub use lanes::BoltLanes;
pub use pacer::{bolt_lanes_from_env, bolt_mbps_from_env, bolt_turbo_from_env, BrutalPacer};
pub use session::BoltSession;
