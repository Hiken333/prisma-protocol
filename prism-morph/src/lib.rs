//! `prism-morph` — CDN Profile Replay (CPR) morphing engine.
//!
//! Samples packet sizes, inter-arrival times and burst patterns from a
//! histogram profile captured from the real decoy origin, using the
//! deterministic exporter-seeded PRNG. Also provides entropy regularization and
//! throttle-driven profile adaptation.

pub mod adapt;
pub mod engine;
pub mod entropy;
pub mod error;
pub mod histogram;
pub mod profile;

pub use adapt::{Adaptation, ThrottleDetector};
pub use engine::MorphEngine;
pub use entropy::{EntropyRegulator, DEFAULT_DUMMY_PERIOD};
pub use error::MorphError;
pub use histogram::{Bucket, Histogram};
pub use profile::{BurstPattern, CdnProfile};
