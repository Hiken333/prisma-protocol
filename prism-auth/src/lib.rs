//! `prism-auth` — Reality-style passwordless authentication.
//!
//! * Client side: build the Reality ClientHello values (X25519 ephemeral +
//!   GREASE auth tag) and, behind the `boringssl` feature, install them onto a
//!   BoringSSL context so the on-wire fingerprint matches Chrome.
//! * Server side: parse the ClientHello, recompute the shadow shared secret and
//!   decide between accepting a PRISM session and proxying to the decoy.
//! * 0-RTT anti-replay via a rotating bloom filter.

pub mod client_hello;
pub mod error;
pub mod parse;
pub mod replay;
pub mod server;

pub use client_hello::{RealityClientHello, CHROME_GROUPS, GREASE_AUTH_EXT};
pub use error::AuthError;
pub use parse::{parse_client_hello, ClientHelloView};
pub use replay::ReplayFilter;
pub use server::{try_classify, AuthDecision, ShadowDetector};
