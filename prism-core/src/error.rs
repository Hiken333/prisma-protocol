//! Shared error type for the PRISM core crate.

use thiserror::Error;

/// Errors raised by core crypto / key-schedule operations.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("HKDF expand failed (output too long)")]
    HkdfExpand,

    #[error("TLS exporter is unavailable before handshake completion")]
    ExporterUnavailable,

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("hex decode error: {0}")]
    HexDecode(String),
}

/// Convenience alias used throughout the core crate.
pub type Result<T> = std::result::Result<T, CoreError>;
