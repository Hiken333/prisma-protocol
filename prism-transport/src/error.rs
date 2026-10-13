use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("core crypto error: {0}")]
    Core(#[from] prism_core::CoreError),

    #[error("auth error: {0}")]
    Auth(#[from] prism_auth::AuthError),

    #[error("AEAD seal/open failed")]
    Aead,

    #[error("malformed datagram: {0}")]
    Malformed(String),

    #[error("handshake rejected (not a valid PRISM client)")]
    Rejected,

    #[error("handshake timed out")]
    Timeout,

    #[error("connection closed")]
    Closed,
}

pub type Result<T> = std::result::Result<T, TransportError>;
