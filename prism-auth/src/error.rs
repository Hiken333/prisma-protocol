use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("core crypto error: {0}")]
    Core(#[from] prism_core::CoreError),

    #[error("ClientHello parse error: {0}")]
    Parse(String),

    #[error("no X25519 key_share entry present in ClientHello")]
    MissingKeyShare,

    #[error("missing GREASE auth extension (0x0A0A)")]
    MissingAuthTag,

    #[error("BoringSSL extension installation failed: {0}")]
    Boring(String),
}
