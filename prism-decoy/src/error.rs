use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecoyError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid decoy origin address: {0}")]
    Address(String),
}
