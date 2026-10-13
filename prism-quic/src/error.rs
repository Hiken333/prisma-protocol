use thiserror::Error;

#[derive(Debug, Error)]
pub enum QuicError {
    #[error("backend would block (no progress to make)")]
    Done,

    #[error("stream {0} is blocked by flow control")]
    StreamBlocked(u64),

    #[error("connection is closed")]
    Closed,

    #[error("buffer too small: need {need}, have {have}")]
    BufferTooSmall { need: usize, have: usize },

    #[error("backend error: {0}")]
    Backend(String),

    #[error("core error: {0}")]
    Core(#[from] prism_core::CoreError),
}

pub type Result<T> = std::result::Result<T, QuicError>;
