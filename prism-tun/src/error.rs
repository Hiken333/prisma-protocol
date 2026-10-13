use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TUN device unavailable (build with --features device)")]
    Unavailable,

    #[error("packet too short to classify ({0} bytes)")]
    ShortPacket(usize),
}
