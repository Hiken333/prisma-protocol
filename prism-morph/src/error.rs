use thiserror::Error;

#[derive(Debug, Error)]
pub enum MorphError {
    #[error("failed to load CDN profile: {0}")]
    Load(String),

    #[error("failed to parse CDN profile: {0}")]
    Parse(String),
}
