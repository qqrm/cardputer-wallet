use thiserror::Error;

#[derive(Debug, Error)]
pub enum SharedError {
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_cbor::Error),
    #[error("transport error: {0}")]
    Transport(String),
}
