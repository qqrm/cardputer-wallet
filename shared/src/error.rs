use crate::schema::CodecError;
use alloc::string::String;
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SharedError {
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),
    #[error("transport error: {0}")]
    Transport(String),
}

impl From<io::Error> for SharedError {
    fn from(value: io::Error) -> Self {
        SharedError::Transport(value.to_string())
    }
}
