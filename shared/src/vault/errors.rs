use core::fmt::Debug;

/// Error emitted while encoding, decoding, or persisting journal pages.
///
/// Firmware re-exports this type as [`VaultStorageError`](crate::vault::VaultStorageError)
/// when it commits encrypted pages to flash, while the host CLI only relies on the
/// codec and nonce helpers that avoid any flash-specific requirements.
#[derive(Debug, thiserror::Error)]
pub enum JournalError<E>
where
    E: Debug,
{
    #[error("storage error: {0:?}")]
    Storage(E),
    #[error("serialization error: {0}")]
    Codec(#[from] postcard::Error),
    #[error("authentication failed")]
    Authentication,
    #[error("unsupported journal version {0}")]
    UnsupportedVersion(u16),
    #[error("nonce counter exhausted")]
    NonceExhausted,
}
