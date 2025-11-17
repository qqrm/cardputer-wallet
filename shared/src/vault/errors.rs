use core::fmt::{Debug, Display, Formatter};

/// Error emitted while encoding, decoding, or persisting journal pages.
///
/// Firmware re-exports this type as [`VaultStorageError`](crate::vault::VaultStorageError)
/// when it commits encrypted pages to flash, while the host CLI only relies on the
/// codec and nonce helpers that avoid any flash-specific requirements.
#[derive(Debug)]
pub enum JournalError<E>
where
    E: Debug,
{
    Storage(E),
    Codec(postcard::Error),
    Authentication,
    UnsupportedVersion(u16),
    NonceExhausted,
}

impl<E> Display for JournalError<E>
where
    E: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            JournalError::Storage(err) => write!(f, "storage error: {err:?}"),
            JournalError::Codec(err) => write!(f, "serialization error: {err}"),
            JournalError::Authentication => write!(f, "authentication failed"),
            JournalError::UnsupportedVersion(version) => {
                write!(f, "unsupported journal version {version}")
            }
            JournalError::NonceExhausted => write!(f, "nonce counter exhausted"),
        }
    }
}

impl<E> From<postcard::Error> for JournalError<E>
where
    E: Debug,
{
    fn from(value: postcard::Error) -> Self {
        JournalError::Codec(value)
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for JournalError<E> where E: Debug {}
