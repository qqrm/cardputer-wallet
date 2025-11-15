//! Compatibility shim that re-exports the `vault-core` crate as `shared::vault`.
//!
//! Existing code can continue to access models and storage primitives using the
//! legacy module path while the actual implementation lives in `vault-core`.
pub use vault_core::{
    EncryptedJournalPage, EntryUpdate, EnvelopeAlgorithm, JOURNAL_AAD, JOURNAL_PAGE_VERSION,
    JournalOperation, JournalPage, JournalRecord, LegacyField, PageCipher, SecretString,
    TotpAlgorithm, TotpConfig, VaultEntry, VaultJournal, VaultMetadata, VaultStorageError,
};
pub use vault_core::{cipher, model, storage};
