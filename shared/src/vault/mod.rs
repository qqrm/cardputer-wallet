//! Vault persistence primitives shared between the host CLI and firmware.
//!
//! The module encapsulates the sequential flash journal described in SPEC §6 and §7.
//! Plaintext [`JournalPage`](model::JournalPage) records mirror the vault entry structure
//! and are wrapped in AEAD envelopes before being pushed to flash via
//! [`sequential-storage`](https://docs.rs/sequential-storage).
//!
//! Sensitive fields such as entry passwords and TOTP secrets opt into `zeroize` so decrypted
//! buffers are cleared automatically once they drop out of scope.

pub mod cipher;
pub mod model;
pub mod storage;

pub use cipher::{EnvelopeAlgorithm, PageCipher};
pub use model::{
    EncryptedJournalPage, EntryUpdate, JOURNAL_AAD, JOURNAL_PAGE_VERSION, JournalOperation,
    JournalPage, JournalRecord, SecretString, TotpAlgorithm, TotpConfig, VaultEntry, VaultMetadata,
};
pub use storage::{VaultJournal, VaultStorageError};
