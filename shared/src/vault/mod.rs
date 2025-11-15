//! Vault persistence primitives shared between the host CLI and firmware.
//!
//! The module encapsulates the sequential flash journal described in SPEC §6 and §7.
//! Plaintext [`JournalPage`](model::JournalPage) records mirror the vault entry structure
//! and are wrapped in AEAD envelopes before being pushed to flash via
//! [`sequential-storage`](https://docs.rs/sequential-storage).
//!
//! Firmware links the [`flash`] module to talk to NOR flash controllers, while the host CLI
//! sticks to the pure-Rust [`journal`] helpers so it can stay `std`-only.
//!
//! Sensitive fields such as entry passwords and TOTP secrets opt into `zeroize` so decrypted
//! buffers are cleared automatically once they drop out of scope.

pub mod cipher;
mod errors;
pub mod flash;
pub mod journal;
pub mod model;
mod nonce;

pub use cipher::{EnvelopeAlgorithm, PageCipher};
pub use flash::VaultStorageError;
pub use journal::VaultJournal;
pub use model::{
    EncryptedJournalPage, EntryUpdate, JOURNAL_AAD, JOURNAL_PAGE_VERSION, JournalOperation,
    JournalPage, JournalRecord, LegacyField, SecretString, TotpAlgorithm, TotpConfig, VaultEntry,
    VaultMetadata,
};
