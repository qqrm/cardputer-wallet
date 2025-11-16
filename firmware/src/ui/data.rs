use alloc::{collections::BTreeMap, string::String, vec::Vec};

use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use shared::vault::SecretString;
use static_cell::StaticCell;

use super::{render::TotpWidget, state::EntrySummary};

/// Data model interface that surfaces entries and pending journal items for the UI layer.
pub trait VaultViewModel {
    /// Return the latest known entries sorted by recency.
    fn entries(&self) -> Vec<EntrySummary>;

    /// Fetch a single entry by identifier.
    fn entry(&self, id: &str) -> Option<EntrySummary>;

    /// Pending journal operations awaiting sync.
    fn journal(&self) -> Vec<JournalEntryView>;
}

/// Compact view of a journal entry exposed to the UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEntryView {
    pub entry_id: String,
    pub action: JournalAction,
    pub description: Option<String>,
    pub timestamp: Option<String>,
}

impl JournalEntryView {
    pub fn new(
        entry_id: impl Into<String>,
        action: JournalAction,
        description: Option<String>,
        timestamp: Option<String>,
    ) -> Self {
        Self {
            entry_id: entry_id.into(),
            action,
            description,
            timestamp,
        }
    }
}

/// Logical action recorded in the journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalAction {
    Add,
    Update,
    Delete,
}

/// Shared snapshot for presenting TOTP state and distributing codes to other subsystems.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpSnapshot {
    pub code: Option<String>,
    pub period: u8,
    pub remaining_ms: u32,
}

impl TotpSnapshot {
    pub fn empty(period: u8) -> Self {
        Self {
            code: None,
            period,
            remaining_ms: period as u32 * 1_000,
        }
    }

    pub fn to_widget(&self) -> TotpWidget {
        TotpWidget {
            code: self.code.clone(),
            seconds_remaining: core::cmp::min(self.remaining_ms / 1_000, self.period as u32) as u8,
            period: self.period,
        }
    }
}

/// Provider that synchronises TOTP state between the UI and HID subsystems.
pub trait TotpProvider {
    /// Select the entry whose TOTP configuration should drive generated codes.
    fn select_entry(&mut self, entry_id: Option<&str>);

    /// Snapshot of the active TOTP code and countdown.
    fn snapshot(&self) -> TotpSnapshot;

    /// Advance the countdown timer.
    fn tick(&mut self, elapsed_ms: u32);
}

fn vault_store() -> &'static Mutex<CriticalSectionRawMutex, VaultStore> {
    static STORE: StaticCell<Mutex<CriticalSectionRawMutex, VaultStore>> = StaticCell::new();
    STORE.init_with(|| Mutex::new(VaultStore::default()))
}

#[derive(Default)]
struct VaultStore {
    entries: Vec<EntrySummary>,
    journal: Vec<JournalEntryView>,
    secrets: BTreeMap<String, EntrySecret>,
}

impl VaultStore {
    fn replace(
        &mut self,
        entries: Vec<EntrySummary>,
        secrets: Vec<EntrySecretMaterial>,
        journal: Vec<JournalEntryView>,
    ) {
        self.entries = entries;
        self.journal = journal;
        self.secrets.clear();
        for secret in secrets {
            self.secrets.insert(
                secret.entry_id.clone(),
                EntrySecret {
                    username: secret.username,
                    password: secret.password,
                },
            );
        }
    }

    fn credentials(&self, entry_id: &str) -> Option<(String, String)> {
        self.secrets
            .get(entry_id)
            .map(|secret| (secret.username.clone(), secret.password.to_string()))
    }
}

#[derive(Clone)]
struct EntrySecret {
    username: String,
    password: SecretString,
}

/// Backing store for UI data hydrated from the synchronization subsystem.
pub struct SyncVaultViewModel {
    store: &'static Mutex<CriticalSectionRawMutex, VaultStore>,
}

impl SyncVaultViewModel {
    /// Construct a view model handle backed by the global store.
    pub fn from_system() -> Self {
        Self {
            store: vault_store(),
        }
    }

    /// Replace the cached entries, secrets, and pending journal with the provided snapshots.
    pub fn replace_entries(
        &self,
        entries: Vec<EntrySummary>,
        secrets: Vec<EntrySecretMaterial>,
        journal: Vec<JournalEntryView>,
    ) {
        self.store
            .lock(|store| store.replace(entries, secrets, journal));
    }

    /// Retrieve username/password pairs for the provided entry.
    pub fn entry_credentials(&self, entry_id: &str) -> Option<(String, String)> {
        self.store.lock(|store| store.credentials(entry_id))
    }
}

impl VaultViewModel for SyncVaultViewModel {
    fn entries(&self) -> Vec<EntrySummary> {
        self.store.lock(|store| store.entries.clone())
    }

    fn entry(&self, id: &str) -> Option<EntrySummary> {
        self.store
            .lock(|store| store.entries.iter().find(|entry| entry.id == id).cloned())
    }

    fn journal(&self) -> Vec<JournalEntryView> {
        self.store.lock(|store| store.journal.clone())
    }
}

/// Secrets captured from the vault that can be transmitted via HID.
#[derive(Clone)]
pub struct EntrySecretMaterial {
    pub entry_id: String,
    pub username: String,
    pub password: SecretString,
}
