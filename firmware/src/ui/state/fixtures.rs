#![cfg(test)]

use alloc::{string::String, vec, vec::Vec};

use super::{
    DEFAULT_TOTP_PERIOD, EntrySummary, TotpProvider, UiCommand, UiEffect, UiRuntime, VaultViewModel,
};
use crate::crypto::{PinLockStatus, PinUnlockError};
use crate::ui::{
    JournalEntryView, TotpSnapshot,
    input::{KeyEvent, PhysicalKey},
    transport,
};

/// Ordering used for generated `last_used` timestamps in entry fixtures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DateOrder {
    /// Entries are ordered from most recently used to least (`2024-01-<count>` … `2024-01-01`).
    NewestFirst,
    /// Entries are ordered from least recently used to most (`2024-01-01` … `2024-01-<count>`).
    OldestFirst,
}

/// Parameters for constructing reusable entry fixtures across UI tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EntryFixtureConfig {
    pub count: usize,
    pub date_order: DateOrder,
    pub include_totp: bool,
}

impl EntryFixtureConfig {
    pub fn newest_first(count: usize, include_totp: bool) -> Self {
        Self {
            count,
            date_order: DateOrder::NewestFirst,
            include_totp,
        }
    }
}

impl Default for EntryFixtureConfig {
    fn default() -> Self {
        Self::newest_first(3, true)
    }
}

/// Generate deterministic entry fixtures for tests.
///
/// `last_used` values are assigned in chronological order to make sorting tests explicit: when
/// `date_order` is [`DateOrder::NewestFirst`], the first element is the most recent; when set to
/// [`DateOrder::OldestFirst`], the first element is the oldest. Setting `include_totp` attaches a
/// placeholder TOTP secret to the final entry so tests can toggle OTP availability per scenario.
pub(super) fn generate_entries(config: EntryFixtureConfig) -> Vec<EntrySummary> {
    const TITLES: [&str; 10] = [
        "Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Eta", "Theta", "Iota", "Kappa",
    ];

    let mut entries = Vec::with_capacity(config.count);
    for index in 0..config.count {
        let day = match config.date_order {
            DateOrder::NewestFirst => config.count.saturating_sub(index),
            DateOrder::OldestFirst => index + 1,
        };

        let title = TITLES
            .get(index)
            .map(|title| String::from(*title))
            .unwrap_or_else(|| format!("Entry {index}"));
        let id = title.to_ascii_lowercase();
        let totp = if config.include_totp && index + 1 == config.count {
            Some(format!("{id}-totp"))
        } else {
            None
        };

        entries.push(EntrySummary {
            id,
            title,
            username: format!("user{index}"),
            last_used: format!("2024-01-{day:02}"),
            totp,
            note: None,
        });
    }

    entries
}

/// Canonical sample entries shared by UI tests.
///
/// Entries are ordered from most recently used to least (`2024-01-03`, `2024-01-02`, `2024-01-01`)
/// so sort-by-recency assertions remain stable. The final entry includes a TOTP secret to exercise
/// OTP-aware rendering paths.
pub(super) fn sample_entries() -> Vec<EntrySummary> {
    let mut entries = generate_entries(EntryFixtureConfig::default());
    if let Some(entry) = entries.get_mut(1) {
        entry.note = Some(String::from("second"));
    }
    entries
}

pub(super) struct MemoryVault {
    entries: Vec<EntrySummary>,
    journal: Vec<JournalEntryView>,
}

impl MemoryVault {
    pub(super) fn new(entries: Vec<EntrySummary>) -> Self {
        Self {
            entries,
            journal: Vec::new(),
        }
    }

    pub(super) fn with_journal(entries: Vec<EntrySummary>, journal: Vec<JournalEntryView>) -> Self {
        Self { entries, journal }
    }
}

impl VaultViewModel for MemoryVault {
    fn entries(&self) -> Vec<EntrySummary> {
        self.entries.clone()
    }

    fn entry(&self, id: &str) -> Option<EntrySummary> {
        self.entries.iter().find(|entry| entry.id == id).cloned()
    }

    fn journal(&self) -> Vec<JournalEntryView> {
        self.journal.clone()
    }
}

#[derive(Clone)]
pub(super) struct NullTotpProvider;

impl TotpProvider for NullTotpProvider {
    fn select_entry(&mut self, _entry_id: Option<&str>) {}

    fn snapshot(&self) -> TotpSnapshot {
        TotpSnapshot::empty(DEFAULT_TOTP_PERIOD)
    }

    fn sync_time(&mut self, _now_ms: u64) {}

    fn tick(&mut self, _elapsed_ms: u32) {}
}

pub(super) fn build_runtime(vault: MemoryVault) -> UiRuntime {
    transport::reset();
    UiRuntime::new(Box::new(vault), Box::new(NullTotpProvider))
}

fn unlocked_status() -> PinLockStatus {
    PinLockStatus {
        consecutive_failures: 0,
        total_failures: 0,
        backoff_remaining_ms: None,
        wipe_required: false,
    }
}

pub(super) struct SystemAdapter {
    unlock_status: PinLockStatus,
    unlock_response: Result<(), PinUnlockError>,
}

impl SystemAdapter {
    pub(super) fn new() -> Self {
        Self {
            unlock_status: unlocked_status(),
            unlock_response: Ok(()),
        }
    }

    pub(super) fn with_unlock_status(mut self, status: PinLockStatus) -> Self {
        self.unlock_status = status;
        self
    }

    pub(super) fn with_unlock_error(mut self, error: PinUnlockError) -> Self {
        self.unlock_response = Err(error);
        self
    }

    pub(super) fn dispatch(&self, ui: &mut UiRuntime, effect: UiEffect) {
        match effect {
            UiEffect::UnlockRequested { .. } => match &self.unlock_response {
                Ok(()) => ui.register_unlock_success(self.unlock_status),
                Err(error) => ui.register_unlock_failure(self.unlock_status, error),
            },
            _ => {}
        }
    }
}

impl Default for SystemAdapter {
    fn default() -> Self {
        Self::new()
    }
}

pub(super) fn apply(ui: &mut UiRuntime, adapter: &SystemAdapter, command: UiCommand) {
    let effect = ui.apply_command(command);
    adapter.dispatch(ui, effect);
}

pub(super) fn press(ui: &mut UiRuntime, adapter: &SystemAdapter, key: PhysicalKey) {
    let effect = ui.handle_key_event(KeyEvent::pressed(key));
    adapter.dispatch(ui, effect);
}

pub(super) const TEST_PIN: &str = "123456";

pub(super) fn submit_pin(ui: &mut UiRuntime, adapter: &SystemAdapter, pin: &str) {
    for digit in pin.chars() {
        apply(ui, adapter, UiCommand::InsertChar(digit));
    }
    apply(ui, adapter, UiCommand::Activate);
}
