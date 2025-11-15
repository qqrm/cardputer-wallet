use alloc::{string::String, vec::Vec};

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
