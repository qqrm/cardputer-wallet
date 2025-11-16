use alloc::{format, string::String};

use super::{SYNC_IDLE_STAGE, UiEffect, UiRuntime, UiScreen};
use crate::ui::{JournalAction, JournalEntryView, input::UiCommand, render::SyncView};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SyncState {
    pub(super) stage: String,
    pub(super) progress_percent: u8,
}

impl SyncState {
    pub(super) fn new() -> Self {
        Self {
            stage: String::from(SYNC_IDLE_STAGE),
            progress_percent: 0,
        }
    }
}

impl UiRuntime {
    pub(super) fn handle_sync(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::Back | UiCommand::GoHome => {
                self.set_screen(UiScreen::Home);
                UiEffect::None
            }
            UiCommand::Lock => {
                self.lock_runtime();
                UiEffect::None
            }
            _ => UiEffect::None,
        }
    }

    /// Update sync progress that will be reflected in the next render.
    pub fn update_sync_progress(&mut self, progress_percent: u8, stage: impl Into<String>) {
        self.sync.progress_percent = progress_percent;
        self.sync.stage = stage.into();
    }

    pub(super) fn render_sync(&self) -> SyncView {
        let journal = self.vault.journal();
        let stage = if journal.is_empty() {
            format!("{} (up to date)", self.sync.stage)
        } else {
            format!("{} ({} pending)", self.sync.stage, journal.len())
        };
        let hint = if journal.is_empty() {
            Some(String::from("Journal empty"))
        } else {
            Some(describe_journal_entry(&journal[0]))
        };

        SyncView {
            stage,
            progress_percent: self.sync.progress_percent,
            hint,
        }
    }
}

fn describe_journal_entry(entry: &JournalEntryView) -> String {
    let mut text = format!("{} {}", journal_action_label(entry.action), entry.entry_id);
    if let Some(description) = &entry.description {
        text.push_str(" – ");
        text.push_str(description);
    }
    if let Some(timestamp) = &entry.timestamp {
        text.push_str(" @ ");
        text.push_str(timestamp);
    }
    text
}

fn journal_action_label(action: JournalAction) -> &'static str {
    match action {
        JournalAction::Add => "Add",
        JournalAction::Update => "Update",
        JournalAction::Delete => "Delete",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_view_reflects_journal() {
        let journal = vec![JournalEntryView::new(
            "alpha",
            JournalAction::Update,
            Some(String::from("username")),
            Some(String::from("2024-01-10T00:00:00Z")),
        )];
        let entries = super::super::fixtures::sample_entries();
        let vault = super::super::fixtures::MemoryVault::with_journal(entries, journal);
        let mut ui = super::super::fixtures::build_runtime(vault);
        super::super::fixtures::press(&mut ui, crate::ui::input::PhysicalKey::Enter);
        super::super::fixtures::press(&mut ui, crate::ui::input::PhysicalKey::Sync);
        let frame = ui.render();
        match frame.content {
            crate::ui::render::ViewContent::Sync(sync) => {
                assert!(sync.stage.contains("pending"));
                assert!(sync.hint.unwrap().contains("Update"));
            }
            _ => panic!("expected sync view"),
        }
    }
}
