use alloc::{format, string::String};

use crate::ui::{JournalAction, JournalEntryView, input::UiCommand, render::SyncView};

use super::{UiEffect, UiRuntime, UiScreen};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncState {
    pub stage: String,
    pub progress_percent: u8,
}

impl UiRuntime {
    pub(super) fn handle_sync(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::Back | UiCommand::GoHome => {
                self.set_screen(UiScreen::Home);
                UiEffect::None
            }
            UiCommand::Lock => {
                self.set_screen(UiScreen::Lock);
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
    use super::super::test_support::{MemoryVault, build_runtime, sample_entries};
    use super::*;
    use crate::ui::input::UiCommand;

    #[test]
    fn update_sync_progress_changes_stage() {
        let mut ui = build_runtime(MemoryVault::new(sample_entries()));
        ui.update_sync_progress(42, "Downloading");
        let view = ui.render_sync();
        assert!(view.stage.contains("Downloading"));
        assert_eq!(view.progress_percent, 42);
    }

    #[test]
    fn handle_sync_back_returns_home() {
        let mut ui = build_runtime(MemoryVault::new(sample_entries()));
        ui.set_screen(UiScreen::Sync);
        let effect = ui.handle_sync(UiCommand::Back);
        assert_eq!(ui.screen(), UiScreen::Home);
        assert!(matches!(effect, UiEffect::None));
    }
}
