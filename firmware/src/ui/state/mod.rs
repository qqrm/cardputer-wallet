use alloc::{boxed::Box, string::String};
use zeroize::Zeroize;

use super::{
    TotpProvider, VaultViewModel,
    input::{KeyEvent, Keymap, UiCommand},
    render::{Frame, ViewContent},
    transport,
};
use crate::crypto::{PinLockStatus, PinUnlockError};

use entry::{EditState, EntryState, HomeState, SettingsState};
use lock::LockState;
use sync::SyncState;
use widgets::default_settings_options;

pub(super) const SYNC_IDLE_STAGE: &str = "Idle";

mod entry;
mod lock;
mod sync;
mod widgets;

/// High level UI screens supported by the device workflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiScreen {
    Lock,
    Home,
    Entry,
    Edit,
    Settings,
    Sync,
}

/// Message emitted when the UI requests a system side effect.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum UiEffect {
    #[default]
    None,
    StartSync,
    BeginEdit {
        entry_id: String,
    },
    SaveEdit {
        entry_id: String,
    },
    CancelEdit {
        entry_id: String,
    },
    UnlockRequested {
        pin: String,
    },
}

/// Entry metadata used to populate views.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntrySummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub last_used: String,
    pub totp: Option<String>,
    pub note: Option<String>,
}

/// Aggregate runtime for UI navigation and rendering.
pub struct UiRuntime {
    screen: UiScreen,
    keymap: Keymap,
    lock: LockState,
    home: HomeState,
    entry: Option<EntryState>,
    edit: Option<EditState>,
    settings: SettingsState,
    sync: SyncState,
    vault: Box<dyn VaultViewModel>,
    totp: Box<dyn TotpProvider>,
    show_hints: bool,
}

impl UiRuntime {
    /// Construct a new UI runtime backed by the provided data sources.
    pub fn new(vault: Box<dyn VaultViewModel>, mut totp: Box<dyn TotpProvider>) -> Self {
        totp.select_entry(None);

        Self {
            screen: UiScreen::Lock,
            keymap: Keymap::default(),
            lock: LockState::new(),
            home: HomeState::new(),
            entry: None,
            edit: None,
            settings: SettingsState::new(default_settings_options()),
            sync: SyncState::new(),
            vault,
            totp,
            show_hints: true,
        }
    }

    /// Retrieve the active screen identifier.
    pub fn screen(&self) -> UiScreen {
        self.screen
    }

    /// Access the mutable keymap for custom bindings.
    pub fn keymap_mut(&mut self) -> &mut Keymap {
        &mut self.keymap
    }

    fn set_screen(&mut self, screen: UiScreen) {
        self.screen = screen;
        self.sync_totp_selection();
    }

    /// Handle a raw keyboard event.
    pub fn handle_key_event(&mut self, event: KeyEvent) -> UiEffect {
        if let Some(command) = self.keymap.resolve(&event) {
            self.apply_command(command)
        } else {
            UiEffect::None
        }
    }

    /// Apply a high level command to the state machine.
    pub fn apply_command(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::ToggleHints => {
                self.show_hints = !self.show_hints;
                UiEffect::None
            }
            UiCommand::Lock => {
                self.lock_runtime();
                UiEffect::None
            }
            other => self.route_command(other),
        }
    }

    fn route_command(&mut self, command: UiCommand) -> UiEffect {
        match self.screen {
            UiScreen::Lock => self.handle_lock(command),
            UiScreen::Home => self.handle_home(command),
            UiScreen::Entry => self.handle_entry(command),
            UiScreen::Edit => self.handle_edit(command),
            UiScreen::Settings => self.handle_settings(command),
            UiScreen::Sync => self.handle_sync(command),
        }
    }

    /// Align time-aware widgets with the system clock.
    pub fn sync_time(&mut self, now_ms: u64) {
        self.totp.sync_time(now_ms);
    }

    /// Advance time for the TOTP countdown.
    pub fn tick(&mut self, elapsed_ms: u32) {
        self.lock.tick(elapsed_ms);
        self.totp.tick(elapsed_ms);
    }

    /// Render the current UI frame.
    pub fn render(&self) -> Frame {
        let transport = transport::snapshot();
        let content = match self.screen {
            UiScreen::Lock => ViewContent::Lock(self.render_lock()),
            UiScreen::Home => ViewContent::Home(self.render_home()),
            UiScreen::Entry => ViewContent::Entry(self.render_entry()),
            UiScreen::Edit => ViewContent::Edit(self.render_edit()),
            UiScreen::Settings => ViewContent::Settings(self.render_settings()),
            UiScreen::Sync => ViewContent::Sync(self.render_sync()),
        };

        Frame {
            transport,
            content,
            hint_bar: self.hint_bar(),
        }
    }

    /// Update lock UI after a successful unlock.
    pub fn register_unlock_success(&mut self, status: PinLockStatus) {
        self.lock.record_success(status);
        self.set_screen(UiScreen::Home);
    }

    /// Update lock UI when unlocking fails.
    pub fn register_unlock_failure(&mut self, status: PinLockStatus, error: &PinUnlockError) {
        self.lock.record_failure(status, error);
        self.set_screen(UiScreen::Lock);
    }

    /// Synchronise the lock indicators without changing screens.
    pub fn sync_lock_status(&mut self, status: PinLockStatus) {
        self.lock.sync_status(status);
    }

    fn lock_runtime(&mut self) {
        self.zeroize_home_filters();
        self.reset_entry_and_edit_state();
        self.reset_selection_indices();
        self.reset_sync_status();
        self.totp.select_entry(None);
        self.set_screen(UiScreen::Lock);
    }

    fn zeroize_home_filters(&mut self) {
        self.home.search_query.zeroize();
        self.home.search_query.clear();
        self.home.search_focus = true;
        self.home.selected_recent = 0;
    }

    fn reset_entry_and_edit_state(&mut self) {
        if let Some(mut edit) = self.edit.take() {
            for field in edit.fields.iter_mut() {
                field.value.zeroize();
            }
        }
        self.entry = None;
    }

    fn reset_selection_indices(&mut self) {
        self.settings.selected = 0;
    }

    fn reset_sync_status(&mut self) {
        self.sync.stage.zeroize();
        self.sync.stage = String::from(SYNC_IDLE_STAGE);
        self.sync.progress_percent = 0;
    }
}

#[cfg(any(test, feature = "ui-tests"))]
pub const DEFAULT_TOTP_PERIOD: u8 = 30;

#[cfg(any(test, feature = "ui-tests"))]
pub mod fixtures;

#[cfg(test)]
mod tests {
    use super::{UiCommand, UiScreen, fixtures};
    use crate::ui::render::ViewContent;

    #[test]
    fn relock_clears_home_search_and_selection() {
        let vault = fixtures::MemoryVault::new(fixtures::sample_entries());
        let mut ui = fixtures::build_runtime(vault);
        let adapter = fixtures::SystemAdapter::default();

        fixtures::submit_pin(&mut ui, &adapter, fixtures::TEST_PIN);
        fixtures::apply(&mut ui, &adapter, UiCommand::InsertChar('a'));
        fixtures::apply(&mut ui, &adapter, UiCommand::InsertChar('l'));
        fixtures::apply(&mut ui, &adapter, UiCommand::MoveSelectionDown);
        fixtures::apply(&mut ui, &adapter, UiCommand::Lock);
        assert_eq!(ui.screen(), UiScreen::Lock);

        fixtures::submit_pin(&mut ui, &adapter, fixtures::TEST_PIN);
        let frame = ui.render();

        match frame.content {
            ViewContent::Home(home) => {
                assert!(home.search.query.is_empty());
                assert_eq!(home.recent.selected, Some(0));
            }
            other => panic!("expected home view after unlock, got {other:?}"),
        }
    }

    #[test]
    fn relock_drops_edit_buffers() {
        let vault = fixtures::MemoryVault::new(fixtures::sample_entries());
        let mut ui = fixtures::build_runtime(vault);
        let adapter = fixtures::SystemAdapter::default();

        fixtures::submit_pin(&mut ui, &adapter, fixtures::TEST_PIN);
        fixtures::apply(&mut ui, &adapter, UiCommand::EditEntry);
        fixtures::apply(&mut ui, &adapter, UiCommand::InsertChar('x'));
        fixtures::apply(&mut ui, &adapter, UiCommand::Lock);
        assert_eq!(ui.screen(), UiScreen::Lock);

        fixtures::submit_pin(&mut ui, &adapter, fixtures::TEST_PIN);
        fixtures::apply(&mut ui, &adapter, UiCommand::EditEntry);
        let frame = ui.render();

        match frame.content {
            ViewContent::Edit(edit) => {
                assert!(!edit.form.fields.is_empty());
                assert_eq!(edit.form.fields[0].value, String::from("Alpha"));
            }
            other => panic!("expected edit view after relaunch, got {other:?}"),
        }
    }
}
