use alloc::{boxed::Box, string::String, vec};

use super::{
    TotpProvider, VaultViewModel,
    input::{KeyEvent, Keymap, UiCommand},
    render::{Frame, HintBar, HintItem, ViewContent},
    transport,
};

mod entry;
mod lock;
mod sync;
mod widgets;

pub use entry::{EditState, EntryState};
pub use lock::LockState;
pub use sync::SyncState;
use widgets::default_settings_options;
pub use widgets::{HomeState, SettingsState};

pub const MIN_SEARCH_LEN: usize = 2;
#[cfg(test)]
const DEFAULT_TOTP_PERIOD: u8 = 30;

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
            lock: LockState {
                remaining_attempts: Some(10),
            },
            home: HomeState {
                search_query: String::new(),
                search_focus: true,
                selected_recent: 0,
            },
            entry: None,
            edit: None,
            settings: SettingsState {
                options: default_settings_options(),
                selected: 0,
            },
            sync: SyncState {
                stage: String::from("Idle"),
                progress_percent: 0,
            },
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
                self.set_screen(UiScreen::Lock);
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

    fn selected_entry_id(&self) -> Option<String> {
        self.visible_entries()
            .get(self.home.selected_recent)
            .map(|entry| entry.id.clone())
    }

    fn active_entry_id(&self) -> Option<String> {
        self.entry
            .as_ref()
            .map(|entry| entry.entry_id.clone())
            .or_else(|| self.selected_entry_id())
    }

    fn sync_totp_selection(&mut self) {
        let target = match self.screen {
            UiScreen::Entry => self.entry.as_ref().and_then(|state| {
                self.vault
                    .entry(&state.entry_id)
                    .filter(|entry| entry.totp.is_some())
                    .map(|entry| entry.id)
            }),
            UiScreen::Home => self
                .visible_entries()
                .get(self.home.selected_recent)
                .filter(|entry| entry.totp.is_some())
                .map(|entry| entry.id.clone()),
            _ => None,
        };

        self.totp.select_entry(target.as_deref());
    }

    /// Advance time for the TOTP countdown.
    pub fn tick(&mut self, elapsed_ms: u32) {
        self.totp.tick(elapsed_ms);
    }

    fn hint_bar(&self) -> HintBar {
        if !self.show_hints {
            return HintBar::new(vec![]);
        }

        let hints = match self.screen {
            UiScreen::Lock => vec![
                HintItem::new("Enter", "Unlock"),
                HintItem::new("Fn+L", "Lock"),
            ],
            UiScreen::Home => vec![
                HintItem::new("Enter", "Open"),
                HintItem::new("E", "Edit"),
                HintItem::new("Fn+S", "Sync"),
                HintItem::new("Fn+L", "Lock"),
            ],
            UiScreen::Entry => vec![
                HintItem::new("Esc", "Back"),
                HintItem::new("E", "Edit"),
                HintItem::new("Fn+S", "Sync"),
            ],
            UiScreen::Edit => vec![
                HintItem::new("Enter", "Save"),
                HintItem::new("Esc", "Cancel"),
                HintItem::new("Tab", "Next field"),
            ],
            UiScreen::Settings => vec![
                HintItem::new("Esc", "Home"),
                HintItem::new("Enter", "Select"),
                HintItem::new("Fn+L", "Lock"),
            ],
            UiScreen::Sync => vec![HintItem::new("Esc", "Home"), HintItem::new("Fn+L", "Lock")],
        };

        HintBar::new(hints)
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
}

#[cfg(test)]
pub(crate) mod test_support {
    use alloc::{boxed::Box, string::String, vec::Vec};

    use crate::ui::{JournalEntryView, TotpProvider, TotpSnapshot, VaultViewModel, transport};

    use super::{DEFAULT_TOTP_PERIOD, EntrySummary, UiRuntime};

    #[derive(Clone)]
    pub struct NullTotpProvider;

    impl TotpProvider for NullTotpProvider {
        fn select_entry(&mut self, _entry_id: Option<&str>) {}

        fn snapshot(&self) -> TotpSnapshot {
            TotpSnapshot::empty(DEFAULT_TOTP_PERIOD)
        }

        fn tick(&mut self, _elapsed_ms: u32) {}
    }

    #[derive(Clone)]
    pub struct MemoryVault {
        pub entries: Vec<EntrySummary>,
        pub journal: Vec<JournalEntryView>,
    }

    impl MemoryVault {
        pub fn new(entries: Vec<EntrySummary>) -> Self {
            Self {
                entries,
                journal: Vec::new(),
            }
        }

        pub fn with_journal(entries: Vec<EntrySummary>, journal: Vec<JournalEntryView>) -> Self {
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

    pub fn sample_entries() -> Vec<EntrySummary> {
        vec![
            EntrySummary {
                id: String::from("alpha"),
                title: String::from("Atlas Account"),
                username: String::from("atlas@example.com"),
                last_used: String::from("2024-01-03"),
                totp: Some(String::from("has-totp")),
                note: Some(String::from("primary account")),
            },
            EntrySummary {
                id: String::from("beta"),
                title: String::from("Beta Service"),
                username: String::from("beta@example.com"),
                last_used: String::from("2024-01-02"),
                totp: None,
                note: None,
            },
            EntrySummary {
                id: String::from("gamma"),
                title: String::from("Gamma Portal"),
                username: String::from("gamma@example.com"),
                last_used: String::from("2024-01-01"),
                totp: None,
                note: None,
            },
        ]
    }

    pub fn build_runtime(vault: MemoryVault) -> UiRuntime {
        transport::reset();
        UiRuntime::new(Box::new(vault), Box::new(NullTotpProvider))
    }
}

#[cfg(test)]
mod tests {
    use crate::ui::{
        JournalAction, JournalEntryView,
        input::{KeyEvent, PhysicalKey},
        render::ViewContent,
        transport,
    };

    use super::test_support::{MemoryVault, build_runtime, sample_entries};

    #[test]
    fn hint_bar_reflects_active_screen() {
        transport::reset();
        let mut ui = build_runtime(MemoryVault::new(sample_entries()));

        let assert_hint = |ui: &super::UiRuntime, expected: &str| {
            let frame = ui.render();
            assert!(
                frame
                    .hint_bar
                    .hints
                    .iter()
                    .any(|hint| hint.action.contains(expected)),
                "missing {expected} hint"
            );
        };

        assert_hint(&ui, "Unlock");
        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Enter));
        assert_hint(&ui, "Open");
        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Enter));
        assert_hint(&ui, "Edit");
        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Edit));
        assert_hint(&ui, "Save");
        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Settings));
        assert_hint(&ui, "Select");
        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Sync));
        assert_hint(&ui, "Lock");
    }

    #[test]
    fn recent_selection_moves_with_arrows() {
        transport::reset();
        let mut ui = build_runtime(MemoryVault::new(sample_entries()));
        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Enter));
        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::ArrowDown));
        let frame = ui.render();
        match frame.content {
            ViewContent::Home(home) => {
                assert_eq!(home.recent.selected, Some(1));
            }
            _ => panic!("expected home view"),
        }
    }

    #[test]
    fn search_results_follow_spec_sorting() {
        transport::reset();
        let mut entries = vec![
            super::EntrySummary {
                id: String::from("alpha"),
                title: String::from("Alpha"),
                username: String::from("admin"),
                last_used: String::from("2024-01-03"),
                totp: None,
                note: None,
            },
            super::EntrySummary {
                id: String::from("alpine"),
                title: String::from("Alpine"),
                username: String::from("ops"),
                last_used: String::from("2024-01-02"),
                totp: None,
                note: None,
            },
            super::EntrySummary {
                id: String::from("gamma"),
                title: String::from("Gamma"),
                username: String::from("alx"),
                last_used: String::from("2024-01-10"),
                totp: None,
                note: None,
            },
            super::EntrySummary {
                id: String::from("omega"),
                title: String::from("Omega"),
                username: String::from("user"),
                last_used: String::from("2024-02-01"),
                totp: None,
                note: None,
            },
        ];
        entries.extend(sample_entries());
        let mut ui = build_runtime(MemoryVault::new(entries));
        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Enter));
        ui.home.search_query = String::from("al");
        let frame = ui.render();
        match frame.content {
            ViewContent::Home(home) => {
                let titles: Vec<_> = home
                    .recent
                    .entries
                    .iter()
                    .map(|item| item.title.clone())
                    .collect();
                assert_eq!(titles[0], "Alpha");
                assert_eq!(titles[1], "Alpine");
                assert_eq!(titles[2], "Gamma");
            }
            _ => panic!("expected home view"),
        }
    }

    #[test]
    fn sync_view_reflects_journal() {
        transport::reset();
        let journal = vec![JournalEntryView::new(
            "alpha",
            JournalAction::Update,
            Some(String::from("username")),
            Some(String::from("2024-01-10T00:00:00Z")),
        )];
        let mut ui = build_runtime(MemoryVault::with_journal(sample_entries(), journal));
        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Enter));
        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Sync));
        let frame = ui.render();
        match frame.content {
            ViewContent::Sync(sync) => {
                assert!(sync.stage.contains("pending"));
                assert!(sync.hint.unwrap().contains("Update"));
            }
            _ => panic!("expected sync view"),
        }
    }
}
