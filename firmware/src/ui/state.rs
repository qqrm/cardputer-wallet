use alloc::{string::String, vec, vec::Vec};
use core::cmp;

use super::{
    input::{KeyEvent, Keymap, UiCommand},
    render::{
        EditView, EntryDetails, EntryView, FormField, FormWidget, Frame, HintBar, HintItem,
        HomeView, LockView, RecentList, RecentListItem, SearchWidget, SettingsItem, SettingsView,
        SyncView, TotpWidget, ViewContent,
    },
    transport,
};

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UiEffect {
    None,
    StartSync,
    BeginEdit { entry_id: String },
    SaveEdit { entry_id: String },
    CancelEdit { entry_id: String },
}

impl Default for UiEffect {
    fn default() -> Self {
        UiEffect::None
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct HomeState {
    search_query: String,
    search_focus: bool,
    selected_recent: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EntryState {
    entry_id: String,
    hint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EditState {
    entry_id: String,
    fields: Vec<FormField>,
    active_index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SettingsState {
    options: Vec<SettingsItem>,
    selected: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SyncState {
    stage: String,
    progress_percent: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LockState {
    remaining_attempts: Option<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TotpState {
    code: Option<String>,
    period: u8,
    remaining_ms: u32,
}

impl TotpState {
    fn new(period: u8) -> Self {
        Self {
            code: None,
            period,
            remaining_ms: period as u32 * 1_000,
        }
    }

    fn seconds_remaining(&self) -> u8 {
        cmp::min(self.remaining_ms / 1_000, self.period as u32) as u8
    }

    fn tick(&mut self, elapsed_ms: u32) {
        if elapsed_ms >= self.remaining_ms {
            self.remaining_ms = self.period as u32 * 1_000;
        } else {
            self.remaining_ms -= elapsed_ms;
        }
    }

    fn widget(&self) -> TotpWidget {
        TotpWidget {
            code: self.code.clone(),
            seconds_remaining: self.seconds_remaining(),
            period: self.period,
        }
    }
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
    recents: Vec<EntrySummary>,
    totp: TotpState,
    show_hints: bool,
}

impl UiRuntime {
    /// Construct a new UI runtime seeded with the provided recent entries.
    pub fn new(recents: Vec<EntrySummary>) -> Self {
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
            recents,
            totp: TotpState::new(30),
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
                self.screen = UiScreen::Lock;
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

    fn handle_lock(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::Activate => {
                self.screen = UiScreen::Home;
                UiEffect::None
            }
            UiCommand::Back => UiEffect::None,
            UiCommand::GoHome => {
                self.screen = UiScreen::Home;
                UiEffect::None
            }
            UiCommand::FocusSearch => {
                self.screen = UiScreen::Home;
                self.home.search_focus = true;
                UiEffect::None
            }
            _ => UiEffect::None,
        }
    }

    fn handle_home(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::Activate => {
                if let Some(entry) = self.selected_entry_id() {
                    self.open_entry(entry)
                } else {
                    UiEffect::None
                }
            }
            UiCommand::EditEntry => {
                if let Some(entry) = self.selected_entry_id() {
                    self.enter_edit(entry)
                } else {
                    UiEffect::None
                }
            }
            UiCommand::OpenSettings => {
                self.screen = UiScreen::Settings;
                UiEffect::None
            }
            UiCommand::StartSync => {
                self.screen = UiScreen::Sync;
                UiEffect::StartSync
            }
            UiCommand::MoveSelectionUp | UiCommand::MoveSelectionLeft => {
                self.move_recent_selection(-1);
                UiEffect::None
            }
            UiCommand::MoveSelectionDown | UiCommand::MoveSelectionRight => {
                self.move_recent_selection(1);
                UiEffect::None
            }
            UiCommand::FocusSearch => {
                self.home.search_focus = true;
                UiEffect::None
            }
            UiCommand::NextWidget => {
                self.home.search_focus = false;
                UiEffect::None
            }
            UiCommand::PreviousWidget => {
                self.home.search_focus = true;
                UiEffect::None
            }
            UiCommand::InsertChar(c) => {
                if !c.is_control() {
                    if !self.home.search_focus {
                        self.home.search_focus = true;
                    }
                    self.home.search_query.push(c);
                }
                UiEffect::None
            }
            UiCommand::DeleteChar => {
                self.home.search_query.pop();
                UiEffect::None
            }
            UiCommand::ClearSearch => {
                self.home.search_query.clear();
                UiEffect::None
            }
            UiCommand::Back | UiCommand::CancelEdit => {
                self.screen = UiScreen::Lock;
                UiEffect::None
            }
            _ => UiEffect::None,
        }
    }

    fn handle_entry(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::Back | UiCommand::GoHome => {
                self.screen = UiScreen::Home;
                UiEffect::None
            }
            UiCommand::Lock => {
                self.screen = UiScreen::Lock;
                UiEffect::None
            }
            UiCommand::StartSync => {
                self.screen = UiScreen::Sync;
                UiEffect::StartSync
            }
            UiCommand::EditEntry | UiCommand::Activate => {
                if let Some(entry) = self.active_entry_id() {
                    self.enter_edit(entry)
                } else {
                    UiEffect::None
                }
            }
            UiCommand::FocusSearch => {
                self.screen = UiScreen::Home;
                self.home.search_focus = true;
                UiEffect::None
            }
            _ => UiEffect::None,
        }
    }

    fn handle_edit(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::InsertChar(c) => {
                if let Some(edit) = self.edit.as_mut() {
                    if let Some(field) = edit.fields.get_mut(edit.active_index) {
                        if !c.is_control() {
                            field.value.push(c);
                        }
                    }
                }
                UiEffect::None
            }
            UiCommand::DeleteChar => {
                if let Some(edit) = self.edit.as_mut() {
                    if let Some(field) = edit.fields.get_mut(edit.active_index) {
                        field.value.pop();
                    }
                }
                UiEffect::None
            }
            UiCommand::MoveSelectionUp | UiCommand::PreviousWidget => {
                if let Some(edit) = self.edit.as_mut() {
                    if edit.active_index > 0 {
                        edit.active_index -= 1;
                    }
                }
                UiEffect::None
            }
            UiCommand::MoveSelectionDown | UiCommand::NextWidget => {
                if let Some(edit) = self.edit.as_mut() {
                    if edit.active_index + 1 < edit.fields.len() {
                        edit.active_index += 1;
                    }
                }
                UiEffect::None
            }
            UiCommand::Activate | UiCommand::ConfirmEdit => {
                if let Some(edit) = self.edit.take() {
                    let entry_id = edit.entry_id.clone();
                    self.entry = Some(EntryState {
                        entry_id: entry_id.clone(),
                        hint: Some(String::from("Entry saved")),
                    });
                    self.screen = UiScreen::Entry;
                    UiEffect::SaveEdit { entry_id }
                } else {
                    UiEffect::None
                }
            }
            UiCommand::Back | UiCommand::CancelEdit => {
                if let Some(edit) = self.edit.take() {
                    let entry_id = edit.entry_id;
                    self.entry = Some(EntryState {
                        entry_id: entry_id.clone(),
                        hint: Some(String::from("Edit cancelled")),
                    });
                    self.screen = UiScreen::Entry;
                    UiEffect::CancelEdit { entry_id }
                } else {
                    self.screen = UiScreen::Entry;
                    UiEffect::None
                }
            }
            UiCommand::Lock => {
                self.screen = UiScreen::Lock;
                UiEffect::None
            }
            UiCommand::StartSync => {
                self.screen = UiScreen::Sync;
                UiEffect::StartSync
            }
            _ => UiEffect::None,
        }
    }

    fn handle_settings(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::Back | UiCommand::GoHome => {
                self.screen = UiScreen::Home;
                UiEffect::None
            }
            UiCommand::Lock => {
                self.screen = UiScreen::Lock;
                UiEffect::None
            }
            UiCommand::MoveSelectionUp => {
                if self.settings.selected > 0 {
                    self.settings.selected -= 1;
                }
                UiEffect::None
            }
            UiCommand::MoveSelectionDown => {
                if self.settings.selected + 1 < self.settings.options.len() {
                    self.settings.selected += 1;
                }
                UiEffect::None
            }
            UiCommand::StartSync => {
                self.screen = UiScreen::Sync;
                UiEffect::StartSync
            }
            _ => UiEffect::None,
        }
    }

    fn handle_sync(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::Back | UiCommand::GoHome => {
                self.screen = UiScreen::Home;
                UiEffect::None
            }
            UiCommand::Lock => {
                self.screen = UiScreen::Lock;
                UiEffect::None
            }
            _ => UiEffect::None,
        }
    }

    fn selected_entry_id(&self) -> Option<String> {
        self.recents
            .get(self.home.selected_recent)
            .map(|entry| entry.id.clone())
    }

    fn active_entry_id(&self) -> Option<String> {
        self.entry
            .as_ref()
            .map(|entry| entry.entry_id.clone())
            .or_else(|| self.selected_entry_id())
    }

    fn open_entry(&mut self, entry_id: String) -> UiEffect {
        self.entry = Some(EntryState {
            entry_id: entry_id.clone(),
            hint: None,
        });
        self.screen = UiScreen::Entry;
        UiEffect::None
    }

    fn enter_edit(&mut self, entry_id: String) -> UiEffect {
        let fields = self
            .recents
            .iter()
            .find(|entry| entry.id == entry_id)
            .map(|entry| {
                vec![
                    FormField {
                        label: String::from("Title"),
                        value: entry.title.clone(),
                        secure: false,
                    },
                    FormField {
                        label: String::from("Username"),
                        value: entry.username.clone(),
                        secure: false,
                    },
                    FormField {
                        label: String::from("Note"),
                        value: entry.note.clone().unwrap_or_default(),
                        secure: false,
                    },
                ]
            })
            .unwrap_or_else(|| {
                vec![FormField {
                    label: String::from("Title"),
                    value: String::new(),
                    secure: false,
                }]
            });

        self.edit = Some(EditState {
            entry_id: entry_id.clone(),
            fields,
            active_index: 0,
        });
        self.screen = UiScreen::Edit;
        UiEffect::BeginEdit { entry_id }
    }

    fn move_recent_selection(&mut self, delta: isize) {
        if self.recents.is_empty() {
            self.home.selected_recent = 0;
            return;
        }

        let current = self.home.selected_recent as isize;
        let max = (self.recents.len() - 1) as isize;
        let mut next = current + delta;
        if next < 0 {
            next = 0;
        }
        if next > max {
            next = max;
        }
        self.home.selected_recent = next as usize;
    }

    /// Update sync progress that will be reflected in the next render.
    pub fn update_sync_progress(&mut self, progress_percent: u8, stage: impl Into<String>) {
        self.sync.progress_percent = progress_percent;
        self.sync.stage = stage.into();
    }

    /// Update the cached TOTP code and reset the countdown window.
    pub fn update_totp(&mut self, code: Option<String>, remaining_ms: u32) {
        self.totp.code = code;
        self.totp.remaining_ms = cmp::min(remaining_ms, self.totp.period as u32 * 1_000);
    }

    /// Advance time for the TOTP countdown.
    pub fn tick(&mut self, elapsed_ms: u32) {
        self.totp.tick(elapsed_ms);
    }

    fn current_entry(&self) -> Option<&EntrySummary> {
        let Some(entry_state) = &self.entry else {
            return None;
        };
        self.recents
            .iter()
            .find(|entry| entry.id == entry_state.entry_id)
    }

    fn render_entry(&self) -> EntryView {
        let entry = self.current_entry();
        let totp_widget =
            entry.and_then(|summary| summary.totp.as_ref().map(|_| self.totp.widget()));

        EntryView {
            entry: EntryDetails {
                title: entry.map(|e| e.title.clone()).unwrap_or_default(),
                username: entry.map(|e| e.username.clone()).unwrap_or_default(),
                note: entry.and_then(|e| e.note.clone()),
                totp: totp_widget,
            },
            hint: self.entry.as_ref().and_then(|state| state.hint.clone()),
        }
    }

    fn render_edit(&self) -> EditView {
        let form = self
            .edit
            .as_ref()
            .map(|edit| FormWidget {
                fields: edit.fields.clone(),
                active_index: edit.active_index,
            })
            .unwrap_or_else(|| FormWidget {
                fields: vec![],
                active_index: 0,
            });

        EditView {
            form,
            toolbar_hint: Some(String::from("Enter to save, Esc to cancel")),
        }
    }

    fn render_home(&self) -> HomeView {
        let entries = self
            .recents
            .iter()
            .map(|entry| RecentListItem {
                title: entry.title.clone(),
                subtitle: Some(entry.username.clone()),
            })
            .collect();
        HomeView {
            search: SearchWidget {
                query: self.home.search_query.clone(),
                has_focus: self.home.search_focus,
            },
            recent: RecentList {
                entries,
                selected: if self.recents.is_empty() {
                    None
                } else {
                    Some(self.home.selected_recent)
                },
            },
            totp: self.totp.widget(),
        }
    }

    fn render_settings(&self) -> SettingsView {
        SettingsView {
            options: self.settings.options.clone(),
            selected: self.settings.selected,
        }
    }

    fn render_sync(&self) -> SyncView {
        SyncView {
            stage: self.sync.stage.clone(),
            progress_percent: self.sync.progress_percent,
            hint: Some(String::from("Keep device awake during sync")),
        }
    }

    fn render_lock(&self) -> LockView {
        LockView {
            prompt: String::from("Enter PIN to unlock"),
            remaining_attempts: self.lock.remaining_attempts,
        }
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

fn default_settings_options() -> Vec<SettingsItem> {
    vec![
        SettingsItem {
            label: String::from("Auto-lock"),
            value: String::from("90s"),
        },
        SettingsItem {
            label: String::from("Theme"),
            value: String::from("Contrast"),
        },
        SettingsItem {
            label: String::from("Sync target"),
            value: String::from("Repo"),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::input::PhysicalKey;

    fn sample_entries() -> Vec<EntrySummary> {
        vec![
            EntrySummary {
                id: String::from("alpha"),
                title: String::from("Alpha Account"),
                username: String::from("alpha@example.com"),
                last_used: String::from("2024-01-01"),
                totp: Some(String::from("123456")),
                note: Some(String::from("primary account")),
            },
            EntrySummary {
                id: String::from("beta"),
                title: String::from("Beta Service"),
                username: String::from("user"),
                last_used: String::from("2024-01-10"),
                totp: None,
                note: None,
            },
        ]
    }

    #[test]
    fn state_machine_transitions_follow_expected_flow() {
        transport::reset();
        let mut ui = UiRuntime::new(sample_entries());
        assert_eq!(ui.screen(), UiScreen::Lock);

        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Enter));
        assert_eq!(ui.screen(), UiScreen::Home);

        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Enter));
        assert_eq!(ui.screen(), UiScreen::Entry);

        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Edit));
        assert_eq!(ui.screen(), UiScreen::Edit);

        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Enter));
        assert_eq!(ui.screen(), UiScreen::Entry);

        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Sync));
        assert_eq!(ui.screen(), UiScreen::Sync);

        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Escape));
        assert_eq!(ui.screen(), UiScreen::Home);

        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Lock));
        assert_eq!(ui.screen(), UiScreen::Lock);
    }

    #[test]
    fn hint_bar_reflects_active_screen() {
        transport::reset();
        let mut ui = UiRuntime::new(sample_entries());
        let mut frame = ui.render();
        assert!(
            frame
                .hint_bar
                .hints
                .iter()
                .any(|hint| hint.action.contains("Unlock"))
        );

        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Enter));
        frame = ui.render();
        assert!(
            frame
                .hint_bar
                .hints
                .iter()
                .any(|hint| hint.action.contains("Open"))
        );

        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Enter));
        frame = ui.render();
        assert!(
            frame
                .hint_bar
                .hints
                .iter()
                .any(|hint| hint.action.contains("Edit"))
        );
    }

    #[test]
    fn recent_selection_moves_with_arrows() {
        transport::reset();
        let mut ui = UiRuntime::new(sample_entries());
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
}
