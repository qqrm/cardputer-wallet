use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::cmp;

use super::{
    JournalEntryView, TotpProvider, TotpSnapshot, VaultViewModel,
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

const MIN_SEARCH_LEN: usize = 2;
const DEFAULT_TOTP_PERIOD: u8 = 30;

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

    fn handle_lock(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::Activate => {
                self.set_screen(UiScreen::Home);
                UiEffect::None
            }
            UiCommand::Back => UiEffect::None,
            UiCommand::GoHome => {
                self.set_screen(UiScreen::Home);
                UiEffect::None
            }
            UiCommand::FocusSearch => {
                self.set_screen(UiScreen::Home);
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
                self.set_screen(UiScreen::Settings);
                UiEffect::None
            }
            UiCommand::StartSync => {
                self.set_screen(UiScreen::Sync);
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
                    self.home.selected_recent = 0;
                    self.sync_totp_selection();
                }
                UiEffect::None
            }
            UiCommand::DeleteChar => {
                self.home.search_query.pop();
                self.home.selected_recent = 0;
                self.sync_totp_selection();
                UiEffect::None
            }
            UiCommand::ClearSearch => {
                self.home.search_query.clear();
                self.home.selected_recent = 0;
                self.sync_totp_selection();
                UiEffect::None
            }
            UiCommand::Back | UiCommand::CancelEdit => {
                self.set_screen(UiScreen::Lock);
                UiEffect::None
            }
            _ => UiEffect::None,
        }
    }

    fn handle_entry(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::Back | UiCommand::GoHome => {
                self.set_screen(UiScreen::Home);
                UiEffect::None
            }
            UiCommand::Lock => {
                self.set_screen(UiScreen::Lock);
                UiEffect::None
            }
            UiCommand::StartSync => {
                self.set_screen(UiScreen::Sync);
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
                self.set_screen(UiScreen::Home);
                self.home.search_focus = true;
                UiEffect::None
            }
            _ => UiEffect::None,
        }
    }

    fn handle_edit(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::InsertChar(c) => {
                if let Some(edit) = self.edit.as_mut()
                    && let Some(field) = edit.fields.get_mut(edit.active_index)
                    && !c.is_control()
                {
                    field.value.push(c);
                }
                UiEffect::None
            }
            UiCommand::DeleteChar => {
                if let Some(edit) = self.edit.as_mut()
                    && let Some(field) = edit.fields.get_mut(edit.active_index)
                {
                    field.value.pop();
                }
                UiEffect::None
            }
            UiCommand::MoveSelectionUp | UiCommand::PreviousWidget => {
                if let Some(edit) = self.edit.as_mut()
                    && edit.active_index > 0
                {
                    edit.active_index -= 1;
                }
                UiEffect::None
            }
            UiCommand::MoveSelectionDown | UiCommand::NextWidget => {
                if let Some(edit) = self.edit.as_mut()
                    && edit.active_index + 1 < edit.fields.len()
                {
                    edit.active_index += 1;
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
                    self.set_screen(UiScreen::Entry);
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
                    self.set_screen(UiScreen::Entry);
                    UiEffect::CancelEdit { entry_id }
                } else {
                    self.set_screen(UiScreen::Entry);
                    UiEffect::None
                }
            }
            UiCommand::Lock => {
                self.set_screen(UiScreen::Lock);
                UiEffect::None
            }
            UiCommand::StartSync => {
                self.set_screen(UiScreen::Sync);
                UiEffect::StartSync
            }
            _ => UiEffect::None,
        }
    }

    fn handle_settings(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::Back | UiCommand::GoHome => {
                self.set_screen(UiScreen::Home);
                UiEffect::None
            }
            UiCommand::Lock => {
                self.set_screen(UiScreen::Lock);
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
                self.set_screen(UiScreen::Sync);
                UiEffect::StartSync
            }
            _ => UiEffect::None,
        }
    }

    fn handle_sync(&mut self, command: UiCommand) -> UiEffect {
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

    fn normalized_query(&self) -> Option<String> {
        let trimmed = self.home.search_query.trim();
        if trimmed.len() >= MIN_SEARCH_LEN {
            Some(trimmed.to_ascii_lowercase())
        } else {
            None
        }
    }

    fn visible_entries(&self) -> Vec<EntrySummary> {
        let entries = self.vault.entries();
        if let Some(query) = self.normalized_query() {
            filter_entries(entries, &query)
        } else {
            sort_by_last_used(entries)
        }
    }

    fn open_entry(&mut self, entry_id: String) -> UiEffect {
        self.entry = Some(EntryState {
            entry_id: entry_id.clone(),
            hint: None,
        });
        self.set_screen(UiScreen::Entry);
        UiEffect::None
    }

    fn enter_edit(&mut self, entry_id: String) -> UiEffect {
        let fields = self
            .vault
            .entry(&entry_id)
            .map(|entry| {
                vec![
                    FormField {
                        label: String::from("Title"),
                        value: entry.title,
                        secure: false,
                    },
                    FormField {
                        label: String::from("Username"),
                        value: entry.username,
                        secure: false,
                    },
                    FormField {
                        label: String::from("Note"),
                        value: entry.note.unwrap_or_default(),
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
        self.set_screen(UiScreen::Edit);
        UiEffect::BeginEdit { entry_id }
    }

    fn move_recent_selection(&mut self, delta: isize) {
        let entries = self.visible_entries();
        if entries.is_empty() {
            self.home.selected_recent = 0;
            self.totp.select_entry(None);
            return;
        }

        let current = self.home.selected_recent as isize;
        let max = (entries.len() - 1) as isize;
        let next = (current + delta).clamp(0, max) as usize;
        if next != self.home.selected_recent {
            self.home.selected_recent = next;
            self.sync_totp_selection();
        }
    }

    /// Update sync progress that will be reflected in the next render.
    pub fn update_sync_progress(&mut self, progress_percent: u8, stage: impl Into<String>) {
        self.sync.progress_percent = progress_percent;
        self.sync.stage = stage.into();
    }

    /// Advance time for the TOTP countdown.
    pub fn tick(&mut self, elapsed_ms: u32) {
        self.totp.tick(elapsed_ms);
    }

    fn current_entry(&self) -> Option<EntrySummary> {
        let entry_state = self.entry.as_ref()?;
        self.vault.entry(&entry_state.entry_id)
    }

    fn render_entry(&self) -> EntryView {
        let entry = self.current_entry();
        let totp_snapshot = self.totp.snapshot();
        let totp_widget = entry
            .as_ref()
            .and_then(|summary| summary.totp.as_ref().map(|_| totp_snapshot.to_widget()));

        EntryView {
            entry: EntryDetails {
                title: entry.as_ref().map(|e| e.title.clone()).unwrap_or_default(),
                username: entry
                    .as_ref()
                    .map(|e| e.username.clone())
                    .unwrap_or_default(),
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
        let visible = self.visible_entries();
        let list_entries = visible
            .iter()
            .map(|entry| RecentListItem {
                title: entry.title.clone(),
                subtitle: Some(entry.username.clone()),
            })
            .collect();
        let totp_widget = self.totp.snapshot().to_widget();
        let selected = if visible.is_empty() || self.home.selected_recent >= visible.len() {
            None
        } else {
            Some(self.home.selected_recent)
        };
        HomeView {
            search: SearchWidget {
                query: self.home.search_query.clone(),
                has_focus: self.home.search_focus,
            },
            recent: RecentList {
                entries: list_entries,
                selected,
            },
            totp: totp_widget,
        }
    }

    fn render_settings(&self) -> SettingsView {
        SettingsView {
            options: self.settings.options.clone(),
            selected: self.settings.selected,
        }
    }

    fn render_sync(&self) -> SyncView {
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

fn sort_by_last_used(mut entries: Vec<EntrySummary>) -> Vec<EntrySummary> {
    entries.sort_by(|a, b| b.last_used.cmp(&a.last_used));
    entries
}

fn filter_entries(entries: Vec<EntrySummary>, query: &str) -> Vec<EntrySummary> {
    let mut prefix: Vec<EntrySummary> = Vec::new();
    let mut fuzzy: Vec<(EntrySummary, usize)> = Vec::new();
    let mut fallback: Vec<EntrySummary> = Vec::new();

    for entry in entries {
        let title = entry.title.to_ascii_lowercase();
        let username = entry.username.to_ascii_lowercase();
        if title.starts_with(query) || username.starts_with(query) {
            prefix.push(entry);
            continue;
        }

        let distance = cmp::min(levenshtein(&title, query), levenshtein(&username, query));
        if distance <= 1 {
            fuzzy.push((entry, distance));
        } else {
            fallback.push(entry);
        }
    }

    prefix.sort_by(|a, b| {
        let title_cmp = a
            .title
            .to_ascii_lowercase()
            .cmp(&b.title.to_ascii_lowercase());
        if title_cmp == cmp::Ordering::Equal {
            a.username
                .to_ascii_lowercase()
                .cmp(&b.username.to_ascii_lowercase())
        } else {
            title_cmp
        }
    });

    fuzzy.sort_by(|(entry_a, dist_a), (entry_b, dist_b)| {
        dist_a
            .cmp(dist_b)
            .then_with(|| {
                entry_a
                    .title
                    .to_ascii_lowercase()
                    .cmp(&entry_b.title.to_ascii_lowercase())
            })
            .then_with(|| {
                entry_a
                    .username
                    .to_ascii_lowercase()
                    .cmp(&entry_b.username.to_ascii_lowercase())
            })
    });

    fallback.sort_by(|a, b| b.last_used.cmp(&a.last_used));

    prefix
        .into_iter()
        .chain(fuzzy.into_iter().map(|(entry, _)| entry))
        .chain(fallback.into_iter())
        .collect()
}

fn levenshtein(a: &str, b: &str) -> usize {
    if a.is_empty() {
        return b.chars().count();
    }
    if b.is_empty() {
        return a.chars().count();
    }

    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b_chars.len()).collect();
    let mut current = vec![0usize; b_chars.len() + 1];

    for (i, a_ch) in a_chars.iter().enumerate() {
        current[0] = i + 1;
        for (j, b_ch) in b_chars.iter().enumerate() {
            let cost = if a_ch == b_ch { 0 } else { 1 };
            current[j + 1] = cmp::min(
                cmp::min(current[j] + 1, previous[j + 1] + 1),
                previous[j] + cost,
            );
        }
        previous.copy_from_slice(&current);
    }

    previous[b_chars.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{
        JournalAction, JournalEntryView, TotpProvider, TotpSnapshot, VaultViewModel,
        input::PhysicalKey,
    };

    struct MemoryVault {
        entries: Vec<EntrySummary>,
        journal: Vec<JournalEntryView>,
    }

    impl MemoryVault {
        fn new(entries: Vec<EntrySummary>) -> Self {
            Self {
                entries,
                journal: Vec::new(),
            }
        }

        fn with_journal(entries: Vec<EntrySummary>, journal: Vec<JournalEntryView>) -> Self {
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
    struct NullTotpProvider;

    impl TotpProvider for NullTotpProvider {
        fn select_entry(&mut self, _entry_id: Option<&str>) {}

        fn snapshot(&self) -> TotpSnapshot {
            TotpSnapshot::empty(DEFAULT_TOTP_PERIOD)
        }

        fn tick(&mut self, _elapsed_ms: u32) {}
    }

    fn sample_entries() -> Vec<EntrySummary> {
        vec![
            EntrySummary {
                id: String::from("alpha"),
                title: String::from("Alpha Account"),
                username: String::from("alpha@example.com"),
                last_used: String::from("2024-01-03"),
                totp: Some(String::from("has-totp")),
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

    fn build_runtime(vault: MemoryVault) -> UiRuntime {
        UiRuntime::new(Box::new(vault), Box::new(NullTotpProvider))
    }

    #[test]
    fn state_machine_transitions_follow_expected_flow() {
        transport::reset();
        let mut ui = build_runtime(MemoryVault::new(sample_entries()));
        assert_eq!(ui.screen(), UiScreen::Lock);

        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Enter));
        assert_eq!(ui.screen(), UiScreen::Home);

        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Enter));
        assert_eq!(ui.screen(), UiScreen::Entry);

        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Edit));
        assert_eq!(ui.screen(), UiScreen::Edit);

        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Enter));
        assert_eq!(ui.screen(), UiScreen::Entry);

        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Settings));
        assert_eq!(ui.screen(), UiScreen::Settings);

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
        let mut ui = build_runtime(MemoryVault::new(sample_entries()));

        let mut assert_hint = |expected: &str| {
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

        assert_hint("Unlock");
        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Enter));
        assert_hint("Open");
        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Enter));
        assert_hint("Edit");
        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Edit));
        assert_hint("Save");
        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Settings));
        assert_hint("Select");
        ui.handle_key_event(KeyEvent::pressed(PhysicalKey::Sync));
        assert_hint("Lock");
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
            EntrySummary {
                id: String::from("alpha"),
                title: String::from("Alpha"),
                username: String::from("admin"),
                last_used: String::from("2024-01-03"),
                totp: None,
                note: None,
            },
            EntrySummary {
                id: String::from("alpine"),
                title: String::from("Alpine"),
                username: String::from("ops"),
                last_used: String::from("2024-01-02"),
                totp: None,
                note: None,
            },
            EntrySummary {
                id: String::from("gamma"),
                title: String::from("Gamma"),
                username: String::from("alx"),
                last_used: String::from("2024-01-10"),
                totp: None,
                note: None,
            },
            EntrySummary {
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
