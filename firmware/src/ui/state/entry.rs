use alloc::{string::String, vec, vec::Vec};
use core::cmp;

use super::{EntrySummary, UiEffect, UiRuntime, UiScreen};
use crate::ui::{
    input::UiCommand,
    render::{
        EditView, EntryDetails, EntryView, FormField, FormWidget, HomeView, RecentList,
        RecentListItem, SearchWidget, SettingsItem, SettingsView,
    },
};

const MIN_SEARCH_LEN: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HomeState {
    pub(super) search_query: String,
    pub(super) search_focus: bool,
    pub(super) selected_recent: usize,
}

impl HomeState {
    pub(super) fn new() -> Self {
        Self {
            search_query: String::new(),
            search_focus: true,
            selected_recent: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct EntryState {
    pub(super) entry_id: String,
    pub(super) hint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct EditState {
    pub(super) entry_id: String,
    pub(super) fields: Vec<FormField>,
    pub(super) active_index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SettingsState {
    pub(super) options: Vec<SettingsItem>,
    pub(super) selected: usize,
}

impl SettingsState {
    pub(super) fn new(options: Vec<SettingsItem>) -> Self {
        Self {
            options,
            selected: 0,
        }
    }
}

impl UiRuntime {
    pub(super) fn handle_home(&mut self, command: UiCommand) -> UiEffect {
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

    pub(super) fn handle_entry(&mut self, command: UiCommand) -> UiEffect {
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
            UiCommand::OpenSettings => {
                self.set_screen(UiScreen::Settings);
                UiEffect::None
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

    pub(super) fn handle_edit(&mut self, command: UiCommand) -> UiEffect {
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
            UiCommand::OpenSettings => {
                self.edit = None;
                self.set_screen(UiScreen::Settings);
                UiEffect::None
            }
            _ => UiEffect::None,
        }
    }

    pub(super) fn handle_settings(&mut self, command: UiCommand) -> UiEffect {
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

    pub(super) fn selected_entry_id(&self) -> Option<String> {
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

    pub(super) fn sync_totp_selection(&mut self) {
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

    fn current_entry(&self) -> Option<EntrySummary> {
        let entry_state = self.entry.as_ref()?;
        self.vault.entry(&entry_state.entry_id)
    }

    pub(super) fn render_entry(&self) -> EntryView {
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

    pub(super) fn render_edit(&self) -> EditView {
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

    pub(super) fn render_home(&self) -> HomeView {
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

    pub(super) fn render_settings(&self) -> SettingsView {
        SettingsView {
            options: self.settings.options.clone(),
            selected: self.settings.selected,
        }
    }
}

fn sort_by_last_used(mut entries: Vec<EntrySummary>) -> Vec<EntrySummary> {
    entries.sort_by(|a, b| b.last_used.cmp(&a.last_used));
    entries
}

fn filter_entries(entries: Vec<EntrySummary>, query: &str) -> Vec<EntrySummary> {
    let mut seen_ids: Vec<String> = Vec::new();
    let mut prefix: Vec<EntrySummary> = Vec::new();
    let mut fuzzy: Vec<(EntrySummary, usize)> = Vec::new();
    let mut fallback: Vec<EntrySummary> = Vec::new();

    for entry in entries {
        if seen_ids.iter().any(|id| id == &entry.id) {
            continue;
        }
        seen_ids.push(entry.id.clone());

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
        .chain(fallback)
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
    use crate::ui::{input::PhysicalKey, render::ViewContent};

    #[test]
    fn recent_selection_moves_with_arrows() {
        let vault =
            super::super::fixtures::MemoryVault::new(super::super::fixtures::sample_entries());
        let mut ui = super::super::fixtures::build_runtime(vault);
        super::super::fixtures::press(&mut ui, PhysicalKey::Enter);
        super::super::fixtures::press(&mut ui, PhysicalKey::ArrowDown);
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
        entries.extend(super::super::fixtures::sample_entries());
        let vault = super::super::fixtures::MemoryVault::new(entries);
        let mut ui = super::super::fixtures::build_runtime(vault);
        super::super::fixtures::press(&mut ui, PhysicalKey::Enter);
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
}
