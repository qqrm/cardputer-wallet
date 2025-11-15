use alloc::{string::String, vec, vec::Vec};
use core::cmp;

use crate::ui::{
    input::UiCommand,
    render::{HomeView, RecentList, RecentListItem, SearchWidget, SettingsItem, SettingsView},
};

use super::{EntrySummary, MIN_SEARCH_LEN, UiEffect, UiRuntime, UiScreen};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HomeState {
    pub search_query: String,
    pub search_focus: bool,
    pub selected_recent: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsState {
    pub options: Vec<SettingsItem>,
    pub selected: usize,
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

    pub(super) fn move_recent_selection(&mut self, delta: isize) {
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

    pub(super) fn normalized_query(&self) -> Option<String> {
        let trimmed = self.home.search_query.trim();
        if trimmed.len() >= MIN_SEARCH_LEN {
            Some(trimmed.to_ascii_lowercase())
        } else {
            None
        }
    }

    pub(super) fn visible_entries(&self) -> Vec<EntrySummary> {
        let entries = self.vault.entries();
        if let Some(query) = self.normalized_query() {
            filter_entries(entries, &query)
        } else {
            sort_by_last_used(entries)
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

pub(super) fn default_settings_options() -> Vec<SettingsItem> {
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
    use crate::ui::input::UiCommand;

    use super::super::test_support::{MemoryVault, build_runtime, sample_entries};
    use super::*;

    #[test]
    fn next_widget_moves_focus_off_search() {
        let mut ui = build_runtime(MemoryVault::new(sample_entries()));
        ui.handle_home(UiCommand::NextWidget);
        assert!(!ui.home.search_focus);
    }

    #[test]
    fn settings_navigation_changes_selected_option() {
        let mut ui = build_runtime(MemoryVault::new(sample_entries()));
        ui.set_screen(UiScreen::Settings);
        ui.handle_settings(UiCommand::MoveSelectionDown);
        assert_eq!(ui.settings.selected, 1);
    }
}
