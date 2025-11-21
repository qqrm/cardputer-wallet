use alloc::{string::String, vec, vec::Vec};
use core::cmp;

use super::super::{EntrySummary, UiEffect, UiRuntime, UiScreen};
use crate::ui::render::FormField;

const MIN_SEARCH_LEN: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HomeState {
    pub(crate) search_query: String,
    pub(crate) search_focus: bool,
    pub(crate) selected_recent: usize,
}

impl HomeState {
    pub(crate) fn new() -> Self {
        Self {
            search_query: String::new(),
            search_focus: true,
            selected_recent: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EntryState {
    pub(crate) entry_id: String,
    pub(crate) hint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EditState {
    pub(crate) entry_id: String,
    pub(crate) fields: Vec<FormField>,
    pub(crate) active_index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SettingsState {
    pub(crate) options: Vec<crate::ui::render::SettingsItem>,
    pub(crate) selected: usize,
}

impl SettingsState {
    pub(crate) fn new(options: Vec<crate::ui::render::SettingsItem>) -> Self {
        Self {
            options,
            selected: 0,
        }
    }
}

impl UiRuntime {
    pub(crate) fn selected_entry_id(&self) -> Option<String> {
        self.visible_entries()
            .get(self.home.selected_recent)
            .map(|entry| entry.id.clone())
    }

    pub(crate) fn active_entry_id(&self) -> Option<String> {
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

    pub(crate) fn visible_entries(&self) -> Vec<EntrySummary> {
        let entries = self.vault.entries();
        if let Some(query) = self.normalized_query() {
            filter_entries(entries, &query)
        } else {
            sort_by_last_used(entries)
        }
    }

    pub(crate) fn open_entry(&mut self, entry_id: String) -> UiEffect {
        self.entry = Some(EntryState {
            entry_id: entry_id.clone(),
            hint: None,
        });
        self.set_screen(UiScreen::Entry);
        UiEffect::None
    }

    pub(crate) fn enter_edit(&mut self, entry_id: String) -> UiEffect {
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

    pub(crate) fn move_recent_selection(&mut self, delta: isize) {
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

    pub(crate) fn sync_totp_selection(&mut self) {
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

    pub(crate) fn current_entry(&self) -> Option<EntrySummary> {
        let entry_state = self.entry.as_ref()?;
        self.vault.entry(&entry_state.entry_id)
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
