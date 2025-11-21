use alloc::{string::String, vec};

use super::super::UiRuntime;
use crate::ui::render::{
    EditView, EntryDetails, EntryView, FormWidget, HomeView, RecentList, RecentListItem,
    SearchWidget, SettingsView,
};

impl UiRuntime {
    pub(crate) fn render_entry(&self) -> EntryView {
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

    pub(crate) fn render_edit(&self) -> EditView {
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

    pub(crate) fn render_home(&self) -> HomeView {
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

    pub(crate) fn render_settings(&self) -> SettingsView {
        SettingsView {
            options: self.settings.options.clone(),
            selected: self.settings.selected,
        }
    }
}
