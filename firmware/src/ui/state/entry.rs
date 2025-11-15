use alloc::{string::String, vec, vec::Vec};

use crate::ui::{
    input::UiCommand,
    render::{EditView, EntryDetails, EntryView, FormField, FormWidget},
};

use super::{EntrySummary, UiEffect, UiRuntime, UiScreen};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryState {
    pub entry_id: String,
    pub hint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditState {
    pub entry_id: String,
    pub fields: Vec<FormField>,
    pub active_index: usize,
}

impl UiRuntime {
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
            UiCommand::OpenSettings => {
                self.set_screen(UiScreen::Settings);
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
            _ => UiEffect::None,
        }
    }

    pub(super) fn open_entry(&mut self, entry_id: String) -> UiEffect {
        self.entry = Some(EntryState {
            entry_id: entry_id.clone(),
            hint: None,
        });
        self.set_screen(UiScreen::Entry);
        UiEffect::None
    }

    pub(super) fn enter_edit(&mut self, entry_id: String) -> UiEffect {
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

    pub(super) fn current_entry(&self) -> Option<EntrySummary> {
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
}

#[cfg(test)]
mod tests {
    use crate::ui::input::UiCommand;

    use super::super::test_support::{MemoryVault, build_runtime, sample_entries};
    use super::*;

    #[test]
    fn entering_edit_mode_builds_form_fields() {
        let mut ui = build_runtime(MemoryVault::new(sample_entries()));
        ui.open_entry(String::from("alpha"));
        let effect = ui.enter_edit(String::from("alpha"));
        assert!(matches!(effect, UiEffect::BeginEdit { .. }));
        assert_eq!(ui.screen(), UiScreen::Edit);
        assert_eq!(ui.edit.as_ref().unwrap().fields.len(), 3);
    }

    #[test]
    fn saving_edit_returns_to_entry_screen() {
        let mut ui = build_runtime(MemoryVault::new(sample_entries()));
        ui.open_entry(String::from("alpha"));
        ui.enter_edit(String::from("alpha"));
        let effect = ui.handle_edit(UiCommand::Activate);
        assert!(matches!(effect, UiEffect::SaveEdit { .. }));
        assert_eq!(ui.screen(), UiScreen::Entry);
    }
}
