use alloc::string::String;

use super::super::{UiEffect, UiRuntime, UiScreen};
use crate::ui::input::UiCommand;

impl UiRuntime {
    pub(crate) fn handle_home(&mut self, command: UiCommand) -> UiEffect {
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
                self.lock_runtime();
                UiEffect::None
            }
            _ => UiEffect::None,
        }
    }

    pub(crate) fn handle_entry(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::Back | UiCommand::GoHome => {
                self.set_screen(UiScreen::Home);
                UiEffect::None
            }
            UiCommand::Lock => {
                self.lock_runtime();
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

    pub(crate) fn handle_edit(&mut self, command: UiCommand) -> UiEffect {
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
                    self.entry = Some(super::model::EntryState {
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
                    self.entry = Some(super::model::EntryState {
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
                self.lock_runtime();
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

    pub(crate) fn handle_settings(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::Back | UiCommand::GoHome => {
                self.set_screen(UiScreen::Home);
                UiEffect::None
            }
            UiCommand::Lock => {
                self.lock_runtime();
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
}
