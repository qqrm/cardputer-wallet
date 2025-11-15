use alloc::string::String;

use super::{UiEffect, UiRuntime, UiScreen};
use crate::ui::{input::UiCommand, render::LockView};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LockState {
    pub remaining_attempts: Option<u8>,
}

impl LockState {
    pub(super) fn new() -> Self {
        Self {
            remaining_attempts: Some(10),
        }
    }
}

impl UiRuntime {
    pub(super) fn handle_lock(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::Activate => {
                self.set_screen(UiScreen::Home);
                UiEffect::None
            }
            UiCommand::Back | UiCommand::GoHome => {
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

    pub(super) fn render_lock(&self) -> LockView {
        LockView {
            prompt: String::from("Enter PIN to unlock"),
            remaining_attempts: self.lock.remaining_attempts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::input::UiCommand;

    #[test]
    fn activate_unlocks_home() {
        let vault =
            super::super::fixtures::MemoryVault::new(super::super::fixtures::sample_entries());
        let mut ui = super::super::fixtures::build_runtime(vault);

        assert_eq!(ui.screen(), UiScreen::Lock);
        ui.apply_command(UiCommand::Activate);
        assert_eq!(ui.screen(), UiScreen::Home);
    }
}
