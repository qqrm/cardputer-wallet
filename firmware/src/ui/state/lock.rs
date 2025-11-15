use alloc::string::String;

use crate::ui::{input::UiCommand, render::LockView};

use super::{UiEffect, UiRuntime, UiScreen};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockState {
    pub remaining_attempts: Option<u8>,
}

impl UiRuntime {
    pub(super) fn handle_lock(&mut self, command: UiCommand) -> UiEffect {
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

    pub(super) fn render_lock(&self) -> LockView {
        LockView {
            prompt: String::from("Enter PIN to unlock"),
            remaining_attempts: self.lock.remaining_attempts,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ui::input::UiCommand;

    use super::super::test_support::{MemoryVault, build_runtime, sample_entries};
    use super::*;

    #[test]
    fn activate_unlocks_to_home() {
        let mut ui = build_runtime(MemoryVault::new(sample_entries()));
        let effect = ui.handle_lock(UiCommand::Activate);
        assert_eq!(ui.screen(), UiScreen::Home);
        assert!(matches!(effect, UiEffect::None));
    }

    #[test]
    fn lock_view_reports_remaining_attempts() {
        let ui = build_runtime(MemoryVault::new(sample_entries()));
        let view = ui.render_lock();
        assert_eq!(view.remaining_attempts, Some(10));
    }
}
