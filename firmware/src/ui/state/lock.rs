use alloc::{format, string::String};
use core::mem;

use super::{UiEffect, UiRuntime};
use crate::crypto::{KeyError, PIN_WIPE_THRESHOLD, PinLockStatus, PinUnlockError};
use crate::ui::{input::UiCommand, render::LockView};

#[cfg(test)]
use super::UiScreen;

const PIN_DIGITS: usize = 6;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LockState {
    pin: String,
    pub remaining_attempts: Option<u8>,
    pub backoff_remaining_ms: Option<u64>,
    pub wipe_required: bool,
    status_message: Option<String>,
}

impl LockState {
    pub(super) fn new() -> Self {
        Self {
            pin: String::new(),
            remaining_attempts: Some(PIN_WIPE_THRESHOLD),
            backoff_remaining_ms: None,
            wipe_required: false,
            status_message: None,
        }
    }

    fn append_digit(&mut self, digit: char) {
        if digit.is_ascii_digit() && self.pin.len() < PIN_DIGITS {
            self.pin.push(digit);
        }
    }

    fn pop_digit(&mut self) {
        self.pin.pop();
    }

    fn clear_pin(&mut self) {
        self.pin.clear();
    }

    fn can_submit(&self) -> bool {
        !self.wipe_required && self.backoff_remaining_ms.is_none() && self.pin.len() == PIN_DIGITS
    }

    fn take_pin(&mut self) -> Option<String> {
        if self.can_submit() {
            Some(mem::take(&mut self.pin))
        } else {
            None
        }
    }

    fn entered_digits(&self) -> usize {
        self.pin.len()
    }

    fn update_from_status(&mut self, status: PinLockStatus) {
        let remaining = PIN_WIPE_THRESHOLD.saturating_sub(status.total_failures);
        self.remaining_attempts = Some(remaining);
        self.backoff_remaining_ms = status.backoff_remaining_ms;
        self.wipe_required = status.wipe_required;
    }

    fn apply_error(&mut self, error: &PinUnlockError) {
        self.status_message = match error {
            PinUnlockError::Backoff { .. } => None,
            PinUnlockError::WipeRequired => Some(String::from("Device requires secure wipe")),
            PinUnlockError::Key(KeyError::CryptoFailure) => Some(String::from("Incorrect PIN")),
            PinUnlockError::Key(other) => Some(format!("Unlock failed: {other}")),
        };
    }

    fn clear_feedback(&mut self) {
        self.status_message = None;
    }

    const fn seconds_from(ms: u64) -> u64 {
        if ms == 0 { 0 } else { (ms + 999) / 1_000 }
    }

    fn prompt(&self) -> String {
        if let Some(message) = &self.status_message {
            return message.clone();
        }

        if self.wipe_required {
            return String::from("Device requires secure wipe");
        }

        if let Some(ms) = self.backoff_remaining_ms {
            if ms > 0 {
                return format!("Try again in {}s", Self::seconds_from(ms));
            }
        }

        String::from("Enter PIN to unlock")
    }

    fn to_view(&self) -> LockView {
        LockView {
            prompt: self.prompt(),
            remaining_attempts: self.remaining_attempts,
            entered_digits: self.entered_digits(),
            max_digits: PIN_DIGITS,
            backoff_remaining_ms: self.backoff_remaining_ms,
            wipe_required: self.wipe_required,
        }
    }

    pub(super) fn record_success(&mut self, status: PinLockStatus) {
        self.update_from_status(status);
        self.clear_feedback();
        self.clear_pin();
    }

    pub(super) fn record_failure(&mut self, status: PinLockStatus, error: &PinUnlockError) {
        self.update_from_status(status);
        self.clear_pin();
        self.apply_error(error);
    }

    pub(super) fn sync_status(&mut self, status: PinLockStatus) {
        self.update_from_status(status);
    }

    pub(super) fn tick(&mut self, elapsed_ms: u32) {
        if elapsed_ms == 0 {
            return;
        }

        if let Some(remaining) = self.backoff_remaining_ms {
            let elapsed = u64::from(elapsed_ms);
            if elapsed >= remaining {
                self.backoff_remaining_ms = None;
            } else {
                self.backoff_remaining_ms = Some(remaining - elapsed);
            }
        }
    }
}

impl UiRuntime {
    pub(super) fn handle_lock(&mut self, command: UiCommand) -> UiEffect {
        match command {
            UiCommand::Activate => {
                if let Some(pin) = self.lock.take_pin() {
                    UiEffect::UnlockRequested { pin }
                } else {
                    UiEffect::None
                }
            }
            UiCommand::InsertChar(ch) => {
                self.lock.append_digit(ch);
                UiEffect::None
            }
            UiCommand::DeleteChar => {
                self.lock.pop_digit();
                UiEffect::None
            }
            UiCommand::Back | UiCommand::GoHome | UiCommand::FocusSearch => UiEffect::None,
            _ => UiEffect::None,
        }
    }

    pub(super) fn render_lock(&self) -> LockView {
        self.lock.to_view()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{PIN_WIPE_THRESHOLD, PinLockStatus, PinUnlockError};
    use crate::ui::input::UiCommand;

    #[test]
    fn entering_complete_pin_requests_unlock() {
        let vault =
            super::super::fixtures::MemoryVault::new(super::super::fixtures::sample_entries());
        let mut ui = super::super::fixtures::build_runtime(vault);

        assert_eq!(ui.screen(), UiScreen::Lock);
        for digit in ['1', '2', '3', '4', '5', '6'] {
            ui.apply_command(UiCommand::InsertChar(digit));
        }

        match ui.apply_command(UiCommand::Activate) {
            UiEffect::UnlockRequested { pin } => assert_eq!(pin, "123456"),
            other => panic!("unexpected effect: {other:?}"),
        }

        let view = ui.render_lock();
        assert_eq!(view.entered_digits, 0);
        assert_eq!(view.max_digits, PIN_DIGITS);
    }

    #[test]
    fn lock_view_shows_backoff_feedback() {
        let vault =
            super::super::fixtures::MemoryVault::new(super::super::fixtures::sample_entries());
        let mut ui = super::super::fixtures::build_runtime(vault);

        let status = PinLockStatus {
            consecutive_failures: 3,
            total_failures: 3,
            backoff_remaining_ms: Some(5_000),
            wipe_required: false,
        };
        ui.lock.record_failure(
            status,
            &PinUnlockError::Backoff {
                remaining_ms: 5_000,
            },
        );

        let view = ui.render_lock();
        assert_eq!(view.backoff_remaining_ms, Some(5_000));
        assert_eq!(view.remaining_attempts, Some(PIN_WIPE_THRESHOLD - 3));
        assert!(view.prompt.contains("Try again"));
    }

    #[test]
    fn backoff_clears_after_waiting_period() {
        let vault =
            super::super::fixtures::MemoryVault::new(super::super::fixtures::sample_entries());
        let mut ui = super::super::fixtures::build_runtime(vault);

        let status = PinLockStatus {
            consecutive_failures: 3,
            total_failures: 3,
            backoff_remaining_ms: Some(2_000),
            wipe_required: false,
        };
        ui.lock.record_failure(
            status,
            &PinUnlockError::Backoff {
                remaining_ms: 2_000,
            },
        );

        for digit in ['1', '2', '3', '4', '5', '6'] {
            ui.apply_command(UiCommand::InsertChar(digit));
        }

        assert_eq!(ui.apply_command(UiCommand::Activate), UiEffect::None);

        ui.tick(2_000);

        match ui.apply_command(UiCommand::Activate) {
            UiEffect::UnlockRequested { pin } => assert_eq!(pin, "123456"),
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn wipe_state_blocks_unlock() {
        let vault =
            super::super::fixtures::MemoryVault::new(super::super::fixtures::sample_entries());
        let mut ui = super::super::fixtures::build_runtime(vault);

        let status = PinLockStatus {
            consecutive_failures: PIN_WIPE_THRESHOLD,
            total_failures: PIN_WIPE_THRESHOLD,
            backoff_remaining_ms: None,
            wipe_required: true,
        };
        ui.lock
            .record_failure(status, &PinUnlockError::WipeRequired);

        for digit in ['0', '0', '0', '0', '0', '0'] {
            ui.apply_command(UiCommand::InsertChar(digit));
        }

        let effect = ui.apply_command(UiCommand::Activate);
        assert_eq!(effect, UiEffect::None);
        let view = ui.render_lock();
        assert!(view.wipe_required);
        assert!(view.prompt.contains("wipe"));
    }

    #[test]
    fn back_does_not_exit_lock() {
        let vault =
            super::super::fixtures::MemoryVault::new(super::super::fixtures::sample_entries());
        let mut ui = super::super::fixtures::build_runtime(vault);

        assert_eq!(ui.screen(), UiScreen::Lock);
        ui.apply_command(UiCommand::Back);
        assert_eq!(ui.screen(), UiScreen::Lock);
    }
}
