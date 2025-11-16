use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use static_cell::StaticCell;

use crate::crypto::PinUnlockError;
use crate::sync::SyncContext;
use crate::totp::GlobalTotpProvider;
use crate::ui::{Frame, KeyEvent, SyncVaultViewModel, UiCommand, UiEffect, UiRuntime, UiScreen};
use zeroize::Zeroizing;

static SYNC_CONTEXT: StaticCell<Mutex<CriticalSectionRawMutex, SyncContext>> = StaticCell::new();
static UI_RUNTIME: StaticCell<Mutex<CriticalSectionRawMutex, UiRuntime>> = StaticCell::new();

fn new_ui_runtime() -> UiRuntime {
    UiRuntime::new(
        Box::new(SyncVaultViewModel::from_system()),
        Box::new(GlobalTotpProvider::new()),
    )
}

pub fn sync_context() -> &'static Mutex<CriticalSectionRawMutex, SyncContext> {
    SYNC_CONTEXT.init_with(|| Mutex::new(SyncContext::new()))
}

pub fn replace_sync_context(new_ctx: SyncContext) {
    sync_context().lock(|ctx| *ctx = new_ctx);
}

pub fn ui_runtime() -> &'static Mutex<CriticalSectionRawMutex, UiRuntime> {
    UI_RUNTIME.init_with(|| Mutex::new(new_ui_runtime()))
}

pub fn reset_ui_runtime() {
    ui_runtime().lock(|runtime| {
        *runtime = new_ui_runtime();
    });
}

pub fn ui_handle_key_event(event: KeyEvent) -> UiEffect {
    let effect = ui_runtime().lock(|runtime| runtime.handle_key_event(event));
    dispatch_ui_effect(effect)
}

pub fn ui_apply_command(command: UiCommand) -> UiEffect {
    let effect = ui_runtime().lock(|runtime| runtime.apply_command(command));
    dispatch_ui_effect(effect)
}

pub fn ui_tick(elapsed_ms: u32) {
    ui_runtime().lock(|runtime| runtime.tick(elapsed_ms));
}

pub fn ui_render_frame() -> Frame {
    ui_runtime().lock(|runtime| runtime.render())
}

pub fn ui_screen() -> UiScreen {
    ui_runtime().lock(|runtime| runtime.screen())
}

fn dispatch_ui_effect(effect: UiEffect) -> UiEffect {
    match effect {
        UiEffect::UnlockRequested { pin } => {
            handle_unlock_request(pin);
            UiEffect::None
        }
        other => other,
    }
}

fn handle_unlock_request(pin: String) {
    let mut pin_bytes = Zeroizing::new(pin.into_bytes());
    let (result, status) = sync_context().lock(|ctx| {
        let now = ctx.current_time_ms();
        let result = ctx.unlock_with_pin(pin_bytes.as_slice(), now);
        let status = ctx.pin_lock_status(now);
        (result, status)
    });

    match result {
        Ok(()) => {
            ui_runtime().lock(|runtime| runtime.register_unlock_success(status));
        }
        Err(error) => {
            ui_runtime().lock(|runtime| runtime.register_unlock_failure(status, &error));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PIN_WIPE_THRESHOLD;
    use crate::ui::{input::UiCommand, render::ViewContent};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn setup_context(pin: &str) {
        replace_sync_context(SyncContext::new());
        sync_context().lock(|ctx| {
            let mut rng = ChaCha20Rng::from_seed([0xAA; 32]);
            ctx.test_configure_pin(pin.as_bytes(), &mut rng)
                .expect("configure pin");
        });
        reset_ui_runtime();
    }

    fn submit_pin(pin: &str) {
        for ch in pin.chars() {
            ui_apply_command(UiCommand::InsertChar(ch));
        }
        ui_apply_command(UiCommand::Activate);
    }

    #[test]
    fn valid_pin_unlocks_home() {
        let pin = "123456";
        setup_context(pin);
        assert_eq!(ui_screen(), UiScreen::Lock);

        submit_pin(pin);
        assert_eq!(ui_screen(), UiScreen::Home);
    }

    #[test]
    fn wrong_pin_reports_backoff_and_wipe() {
        setup_context("654321");
        let wrong = "000000";
        let mut saw_backoff = false;
        let mut attempts = 0usize;

        while attempts < (PIN_WIPE_THRESHOLD as usize + 5) {
            submit_pin(wrong);
            attempts += 1;

            let frame = ui_render_frame();
            let ViewContent::Lock(lock) = frame.content else {
                panic!("expected lock view");
            };

            if attempts == 1 {
                assert_eq!(lock.remaining_attempts, Some(PIN_WIPE_THRESHOLD - 1));
            }

            if let Some(remaining) = lock.backoff_remaining_ms {
                saw_backoff = true;
                assert!(lock.prompt.contains("Try again"));
                sync_context().lock(|ctx| {
                    let now = ctx.current_time_ms();
                    ctx.test_set_current_time_ms(now.saturating_add(remaining + 1));
                });
            }

            if lock.wipe_required {
                assert!(lock.prompt.contains("wipe"));
                assert!(saw_backoff);
                break;
            }
        }

        assert!(saw_backoff);
    }
}
