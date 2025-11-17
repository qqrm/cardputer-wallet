use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use embassy_sync::channel::{Channel, Receiver as ChannelReceiver, Sender as ChannelSender};
use embassy_sync::signal::Signal;
use embassy_sync::watch::{Receiver as WatchReceiver, Sender as WatchSender, Watch};
use static_cell::StaticCell;

use crate::sync::SyncContext;
use crate::totp::GlobalTotpProvider;
use crate::ui::{Frame, KeyEvent, SyncVaultViewModel, UiCommand, UiEffect, UiRuntime, UiScreen};
use zeroize::Zeroizing;

#[cfg(target_arch = "xtensa")]
use embassy_futures::select::{Either, select};
#[cfg(target_arch = "xtensa")]
use embassy_time::{Duration, Ticker};

type UiMutex = CriticalSectionRawMutex;

const UI_CHANNEL_DEPTH: usize = 8;
const UI_STATE_SUBSCRIBERS: usize = 4;
const UI_TICK_MS: u64 = 50;

static SYNC_CONTEXT: StaticCell<Mutex<UiMutex, SyncContext>> = StaticCell::new();
static UI_COMMANDS: Channel<UiMutex, UiTaskMessage, UI_CHANNEL_DEPTH> = Channel::new();
static UI_FRAMES: Watch<UiMutex, Frame, UI_STATE_SUBSCRIBERS> = Watch::new();
static UI_SCREENS: Watch<UiMutex, UiScreen, UI_STATE_SUBSCRIBERS> = Watch::new_with(UiScreen::Lock);
static UI_EFFECTS: Signal<UiMutex, UiEffect> = Signal::new();

fn new_ui_runtime() -> UiRuntime {
    UiRuntime::new(
        Box::new(SyncVaultViewModel::from_system()),
        Box::new(GlobalTotpProvider::new()),
    )
}

pub fn sync_context() -> &'static Mutex<UiMutex, SyncContext> {
    SYNC_CONTEXT.init_with(|| Mutex::new(SyncContext::new()))
}

pub fn replace_sync_context(new_ctx: SyncContext) {
    sync_context().lock(|ctx| *ctx = new_ctx);
}

pub type UiCommandSender = ChannelSender<'static, UiMutex, UiTaskMessage, UI_CHANNEL_DEPTH>;
pub type UiCommandReceiver = ChannelReceiver<'static, UiMutex, UiTaskMessage, UI_CHANNEL_DEPTH>;
pub type UiFrameReceiver = WatchReceiver<'static, UiMutex, Frame, UI_STATE_SUBSCRIBERS>;
pub type UiScreenReceiver = WatchReceiver<'static, UiMutex, UiScreen, UI_STATE_SUBSCRIBERS>;
type UiFrameSender = WatchSender<'static, UiMutex, Frame, UI_STATE_SUBSCRIBERS>;
type UiScreenSender = WatchSender<'static, UiMutex, UiScreen, UI_STATE_SUBSCRIBERS>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UiTaskMessage {
    Key(KeyEvent),
    Command(UiCommand),
}

pub fn ui_command_sender() -> UiCommandSender {
    UI_COMMANDS.sender()
}

pub fn ui_command_receiver() -> UiCommandReceiver {
    UI_COMMANDS.receiver()
}

pub fn ui_frame_receiver() -> Option<UiFrameReceiver> {
    UI_FRAMES.receiver()
}

pub fn ui_screen_receiver() -> Option<UiScreenReceiver> {
    UI_SCREENS.receiver()
}

pub fn ui_effect_signal() -> &'static Signal<UiMutex, UiEffect> {
    &UI_EFFECTS
}

#[cfg(target_arch = "xtensa")]
#[embassy_executor::task]
pub async fn ui_task() {
    let mut runtime = new_ui_runtime();
    publish_ui_state(&runtime);

    let receiver = ui_command_receiver();
    let mut ticker = Ticker::every(Duration::from_millis(UI_TICK_MS));

    loop {
        match select(receiver.receive(), ticker.next()).await {
            Either::First(message) => {
                handle_ui_message(&mut runtime, message);
                publish_ui_state(&runtime);
            }
            Either::Second(_) => {
                runtime.tick(UI_TICK_MS as u32);
                publish_ui_state(&runtime);
            }
        }
    }
}

fn handle_ui_message(runtime: &mut UiRuntime, message: UiTaskMessage) {
    let effect = match message {
        UiTaskMessage::Key(event) => runtime.handle_key_event(event),
        UiTaskMessage::Command(command) => runtime.apply_command(command),
    };

    dispatch_ui_effect(runtime, effect);
}

fn dispatch_ui_effect(runtime: &mut UiRuntime, effect: UiEffect) {
    match effect {
        UiEffect::UnlockRequested { pin } => {
            handle_unlock_request(runtime, pin);
        }
        UiEffect::None => {}
        other => {
            ui_effect_signal().signal(other);
        }
    }
}

fn handle_unlock_request(runtime: &mut UiRuntime, pin: String) {
    let mut pin_bytes = Zeroizing::new(pin.into_bytes());
    let (result, status) = sync_context().lock(|ctx| {
        let now = ctx.current_time_ms();
        let result = ctx.unlock_with_pin(pin_bytes.as_slice(), now);
        let status = ctx.pin_lock_status(now);
        (result, status)
    });

    match result {
        Ok(()) => runtime.register_unlock_success(status),
        Err(error) => runtime.register_unlock_failure(status, &error),
    }
}

fn publish_ui_state(runtime: &UiRuntime) {
    frame_sender().send(runtime.render());
    screen_sender().send(runtime.screen());
}

fn frame_sender() -> UiFrameSender {
    UI_FRAMES.sender()
}

fn screen_sender() -> UiScreenSender {
    UI_SCREENS.sender()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PIN_WIPE_THRESHOLD;
    use crate::ui::{input::UiCommand, render::ViewContent};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn setup_context(pin: &str) -> UiRuntime {
        replace_sync_context(SyncContext::new());
        sync_context().lock(|ctx| {
            let mut rng = ChaCha20Rng::from_seed([0xAA; 32]);
            ctx.test_configure_pin(pin.as_bytes(), &mut rng)
                .expect("configure pin");
        });

        let runtime = new_ui_runtime();
        publish_ui_state(&runtime);
        runtime
    }

    fn drive_ui(runtime: &mut UiRuntime, message: UiTaskMessage) {
        handle_ui_message(runtime, message);
        publish_ui_state(runtime);
    }

    fn submit_pin(runtime: &mut UiRuntime, pin: &str) {
        for ch in pin.chars() {
            drive_ui(runtime, UiTaskMessage::Command(UiCommand::InsertChar(ch)));
        }
        drive_ui(runtime, UiTaskMessage::Command(UiCommand::Activate));
    }

    #[test]
    fn valid_pin_unlocks_home() {
        let pin = "123456";
        let mut runtime = setup_context(pin);
        let mut screen_rx = ui_screen_receiver().expect("screen receiver");
        assert_eq!(screen_rx.try_get(), Some(UiScreen::Lock));

        submit_pin(&mut runtime, pin);
        assert_eq!(screen_rx.try_get(), Some(UiScreen::Home));
    }

    #[test]
    fn wrong_pin_reports_backoff_and_wipe() {
        let mut runtime = setup_context("654321");
        let mut frame_rx = ui_frame_receiver().expect("frame receiver");
        let wrong = "000000";
        let mut saw_backoff = false;
        let mut attempts = 0usize;

        while attempts < (PIN_WIPE_THRESHOLD as usize + 5) {
            submit_pin(&mut runtime, wrong);
            attempts += 1;

            let frame = frame_rx.try_get().unwrap_or_else(|| runtime.render());
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
