use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use static_cell::StaticCell;

use crate::sync::SyncContext;
use crate::totp::GlobalTotpProvider;
use crate::ui::{Frame, KeyEvent, SyncVaultViewModel, UiCommand, UiEffect, UiRuntime, UiScreen};

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
    ui_runtime().lock(|runtime| runtime.handle_key_event(event))
}

pub fn ui_apply_command(command: UiCommand) -> UiEffect {
    ui_runtime().lock(|runtime| runtime.apply_command(command))
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
