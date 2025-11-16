use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::fmt;

use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use static_cell::StaticCell;

use crate::sync::SyncContext;
use crate::ui::{
    EntrySummary, Frame, JournalEntryView, KeyEvent, TotpProvider, TotpSnapshot, UiCommand,
    UiEffect, UiRuntime, UiScreen, VaultViewModel,
    transport::{self, TransportIndicators},
};

static SYNC_CONTEXT: StaticCell<Mutex<CriticalSectionRawMutex, SyncContext>> = StaticCell::new();
static UI_RUNTIME: StaticCell<Mutex<CriticalSectionRawMutex, UiRuntime>> = StaticCell::new();
static SYNC_TRANSPORT: StaticCell<Mutex<CriticalSectionRawMutex, Box<dyn SyncTransport + Send>>> =
    StaticCell::new();

fn new_ui_runtime() -> UiRuntime {
    UiRuntime::new(
        Box::new(SyncVaultViewModel::from_system()),
        Box::new(GlobalTotpProvider::new()),
    )
}

fn sync_transport() -> &'static Mutex<CriticalSectionRawMutex, Box<dyn SyncTransport + Send>> {
    SYNC_TRANSPORT.init_with(|| Mutex::new(Box::new(NoopSyncTransport)))
}

pub fn sync_context() -> &'static Mutex<CriticalSectionRawMutex, SyncContext> {
    SYNC_CONTEXT.init_with(|| Mutex::new(SyncContext::new()))
}

pub fn replace_sync_context(new_ctx: SyncContext) {
    unsafe {
        sync_context().lock_mut(|ctx| *ctx = new_ctx);
    }
}

pub fn replace_sync_transport(new_transport: Box<dyn SyncTransport + Send>) {
    unsafe {
        sync_transport().lock_mut(|current| *current = new_transport);
    }
}

pub fn ui_runtime() -> &'static Mutex<CriticalSectionRawMutex, UiRuntime> {
    UI_RUNTIME.init_with(|| Mutex::new(new_ui_runtime()))
}

pub fn reset_ui_runtime() {
    unsafe {
        ui_runtime().lock_mut(|runtime| {
            *runtime = new_ui_runtime();
        });
    }
}

pub fn ui_handle_key_event(event: KeyEvent) -> UiEffect {
    let effect = unsafe { ui_runtime().lock_mut(|runtime| runtime.handle_key_event(event)) };
    handle_ui_effect(&effect);
    effect
}

pub fn ui_apply_command(command: UiCommand) -> UiEffect {
    let effect = unsafe { ui_runtime().lock_mut(|runtime| runtime.apply_command(command)) };
    handle_ui_effect(&effect);
    effect
}

pub fn ui_tick(elapsed_ms: u32) {
    unsafe {
        ui_runtime().lock_mut(|runtime| runtime.tick(elapsed_ms));
    }
}

pub fn ui_render_frame() -> Frame {
    ui_runtime().lock(|runtime| runtime.render())
}

pub fn ui_screen() -> UiScreen {
    ui_runtime().lock(|runtime| runtime.screen())
}

fn handle_ui_effect(effect: &UiEffect) {
    if matches!(effect, UiEffect::StartSync) {
        start_sync_session();
    }
}

fn start_sync_session() {
    unsafe {
        ui_runtime().lock_mut(|runtime| runtime.open_sync_overlay());
    }

    let indicators = transport::snapshot();
    let pending = sync_context().lock(|ctx| ctx.pending_operations());
    update_sync_stage(5, describe_transport_stage(&indicators, pending));

    let outcome = if pending == 0 {
        Ok(())
    } else {
        unsafe {
            sync_context()
                .lock_mut(|ctx| sync_transport().lock_mut(|transport| transport.run_sync(ctx)))
        }
    };

    match outcome {
        Ok(()) => {
            unsafe {
                sync_context().lock_mut(|ctx| ctx.clear_pending_operations());
            }
            update_sync_stage(100, describe_completion_stage(&indicators, pending));
            unsafe {
                ui_runtime().lock_mut(|runtime| runtime.close_sync_overlay());
            }
        }
        Err(err) => {
            update_sync_stage(5, describe_error_stage(&indicators, &err));
        }
    }
}

fn update_sync_stage(progress_percent: u8, stage: String) {
    unsafe {
        ui_runtime().lock_mut(|runtime| runtime.update_sync_progress(progress_percent, stage));
    }
}

fn describe_transport_stage(indicators: &TransportIndicators, pending: usize) -> String {
    let pending_text = if pending == 0 {
        String::from("journal up to date")
    } else {
        format!("{pending} pending entries")
    };

    format!(
        "{} | {} | {}",
        indicators.usb.text.as_str(),
        indicators.ble.text.as_str(),
        pending_text
    )
}

fn describe_completion_stage(indicators: &TransportIndicators, cleared: usize) -> String {
    format!(
        "{} | {} | {} cleared",
        indicators.usb.text.as_str(),
        indicators.ble.text.as_str(),
        cleared
    )
}

fn describe_error_stage(indicators: &TransportIndicators, err: &SyncError) -> String {
    format!(
        "{} | {} | failed: {}",
        indicators.usb.text.as_str(),
        indicators.ble.text.as_str(),
        err
    )
}

struct SyncVaultViewModel;

impl SyncVaultViewModel {
    fn from_system() -> Self {
        Self
    }
}

impl VaultViewModel for SyncVaultViewModel {
    fn entries(&self) -> Vec<EntrySummary> {
        Vec::new()
    }

    fn entry(&self, _id: &str) -> Option<EntrySummary> {
        None
    }

    fn journal(&self) -> Vec<JournalEntryView> {
        Vec::new()
    }
}

struct GlobalTotpProvider;

impl GlobalTotpProvider {
    fn new() -> Self {
        Self
    }
}

impl TotpProvider for GlobalTotpProvider {
    fn select_entry(&mut self, _entry_id: Option<&str>) {}

    fn snapshot(&self) -> TotpSnapshot {
        TotpSnapshot::empty(30)
    }

    fn tick(&mut self, _elapsed_ms: u32) {}
}

pub trait SyncTransport {
    fn run_sync(&mut self, ctx: &mut SyncContext) -> Result<(), SyncError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncError {
    message: String,
}

impl SyncError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[derive(Default)]
struct NoopSyncTransport;

impl SyncTransport for NoopSyncTransport {
    fn run_sync(&mut self, _ctx: &mut SyncContext) -> Result<(), SyncError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::UiCommand;
    use crate::ui::transport::{self, TransportState};
    use shared::schema::JournalOperation;

    struct TransportGuard;

    impl TransportGuard {
        fn install(mock: Box<dyn SyncTransport + Send>) -> Self {
            replace_sync_transport(mock);
            Self
        }
    }

    impl Drop for TransportGuard {
        fn drop(&mut self) {
            replace_sync_transport(Box::new(NoopSyncTransport));
        }
    }

    struct MockCdcTransport {
        result: Result<(), SyncError>,
    }

    impl MockCdcTransport {
        fn succeeds() -> Self {
            Self { result: Ok(()) }
        }

        fn fails(message: &str) -> Self {
            Self {
                result: Err(SyncError::new(message)),
            }
        }
    }

    impl SyncTransport for MockCdcTransport {
        fn run_sync(&mut self, _ctx: &mut SyncContext) -> Result<(), SyncError> {
            self.result.clone()
        }
    }

    fn unlock_home() {
        reset_ui_runtime();
        transport::set_usb_state(TransportState::Connected);
        transport::set_ble_state(TransportState::Waiting);
        ui_apply_command(UiCommand::Activate);
    }

    #[test]
    fn start_sync_clears_journal_and_returns_home() {
        unlock_home();
        unsafe {
            sync_context().lock_mut(|ctx| {
                ctx.record_operation(JournalOperation::Add {
                    entry_id: "alpha".into(),
                });
            });
        }
        let _guard = TransportGuard::install(Box::new(MockCdcTransport::succeeds()));

        ui_apply_command(UiCommand::StartSync);

        assert_eq!(ui_screen(), UiScreen::Home);
        sync_context().lock(|ctx| assert_eq!(ctx.pending_operations(), 0));
        let (progress, stage) = ui_runtime().lock(|runtime| runtime.sync_progress());
        assert_eq!(progress, 100);
        assert!(stage.contains("cleared"));
    }

    #[test]
    fn start_sync_surfaces_errors_and_preserves_journal() {
        unlock_home();
        unsafe {
            sync_context().lock_mut(|ctx| {
                ctx.record_operation(JournalOperation::Add {
                    entry_id: "beta".into(),
                });
            });
        }
        let _guard = TransportGuard::install(Box::new(MockCdcTransport::fails("link lost")));

        ui_apply_command(UiCommand::StartSync);

        assert_eq!(ui_screen(), UiScreen::Sync);
        sync_context().lock(|ctx| assert_eq!(ctx.pending_operations(), 1));
        let (progress, stage) = ui_runtime().lock(|runtime| runtime.sync_progress());
        assert_eq!(progress, 5);
        assert!(stage.contains("failed"));
        assert!(stage.contains("link lost"));
    }
}
