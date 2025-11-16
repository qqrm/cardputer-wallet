use alloc::boxed::Box;
use alloc::string::String;
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use static_cell::StaticCell;

use crate::sync::SyncContext;
use crate::totp::GlobalTotpProvider;
use crate::ui::{
    Frame, KeyEvent, SecretField, SyncVaultViewModel, UiCommand, UiEffect, UiRuntime, UiScreen,
};

#[cfg(any(test, target_arch = "xtensa"))]
use crate::hid::actions::{
    self, DeviceAction, KeyboardReport, MACRO_BUFFER_CAPACITY, MacroBuffer, MacroStep,
};
#[cfg(any(test, target_arch = "xtensa"))]
use alloc::vec::Vec;
#[cfg(any(test, target_arch = "xtensa"))]
use core::sync::atomic::{AtomicU32, Ordering};

static SYNC_CONTEXT: StaticCell<Mutex<CriticalSectionRawMutex, SyncContext>> = StaticCell::new();
static UI_RUNTIME: StaticCell<Mutex<CriticalSectionRawMutex, UiRuntime>> = StaticCell::new();
#[cfg(any(test, target_arch = "xtensa"))]
static NEXT_HID_SESSION: AtomicU32 = AtomicU32::new(1);

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
    dispatch_ui_effect(&effect);
    effect
}

pub fn ui_apply_command(command: UiCommand) -> UiEffect {
    let effect = ui_runtime().lock(|runtime| runtime.apply_command(command));
    dispatch_ui_effect(&effect);
    effect
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

fn dispatch_ui_effect(effect: &UiEffect) {
    if let UiEffect::SendSecret { entry_id, field } = effect {
        dispatch_secret(entry_id, *field);
    }
}

#[cfg(any(test, target_arch = "xtensa"))]
fn dispatch_secret(entry_id: &str, field: SecretField) {
    if let Some(text) = secret_payload(entry_id, field) {
        if text.is_empty() {
            return;
        }
        if let Some(buffers) = text_to_macro_buffers(&text) {
            let session_id = next_hid_session();
            actions::publish(DeviceAction::StartSession { session_id });
            for buffer in buffers {
                actions::publish(DeviceAction::StreamMacro {
                    session_id,
                    buffer: Box::new(buffer),
                });
            }
            actions::publish(DeviceAction::EndSession);
        }
    }
}

#[cfg(not(any(test, target_arch = "xtensa")))]
fn dispatch_secret(_entry_id: &str, _field: SecretField) {}

#[cfg(any(test, target_arch = "xtensa"))]
fn next_hid_session() -> u32 {
    NEXT_HID_SESSION.fetch_add(1, Ordering::Relaxed)
}

#[cfg(any(test, target_arch = "xtensa"))]
fn secret_payload(entry_id: &str, field: SecretField) -> Option<String> {
    match field {
        SecretField::Username => SyncVaultViewModel::from_system()
            .entry_credentials(entry_id)
            .map(|(username, _)| username),
        SecretField::Password => SyncVaultViewModel::from_system()
            .entry_credentials(entry_id)
            .map(|(_, password)| password),
        SecretField::Totp => GlobalTotpProvider::new().code_for_entry(entry_id),
    }
}

#[cfg(any(test, target_arch = "xtensa"))]
fn text_to_macro_buffers(text: &str) -> Option<Vec<MacroBuffer>> {
    if text.is_empty() {
        return None;
    }
    let mut buffers = Vec::new();
    let mut current = MacroBuffer::new();
    for ch in text.chars() {
        let (mods, usage) = ascii_to_usage(ch)?;
        let steps = [
            MacroStep::Report(KeyboardReport::from_keys(mods, &[usage])),
            MacroStep::Report(KeyboardReport::empty()),
        ];
        for step in steps {
            if current.len() == MACRO_BUFFER_CAPACITY {
                buffers.push(current);
                current = MacroBuffer::new();
            }
            if current.push(step).is_err() {
                return None;
            }
        }
    }
    if !current.is_empty() {
        buffers.push(current);
    }
    Some(buffers)
}

#[cfg(any(test, target_arch = "xtensa"))]
const SHIFT: u8 = 0x02;

#[cfg(any(test, target_arch = "xtensa"))]
fn ascii_to_usage(c: char) -> Option<(u8, u8)> {
    match c {
        'a'..='z' => Some((0, 0x04 + (c as u8 - b'a'))),
        'A'..='Z' => Some((SHIFT, 0x04 + (c as u8 - b'A'))),
        '1'..='9' => Some((0, 0x1E + (c as u8 - b'1'))),
        '0' => Some((0, 0x27)),
        '!' => Some((SHIFT, 0x1E)),
        '@' => Some((SHIFT, 0x1F)),
        '#' => Some((SHIFT, 0x20)),
        '$' => Some((SHIFT, 0x21)),
        '%' => Some((SHIFT, 0x22)),
        '^' => Some((SHIFT, 0x23)),
        '&' => Some((SHIFT, 0x24)),
        '*' => Some((SHIFT, 0x25)),
        '(' => Some((SHIFT, 0x26)),
        ')' => Some((SHIFT, 0x27)),
        '-' => Some((0, 0x2D)),
        '_' => Some((SHIFT, 0x2D)),
        '=' => Some((0, 0x2E)),
        '+' => Some((SHIFT, 0x2E)),
        '[' => Some((0, 0x2F)),
        '{' => Some((SHIFT, 0x2F)),
        ']' => Some((0, 0x30)),
        '}' => Some((SHIFT, 0x30)),
        '\\' => Some((0, 0x31)),
        '|' => Some((SHIFT, 0x31)),
        ';' => Some((0, 0x33)),
        ':' => Some((SHIFT, 0x33)),
        '\'' => Some((0, 0x34)),
        '"' => Some((SHIFT, 0x34)),
        '`' => Some((0, 0x35)),
        '~' => Some((SHIFT, 0x35)),
        ',' => Some((0, 0x36)),
        '<' => Some((SHIFT, 0x36)),
        '.' => Some((0, 0x37)),
        '>' => Some((SHIFT, 0x37)),
        '/' => Some((0, 0x38)),
        '?' => Some((SHIFT, 0x38)),
        ' ' => Some((0, 0x2C)),
        '\n' | '\r' => Some((0, 0x28)),
        '\t' => Some((0, 0x2B)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hid::actions;
    use crate::totp;
    use crate::ui::{EntrySecretMaterial, EntrySummary};
    use shared::vault::{SecretString, TotpAlgorithm, TotpConfig};

    fn sample_entry(id: &str) -> EntrySummary {
        EntrySummary {
            id: id.into(),
            title: String::from("Sample"),
            username: String::from("admin"),
            last_used: String::from("2024-01-01"),
            totp: Some(String::from("cfg")),
            note: None,
        }
    }

    fn store_credentials(entry_id: &str, username: &str, password: &str) {
        let view = SyncVaultViewModel::from_system();
        view.replace_entries(
            vec![sample_entry(entry_id)],
            vec![EntrySecretMaterial {
                entry_id: entry_id.into(),
                username: username.into(),
                password: SecretString::from(password),
            }],
            vec![],
        );
    }

    #[test]
    fn dispatches_username_macro() {
        actions::clear();
        store_credentials("alpha", "admin", "secret");

        let effect = UiEffect::SendSecret {
            entry_id: String::from("alpha"),
            field: SecretField::Username,
        };
        dispatch_ui_effect(&effect);

        let drained = actions::drain();
        assert!(
            drained
                .iter()
                .any(|action| matches!(action, DeviceAction::StartSession { .. }))
        );
        assert!(
            drained
                .iter()
                .any(|action| matches!(action, DeviceAction::EndSession))
        );
        let macro_actions: Vec<_> = drained
            .into_iter()
            .filter_map(|action| match action {
                DeviceAction::StreamMacro { buffer, .. } => Some(buffer),
                _ => None,
            })
            .collect();
        assert!(!macro_actions.is_empty());
        let first = &macro_actions[0];
        let mut reports = first
            .iter()
            .filter_map(|step| match step {
                MacroStep::Report(report) if report.keys[0] != 0 => Some(report.keys[0]),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(reports.len(), 5);
        assert_eq!(reports[0], 0x04); // 'a'
    }

    #[test]
    fn splits_long_password_into_multiple_macros() {
        actions::clear();
        let password = "abcdefghijklmnopqrstuvwxyz";
        store_credentials("beta", "user", password);
        let effect = UiEffect::SendSecret {
            entry_id: String::from("beta"),
            field: SecretField::Password,
        };
        dispatch_ui_effect(&effect);
        let macro_actions: Vec<_> = actions::drain()
            .into_iter()
            .filter(|action| matches!(action, DeviceAction::StreamMacro { .. }))
            .collect();
        assert!(macro_actions.len() >= 2);
    }

    #[test]
    fn sends_totp_code_when_available() {
        actions::clear();
        store_credentials("gamma", "ops", "hidden");
        let config = TotpConfig {
            secret: SecretString::from("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
        };
        totp::reset();
        totp::replace_configs(vec![(String::from("gamma"), config)]);
        totp::sync_time(59_000);
        totp::select_entry(Some("gamma"));
        let expected = totp::hid_code().expect("totp code");

        let effect = UiEffect::SendSecret {
            entry_id: String::from("gamma"),
            field: SecretField::Totp,
        };
        dispatch_ui_effect(&effect);

        let digits: String = actions::drain()
            .into_iter()
            .find_map(|action| match action {
                DeviceAction::StreamMacro { buffer, .. } => Some(buffer),
                _ => None,
            })
            .map(|buffer| {
                buffer
                    .iter()
                    .filter_map(|step| match step {
                        MacroStep::Report(report) if report.keys[0] != 0 => Some(report.keys[0]),
                        _ => None,
                    })
                    .map(|code| match code {
                        0x27 => '0',
                        0x1E => '1',
                        0x1F => '2',
                        0x20 => '3',
                        0x21 => '4',
                        0x22 => '5',
                        0x23 => '6',
                        0x24 => '7',
                        0x25 => '8',
                        0x26 => '9',
                        _ => '?',
                    })
                    .collect()
            })
            .unwrap();
        assert_eq!(digits, expected);
    }
}
