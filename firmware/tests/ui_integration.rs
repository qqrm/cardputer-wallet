#![cfg(feature = "ui-tests")]

use firmware::totp::SharedTotp;
use firmware::ui::{
    EntrySummary, JournalEntryView, UiRuntime, VaultViewModel, ViewContent,
    transport::{self, TransportState},
};
use firmware::{PinLockState, SyncContext};
use shared::cdc::CdcCommand;
use shared::schema::{self, PROTOCOL_VERSION};
use shared::vault::{SecretString, TotpAlgorithm, TotpConfig};

fn sample_entry() -> EntrySummary {
    EntrySummary {
        id: String::from("alpha"),
        title: String::from("Primary"),
        username: String::from("admin"),
        last_used: String::from("2024-01-03T00:00:00Z"),
        totp: Some(String::from("totp")),
        note: None,
    }
}

fn sample_totp_config() -> TotpConfig {
    TotpConfig {
        secret: SecretString::from("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
    }
}

#[derive(Clone)]
struct TestVault {
    entries: Vec<EntrySummary>,
}

impl TestVault {
    fn new(entries: Vec<EntrySummary>) -> Self {
        Self { entries }
    }
}

impl VaultViewModel for TestVault {
    fn entries(&self) -> Vec<EntrySummary> {
        self.entries.clone()
    }

    fn entry(&self, id: &str) -> Option<EntrySummary> {
        self.entries.iter().find(|entry| entry.id == id).cloned()
    }

    fn journal(&self) -> Vec<JournalEntryView> {
        Vec::new()
    }
}

#[test]
fn ui_renders_entries_and_transport_status() {
    transport::set_usb_state(TransportState::Offline);
    transport::set_ble_state(TransportState::Offline);

    let mut totp = SharedTotp::new();
    totp.upsert_config("alpha", sample_totp_config());
    totp.sync_time(59_000);

    let vault = TestVault::new(vec![sample_entry()]);
    let mut ui = UiRuntime::new(Box::new(vault), Box::new(totp));
    let status = PinLockState::new().status(59_000);
    ui.register_unlock_success(status);

    transport::set_usb_state(TransportState::Connected);
    transport::set_ble_state(TransportState::Waiting);

    let frame = ui.render();
    assert_eq!(frame.transport.usb.state, TransportState::Connected);
    assert_eq!(frame.transport.ble.state, TransportState::Waiting);

    match frame.content {
        ViewContent::Home(home) => {
            assert_eq!(home.recent.entries.len(), 1);
            assert_eq!(home.recent.entries[0].title, "Primary");
            assert!(home.totp.code.is_some());
        }
        other => panic!("expected home view, got {other:?}"),
    }
}

#[test]
fn set_time_updates_totp_clock() {
    let mut ctx = SyncContext::new();
    let request = schema::HostRequest::SetTime(schema::SetTimeRequest {
        protocol_version: PROTOCOL_VERSION,
        epoch_millis: 123_456,
    });
    let frame = schema::encode_host_request(&request).expect("encode set time");
    let _ = firmware::sync::process_host_frame(CdcCommand::SetTime, &frame, &mut ctx)
        .expect("process set time");

    assert_eq!(ctx.current_time_ms(), 123_456);
}
