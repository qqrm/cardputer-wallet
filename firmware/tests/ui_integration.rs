#![cfg(feature = "ui-tests")]

use firmware::sync::SyncContext;
use firmware::system;
use firmware::totp;
use firmware::ui::{
    self,
    input::UiCommand,
    state::UiScreen,
    transport::{self, TransportState},
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use shared::cdc::CdcCommand;
use shared::schema::{self, JournalOperation, PROTOCOL_VERSION};
use shared::totp::generate;
use shared::vault::{
    SecretString, TotpAlgorithm, TotpConfig, VaultEntry, VaultMetadata, VaultSnapshot,
    encrypt_snapshot,
};
use uuid::Uuid;

fn sample_snapshot(entry_id: Uuid) -> VaultSnapshot {
    VaultSnapshot {
        version: 1,
        metadata: VaultMetadata {
            generation: 1,
            created_at: "2024-01-01T00:00:00Z".into(),
            updated_at: "2024-01-02T00:00:00Z".into(),
        },
        entries: vec![VaultEntry {
            id: entry_id,
            title: "Primary".into(),
            service: "example".into(),
            domains: vec!["example.com".into()],
            username: "admin".into(),
            password: SecretString::from("secret"),
            totp: Some(TotpConfig {
                secret: SecretString::from("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
                algorithm: TotpAlgorithm::Sha1,
                digits: 6,
                period: 30,
            }),
            tags: vec![],
            r#macro: None,
            updated_at: "2024-01-02T00:00:00Z".into(),
            used_at: Some("2024-01-03T00:00:00Z".into()),
        }],
    }
}

fn stage_context(ctx: &mut SyncContext, snapshot: &VaultSnapshot, key: [u8; 32]) {
    let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
    let encrypted = encrypt_snapshot(snapshot, &key, &mut rng).expect("encrypt snapshot");
    ctx.test_set_vault_key(key);
    ctx.test_set_vault_image(encrypted);
    ctx.test_set_journal(vec![JournalOperation::Add {
        entry_id: snapshot.entries[0].id.to_string(),
    }]);
}

#[test]
fn ui_renders_entries_and_transport_status() {
    transport::reset();
    totp::reset();

    let entry_id = Uuid::from_u128(0xAABBCCDD00112233445566778899AABB);
    let snapshot = sample_snapshot(entry_id);
    let key = [0x11u8; 32];

    system::sync_context().lock(|ctx| {
        *ctx = SyncContext::new();
        stage_context(ctx, &snapshot, key);
    });

    totp::sync_time(59_000);
    transport::set_usb_state(TransportState::Connected);
    transport::set_ble_state(TransportState::Waiting);

    system::reset_ui_runtime();
    assert_eq!(system::ui_screen(), UiScreen::Lock);
    system::ui_apply_command(UiCommand::Activate);
    assert_eq!(system::ui_screen(), UiScreen::Home);

    let frame = system::ui_render_frame();
    assert_eq!(frame.transport.usb.state, TransportState::Connected);
    assert_eq!(frame.transport.ble.state, TransportState::Waiting);

    match frame.content {
        ui::render::ViewContent::Home(home) => {
            assert_eq!(home.recent.entries.len(), 1);
            assert_eq!(home.recent.entries[0].title, "Primary");
            assert!(home.totp.code.is_some());
        }
        other => panic!("expected home view, got {other:?}"),
    }
}

#[test]
fn set_time_updates_totp_clock() {
    totp::reset();
    let mut ctx = SyncContext::new();
    let request = schema::HostRequest::SetTime(schema::SetTimeRequest {
        protocol_version: PROTOCOL_VERSION,
        epoch_millis: 123_456,
    });
    let frame = schema::encode_host_request(&request).expect("encode set time");
    let _ = firmware::sync::process_host_frame(CdcCommand::SetTime, &frame, &mut ctx)
        .expect("process set time");

    let config = TotpConfig {
        secret: SecretString::from("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
    };
    let expected = generate(&config, 123_456).expect("generate totp");
    totp::replace_configs(vec![(String::from("alpha"), config)]);
    totp::select_entry(Some("alpha"));
    assert_eq!(totp::hid_code(), Some(expected.code));
}
