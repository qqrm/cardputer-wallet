#![cfg(feature = "ui-tests")]

use firmware::sync::SyncContext;
use firmware::system;
use firmware::totp;
use firmware::ui::{
    input::UiCommand,
    state::UiScreen,
    transport::{self, TransportState},
};
use shared::cdc::CdcCommand;
use shared::schema::{self, PROTOCOL_VERSION};
use shared::totp::generate;

use shared::vault::{SecretString, TotpAlgorithm, TotpConfig};

#[test]
fn home_screen_reflects_transport_status() {
    transport::reset();
    totp::reset();

    transport::set_usb_state(TransportState::Connected);
    transport::set_ble_state(TransportState::Waiting);

    system::reset_ui_runtime();
    assert_eq!(system::ui_screen(), UiScreen::Lock);

    system::ui_apply_command(UiCommand::Activate);
    assert_eq!(system::ui_screen(), UiScreen::Home);

    let frame = system::ui_render_frame();
    assert_eq!(frame.transport.usb.state, TransportState::Connected);
    assert_eq!(frame.transport.ble.state, TransportState::Waiting);
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
