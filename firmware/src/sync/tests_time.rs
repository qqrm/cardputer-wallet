use alloc::string::String;

use super::*;
use crate::sync::test_helpers::fresh_context;
use shared::cdc::CdcCommand;
use shared::schema::{
    DeviceResponse, GetTimeRequest, HelloRequest, HostRequest, PROTOCOL_VERSION, SetTimeRequest,
    StatusRequest, decode_device_response, encode_host_request,
};

#[test]
fn hello_enqueues_ble_session_action() {
    let mut ctx = fresh_context();
    let request = HostRequest::Hello(HelloRequest {
        protocol_version: PROTOCOL_VERSION,
        client_name: String::from("host"),
        client_version: String::from("host-fw"),
    });
    let encoded = encode_host_request(&request).unwrap();
    let (_, response_bytes) = process_host_frame(CdcCommand::Hello, &encoded, &mut ctx).unwrap();
    let response = decode_device_response(&response_bytes).unwrap();
    match response {
        DeviceResponse::Hello(info) => {
            assert_eq!(info.protocol_version, PROTOCOL_VERSION);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    // TODO: Legacy scenario overlapping hello_establishes_session; keep until BLE session flow is consolidated.
    let actions = crate::hid::core::actions::drain();
    assert!(actions.iter().any(|action| matches!(
        action,
        crate::hid::core::actions::DeviceAction::StartSession { .. }
    )));
}

#[test]
fn hello_establishes_session() {
    let mut ctx = fresh_context();
    let request = HostRequest::Hello(HelloRequest {
        protocol_version: PROTOCOL_VERSION,
        client_name: String::from("host"),
        client_version: String::from("host-fw"),
    });
    let encoded = encode_host_request(&request).unwrap();
    let (command, response_bytes) =
        process_host_frame(CdcCommand::Hello, &encoded, &mut ctx).unwrap();
    assert_eq!(command, CdcCommand::Hello);
    let response = decode_device_response(&response_bytes).unwrap();

    match response {
        DeviceResponse::Hello(info) => {
            assert_eq!(info.protocol_version, PROTOCOL_VERSION);
            assert_ne!(info.session_id, 0);
            assert_eq!(info.device_name, "Cardputer Wallet");
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn status_reflects_context_state() {
    let mut ctx = fresh_context();
    ctx.vault_image.extend_from_slice(b"demo-vault");
    ctx.recipients_manifest.extend_from_slice(b"recipients");
    ctx.record_operation(JournalOperation::Add {
        entry_id: String::from("status-entry"),
    });
    ctx.set_epoch_time_ms(1_234_567);
    ctx.vault_generation = 9;

    let request = HostRequest::Status(StatusRequest {
        protocol_version: PROTOCOL_VERSION,
    });
    let encoded = encode_host_request(&request).unwrap();
    let (command, response_bytes) =
        process_host_frame(CdcCommand::Status, &encoded, &mut ctx).unwrap();
    assert_eq!(command, CdcCommand::Status);
    let response = decode_device_response(&response_bytes).unwrap();

    match response {
        DeviceResponse::Status(status) => {
            assert_eq!(status.vault_generation, 9);
            assert_eq!(status.pending_operations, ctx.journal_ops.len() as u32);
            assert_eq!(status.current_time_ms, 1_234_567);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn set_time_updates_clock_and_get_time_reports_it() {
    let mut ctx = fresh_context();
    let set_request = HostRequest::SetTime(SetTimeRequest {
        protocol_version: PROTOCOL_VERSION,
        epoch_millis: 9_876,
    });
    let encoded_set = encode_host_request(&set_request).unwrap();
    let (command, response_bytes) =
        process_host_frame(CdcCommand::SetTime, &encoded_set, &mut ctx).unwrap();
    assert_eq!(command, CdcCommand::Ack);
    let ack = decode_device_response(&response_bytes).unwrap();
    match ack {
        DeviceResponse::Ack(message) => {
            assert!(message.message.contains("9876"));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let get_request = HostRequest::GetTime(GetTimeRequest {
        protocol_version: PROTOCOL_VERSION,
    });
    let encoded_get = encode_host_request(&get_request).unwrap();
    let (command, response_bytes) =
        process_host_frame(CdcCommand::GetTime, &encoded_get, &mut ctx).unwrap();
    assert_eq!(command, CdcCommand::GetTime);
    let time_response = decode_device_response(&response_bytes).unwrap();
    match time_response {
        DeviceResponse::Time(time) => {
            assert_eq!(time.epoch_millis, 9_876);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}
