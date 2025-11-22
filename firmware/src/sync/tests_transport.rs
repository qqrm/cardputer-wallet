use alloc::{string::String, vec::Vec};

use super::{protocol, *};
use crate::sync::test_helpers::{frame_header_for_payload, fresh_context};
use shared::cdc::transport::decode_frame;
use shared::cdc::{CdcCommand, FRAME_HEADER_SIZE};
use shared::schema::{
    HelloRequest, HostRequest, PROTOCOL_VERSION, ProtocolError, PullVaultRequest, StatusRequest,
    encode_host_request,
};

#[test]
fn unsupported_protocol_is_rejected() {
    let mut ctx = fresh_context();
    let request = HostRequest::PullVault(PullVaultRequest {
        protocol_version: PROTOCOL_VERSION + 1,
        host_buffer_size: 1,
        max_chunk_size: 1,
        known_generation: None,
    });
    let encoded = encode_host_request(&request).unwrap();
    let error = process_host_frame(CdcCommand::PullVault, &encoded, &mut ctx)
        .expect_err("expected rejection");
    assert!(matches!(error, ProtocolError::UnsupportedProtocol(_)));
}

#[test]
fn mismatched_command_is_rejected() {
    let mut ctx = fresh_context();
    let request = HostRequest::Status(StatusRequest {
        protocol_version: PROTOCOL_VERSION,
    });
    let encoded = encode_host_request(&request).unwrap();
    let error =
        process_host_frame(CdcCommand::Hello, &encoded, &mut ctx).expect_err("command mismatch");
    assert!(matches!(error, ProtocolError::InvalidCommand));
}

#[test]
fn checksum_validation_detects_corruption() {
    let mut ctx = fresh_context();
    let request = HostRequest::Hello(HelloRequest {
        protocol_version: PROTOCOL_VERSION,
        client_name: String::from("host"),
        client_version: String::from("fw"),
    });
    let encoded = encode_host_request(&request).unwrap();
    let header = frame_header_for_payload(CdcCommand::Hello, &encoded);

    let mut corrupted = encoded.clone();
    *corrupted.last_mut().unwrap() ^= 0xFF;

    let transport_error = decode_frame(&header, &corrupted).expect_err("checksum error");
    let protocol_error: ProtocolError = transport_error.into();
    assert!(matches!(protocol_error, ProtocolError::ChecksumMismatch));

    decode_frame(&header, &encoded).expect("valid payload");
    let error =
        process_host_frame(CdcCommand::Hello, &corrupted, &mut ctx).expect_err("checksum error");
    assert!(matches!(error, ProtocolError::Decode(_)));
}

#[test]
fn transport_limit_matches_firmware_max_size() {
    let payload = vec![0u8; FRAME_MAX_SIZE];
    let header = frame_header_for_payload(CdcCommand::Hello, &payload);

    assert_eq!(header.length as usize, FRAME_MAX_SIZE);
    assert_eq!(header.command, CdcCommand::Hello);
    assert_eq!(
        FRAME_HEADER_SIZE + payload.len(),
        FRAME_HEADER_SIZE + FRAME_MAX_SIZE
    );
}
