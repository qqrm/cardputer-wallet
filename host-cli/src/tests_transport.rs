use std::io::Cursor;

use shared::cdc::transport::{command_for_request, encode_frame};
use shared::cdc::{CdcCommand, FRAME_HEADER_SIZE, FrameHeader, compute_crc32};
use shared::error::SharedError;
use shared::schema::{
    DeviceErrorCode, DeviceResponse, HostRequest, NackResponse, PROTOCOL_VERSION, PullVaultRequest,
    StatusRequest,
};

use crate::constants::{CARDPUTER_USB_PID, CARDPUTER_USB_VID, HOST_BUFFER_SIZE, MAX_CHUNK_SIZE};
use crate::test_support::{RecordingTransportProvider, non_usb_port, usb_port};
use crate::transport::{
    read_device_response, read_framed_message_for_tests as read_framed_message, select_serial_port,
    write_framed_message_for_tests as write_framed_message,
};
use crate::{Cli, Command, application};

#[test]
fn detect_cardputer_by_vid_pid() {
    let ports = vec![
        non_usb_port("/dev/ttyS0"),
        usb_port(
            "/dev/ttyUSB0",
            CARDPUTER_USB_VID,
            CARDPUTER_USB_PID,
            None,
            Some("M5Stack"),
            None,
        ),
    ];

    let detected = select_serial_port(&ports, false).expect("cardputer port");
    assert_eq!(detected.port_name, "/dev/ttyUSB0");
}

#[test]
fn detect_cardputer_prefers_identity_keywords() {
    let ports = vec![
        usb_port(
            "/dev/ttyUSB0",
            CARDPUTER_USB_VID,
            CARDPUTER_USB_PID,
            None,
            None,
            Some("Generic CDC"),
        ),
        usb_port(
            "/dev/ttyUSB1",
            CARDPUTER_USB_VID,
            CARDPUTER_USB_PID,
            None,
            Some("M5Stack"),
            Some("Cardputer CDC"),
        ),
    ];

    let detected = select_serial_port(&ports, false).expect("cardputer port");
    assert_eq!(detected.port_name, "/dev/ttyUSB1");
}

#[test]
fn detect_cardputer_none_without_match() {
    let ports = vec![
        non_usb_port("/dev/ttyS0"),
        usb_port(
            "/dev/ttyUSB0",
            0x10C4,
            0xEA60,
            None,
            Some("Silicon Labs"),
            Some("CP210x"),
        ),
    ];

    assert!(select_serial_port(&ports, false).is_none());
}

#[test]
fn detect_cardputer_allows_any_port_override() {
    let ports = vec![
        usb_port(
            "/dev/ttyUSB0",
            0x10C4,
            0xEA60,
            None,
            Some("Silicon Labs"),
            Some("CP210x"),
        ),
        usb_port(
            "/dev/ttyUSB1",
            CARDPUTER_USB_VID,
            CARDPUTER_USB_PID,
            None,
            Some("M5Stack"),
            Some("Cardputer CDC"),
        ),
    ];

    let detected = select_serial_port(&ports, true).expect("usb port");
    assert_eq!(detected.port_name, "/dev/ttyUSB0");
}

#[test]
fn connect_transport_uses_cli_port() {
    let cli = Cli {
        port: Some("/dev/ttyTEST".into()),
        any_port: false,
        command: Command::Hello,
    };

    let provider = RecordingTransportProvider::default();

    let _transport = application::connect_transport(&cli, &provider).expect("connect transport");
    let requested = provider.requested_ports.borrow();
    assert_eq!(requested.as_slice(), ["/dev/ttyTEST"]);
}

#[test]
fn framing_roundtrip() {
    let request = HostRequest::PullVault(PullVaultRequest {
        protocol_version: PROTOCOL_VERSION,
        host_buffer_size: HOST_BUFFER_SIZE,
        max_chunk_size: MAX_CHUNK_SIZE,
        known_generation: Some(7),
    });

    let payload = postcard::to_allocvec(&request).expect("encode request");
    let mut writer = Cursor::new(Vec::new());
    let command = command_for_request(&request);
    write_framed_message(&mut writer, command, &payload).expect("write frame");

    let data = writer.into_inner();
    let mut reader = Cursor::new(data);
    let (decoded_command, decoded) = read_framed_message(&mut reader).expect("read frame");

    assert_eq!(decoded_command, command);
    assert_eq!(decoded, payload);
}

#[test]
fn cli_header_matches_shared_encoding() {
    let request = HostRequest::Status(StatusRequest {
        protocol_version: PROTOCOL_VERSION,
    });
    let payload = postcard::to_allocvec(&request).expect("encode request");
    let command = command_for_request(&request);

    let mut writer = Cursor::new(Vec::new());
    write_framed_message(&mut writer, command, &payload).expect("write frame");
    let frame = writer.into_inner();

    let expected =
        encode_frame(PROTOCOL_VERSION, command, &payload, usize::MAX).expect("encode header");
    assert_eq!(&frame[..FRAME_HEADER_SIZE], &expected);
}

#[test]
fn framing_detects_checksum_mismatch() {
    let payload = vec![1u8, 2, 3, 4];
    let mut frame = Vec::new();
    let header = FrameHeader::new(
        PROTOCOL_VERSION,
        CdcCommand::PullVault,
        payload.len() as u32,
        0xDEADBEEFu32,
    );
    frame.extend_from_slice(&header.to_bytes());
    frame.extend_from_slice(&payload);

    let mut reader = Cursor::new(frame);
    let err = read_framed_message(&mut reader).expect_err("expected checksum error");
    match err {
        SharedError::Transport(message) => {
            assert!(message.contains("checksum mismatch"));
        }
        _ => panic!("unexpected error variant"),
    }
}

#[test]
fn framing_rejects_payload_exceeding_limit() {
    let mut frame = Vec::new();
    let header = FrameHeader::new(
        PROTOCOL_VERSION,
        CdcCommand::PullVault,
        HOST_BUFFER_SIZE + 1,
        0,
    );
    frame.extend_from_slice(&header.to_bytes());

    let mut reader = Cursor::new(frame);
    let err = read_framed_message(&mut reader).expect_err("expected length error");
    match err {
        SharedError::Transport(message) => {
            assert!(message.contains("frame payload") && message.contains("exceeds limit"));
        }
        other => panic!("unexpected error variant: {:?}", other),
    }
}

#[test]
fn response_command_mismatch_is_reported() {
    let response = DeviceResponse::Nack(NackResponse {
        protocol_version: PROTOCOL_VERSION,
        code: DeviceErrorCode::InternalFailure,
        message: "failure".into(),
    });
    let payload = postcard::to_allocvec(&response).expect("encode response");
    let mut frame = Vec::new();
    let checksum = compute_crc32(&payload);
    let wrong_command = FrameHeader::new(
        PROTOCOL_VERSION,
        CdcCommand::PullVault,
        payload.len() as u32,
        checksum,
    );
    frame.extend_from_slice(&wrong_command.to_bytes());
    frame.extend_from_slice(&payload);

    let mut reader = Cursor::new(frame);
    let err = read_device_response(&mut reader).expect_err("expected command error");
    match err {
        SharedError::Transport(message) => {
            assert!(message.contains("unexpected command"));
        }
        _ => panic!("unexpected error variant"),
    }
}
