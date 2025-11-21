use std::io::Cursor;

use shared::cdc::CdcCommand;
use shared::schema::{DeviceResponse, HostRequest, PROTOCOL_VERSION, StatusResponse};

use crate::commands;
use crate::test_support::{MockPort, decode_written_host_request, encode_response};
use crate::transport::read_framed_message_for_tests as read_framed_message;

#[test]
fn status_sends_status_command() {
    let responses = encode_response(DeviceResponse::Status(StatusResponse {
        protocol_version: PROTOCOL_VERSION,
        vault_generation: 2,
        pending_operations: 1,
        current_time_ms: 42,
    }));

    let mut port = MockPort::new(responses);

    commands::status::run(&mut port).expect("status succeeds");

    let mut reader = Cursor::new(port.writes);
    let (command, payload) = read_framed_message(&mut reader).expect("decode written frame");
    assert_eq!(command, CdcCommand::Status);
    let decoded = decode_written_host_request(&payload);
    assert!(matches!(decoded, HostRequest::Status(_)));
}
