use std::fs;
use std::io::Cursor;

use shared::cdc::CdcCommand;
use shared::schema::{AckResponse, DeviceResponse, HostRequest, JournalFrame, PROTOCOL_VERSION};

use crate::RepoArgs;
use crate::commands;
use crate::test_support::{
    MockPort, decode_written_host_request, encode_response, write_empty_credentials,
};
use crate::transport::read_framed_message_for_tests as read_framed_message;

#[test]
fn confirm_sends_ack_request_with_saved_state() {
    let temp = tempfile::tempdir().expect("tempdir");
    let args = RepoArgs {
        repo: temp.path().join("confirm/repo"),
        credentials: temp.path().join("creds"),
        signing_pubkey: None,
    };

    fs::create_dir_all(&args.repo).expect("create repo directory");
    write_empty_credentials(&args.credentials);

    let sequence = 7;
    let frame_checksum = 0xAABBCCDD;
    let pull_responses = [
        encode_response(DeviceResponse::Head(shared::schema::PullHeadResponse {
            protocol_version: PROTOCOL_VERSION,
            vault_generation: 5,
            vault_hash: [0x44; 32],
            recipients_hash: [0u8; 32],
            signature_hash: [0u8; 32],
        })),
        encode_response(DeviceResponse::JournalFrame(JournalFrame {
            protocol_version: PROTOCOL_VERSION,
            sequence,
            remaining_operations: 0,
            operations: vec![],
            checksum: frame_checksum,
        })),
    ]
    .concat();

    let mut pull_port = MockPort::new(pull_responses);
    let mut pull_store = commands::FilesystemArtifactStore::new(&args.repo);
    commands::pull::run(&mut pull_port, &mut pull_store, &args).expect("pull succeeds");

    let push_responses = encode_response(DeviceResponse::Ack(AckResponse {
        protocol_version: PROTOCOL_VERSION,
        message: String::from("acknowledged"),
    }));

    let mut push_port = MockPort::new(push_responses);
    commands::confirm::run(&mut push_port, &args).expect("confirm succeeds");

    let mut reader = Cursor::new(push_port.writes);
    let (command, payload) = read_framed_message(&mut reader).expect("decode written frame");
    assert_eq!(command, CdcCommand::Ack);
    let decoded = decode_written_host_request(&payload);

    match decoded {
        HostRequest::Ack(ack) => {
            assert_eq!(ack.last_frame_sequence, sequence);
            assert_eq!(ack.journal_checksum, frame_checksum);
        }
        other => panic!("unexpected request written: {:?}", other),
    }
}
