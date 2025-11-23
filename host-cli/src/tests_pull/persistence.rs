use std::fs;
use std::io::Cursor;

use shared::cdc::CdcCommand;
use shared::schema::{DeviceResponse, HostRequest, VaultArtifact};

use crate::commands;
use crate::test_support::{
    InMemoryArtifactStore, InMemoryDeviceTransport, MockPort, decode_written_host_request,
};
use crate::transport::read_framed_message_for_tests as read_framed_message;

use super::fixtures::{PullTestContext, encoded_responses, head_response, vault_chunk};

// Legacy streaming-only coverage is provided by transport framing tests; avoid duplicating it here.
#[test]
fn pull_reissues_request_until_completion() {
    let ctx = PullTestContext::new("reissue");
    let vault_payload = vec![0; 16];
    let responses = encoded_responses(&[
        DeviceResponse::Head(head_response(1, &vault_payload, None, None, 0x11)),
        DeviceResponse::VaultChunk(vault_chunk(
            1,
            16,
            8,
            vault_payload[..8].to_vec(),
            false,
            VaultArtifact::Vault,
        )),
        DeviceResponse::VaultChunk(vault_chunk(
            2,
            16,
            0,
            vault_payload[8..].to_vec(),
            true,
            VaultArtifact::Vault,
        )),
    ]);

    let mut port = MockPort::new(responses);
    let mut store = commands::FilesystemArtifactStore::new(ctx.repo_path());
    commands::pull::run(&mut port, &mut store, &ctx.args()).expect("pull succeeds");

    let mut reader = Cursor::new(port.writes);
    let (first_command, first_payload) =
        read_framed_message(&mut reader).expect("decode head request frame");
    assert_eq!(first_command, CdcCommand::PullHead);
    let decoded_head = decode_written_host_request(&first_payload);
    assert!(matches!(decoded_head, HostRequest::PullHead(_)));

    let (second_command, _) =
        read_framed_message(&mut reader).expect("decode first pull request frame");
    assert_eq!(second_command, CdcCommand::PullVault);

    let (third_command, _) =
        read_framed_message(&mut reader).expect("decode second pull request frame");
    assert_eq!(third_command, CdcCommand::PullVault);

    assert_eq!(
        reader.position(),
        reader.get_ref().len() as u64,
        "expected head request followed by two pull requests",
    );

    let vault_path = ctx.repo_path().join("vault.enc");
    let vault_content = fs::read(&vault_path).expect("vault file");
    assert_eq!(vault_content, vault_payload);
}

#[test]
fn pull_command_uses_in_memory_transport_and_store() {
    let ctx = PullTestContext::new("memory/pull");

    let vault_payload = vec![1, 2, 3, 4];
    let responses = vec![
        DeviceResponse::Head(head_response(1, &vault_payload, None, None, 0x22)),
        DeviceResponse::VaultChunk(vault_chunk(
            1,
            vault_payload.len() as u64,
            0,
            vault_payload.clone(),
            true,
            VaultArtifact::Vault,
        )),
    ];

    let mut transport = InMemoryDeviceTransport::new(responses);
    let mut store = InMemoryArtifactStore::default();

    commands::pull::run(&mut transport, &mut store, &ctx.args()).expect("pull succeeds");

    let requests = transport.requests();
    assert!(matches!(requests.first(), Some(HostRequest::PullHead(_))));
    assert!(matches!(requests.get(1), Some(HostRequest::PullVault(_))));

    assert_eq!(
        store.artifact_bytes(VaultArtifact::Vault),
        Some(vault_payload),
    );
    assert!(store.artifact_bytes(VaultArtifact::Recipients).is_none());
}

#[test]
fn pull_persists_multi_chunk_recipients_manifest() {
    let first_fragment = br#"{"recipients":[{"#.to_vec();
    let second_fragment = br#"address":"deadbeef"}]}"#.to_vec();
    let mut recipients_payload = first_fragment.clone();
    recipients_payload.extend_from_slice(&second_fragment);
    let responses = encoded_responses(&[
        DeviceResponse::Head(head_response(
            11,
            &[1, 3, 3, 7],
            Some(&recipients_payload),
            None,
            0x33,
        )),
        DeviceResponse::VaultChunk(vault_chunk(
            1,
            4,
            0,
            vec![1, 3, 3, 7],
            true,
            VaultArtifact::Vault,
        )),
        DeviceResponse::VaultChunk(vault_chunk(
            2,
            (first_fragment.len() + second_fragment.len()) as u64,
            second_fragment.len() as u64,
            first_fragment.clone(),
            false,
            VaultArtifact::Recipients,
        )),
        DeviceResponse::VaultChunk(vault_chunk(
            3,
            (first_fragment.len() + second_fragment.len()) as u64,
            0,
            second_fragment.clone(),
            true,
            VaultArtifact::Recipients,
        )),
    ]);

    let mut port = MockPort::new(responses);
    let ctx = PullTestContext::new("multi/recipients");
    let mut store = commands::FilesystemArtifactStore::new(ctx.repo_path());
    commands::pull::run(&mut port, &mut store, &ctx.args()).expect("pull succeeds");

    let mut reader = Cursor::new(port.writes);
    let (first_command, first_payload) =
        read_framed_message(&mut reader).expect("decode head request frame");
    assert_eq!(first_command, CdcCommand::PullHead);
    let decoded_head = decode_written_host_request(&first_payload);
    assert!(matches!(decoded_head, HostRequest::PullHead(_)));

    for index in 0..3 {
        let (command, payload) =
            read_framed_message(&mut reader).expect("decode pull request frame");
        assert_eq!(
            command,
            CdcCommand::PullVault,
            "expected pull request #{index}",
        );
        let decoded: HostRequest = decode_written_host_request(&payload);
        assert!(matches!(decoded, HostRequest::PullVault(_)));
    }

    assert_eq!(
        reader.position(),
        reader.get_ref().len() as u64,
        "expected one head request followed by three pull requests",
    );

    let recipients_path = ctx.repo_path().join("recips.json");
    let recipients_content = fs::read(&recipients_path).expect("recipients file");
    assert_eq!(recipients_content, recipients_payload);
    let signature_path = ctx.repo_path().join("vault.sig");
    assert!(!signature_path.exists(), "unexpected signature artifact");
}
