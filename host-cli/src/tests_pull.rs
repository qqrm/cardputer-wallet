use std::fs;
use std::io::Cursor;

use ed25519_dalek::SigningKey;
use serde_json::json;
use tempfile::tempdir;

use shared::cdc::CdcCommand;
use shared::error::SharedError;
use shared::schema::{
    AckResponse, DeviceResponse, HostRequest, PROTOCOL_VERSION, PullHeadResponse, VaultArtifact,
    VaultChunk,
};

use crate::RepoArgs;
use crate::commands;
use crate::constants::{MAX_CHUNK_SIZE, VAULT_FILE};
use crate::test_support::{
    InMemoryArtifactStore, InMemoryDeviceTransport, MockPort, SIGNATURE_SIZE, TEST_SIGNING_SEED,
    chunk_checksum, decode_written_host_request, encode_response, hash_with_crc, sign_artifacts,
    write_credentials_with_keys, write_empty_credentials,
};
use crate::transport::read_framed_message_for_tests as read_framed_message;

#[test]
fn pull_reissues_request_until_completion() {
    let temp = tempdir().expect("tempdir");
    let args = RepoArgs {
        repo: temp.path().join("repo"),
        credentials: temp.path().join("creds"),
        signing_pubkey: None,
    };

    write_empty_credentials(&args.credentials);

    let vault_payload = vec![0; 16];
    let responses = [
        encode_response(DeviceResponse::Head(PullHeadResponse {
            protocol_version: PROTOCOL_VERSION,
            vault_generation: 1,
            vault_hash: hash_with_crc(0x11, &vault_payload),
            recipients_hash: [0u8; 32],
            signature_hash: [0u8; 32],
        })),
        encode_response(DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 1,
            total_size: 16,
            remaining_bytes: 8,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: vault_payload[..8].to_vec(),
            checksum: chunk_checksum(&vault_payload[..8]),
            is_last: false,
            artifact: VaultArtifact::Vault,
        })),
        encode_response(DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 2,
            total_size: 16,
            remaining_bytes: 0,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: vault_payload[8..].to_vec(),
            checksum: chunk_checksum(&vault_payload[8..]),
            is_last: true,
            artifact: VaultArtifact::Vault,
        })),
    ]
    .concat();

    let mut port = MockPort::new(responses);

    let mut store = commands::FilesystemArtifactStore::new(&args.repo);
    commands::pull::run(&mut port, &mut store, &args).expect("pull succeeds");

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

    let vault_path = args.repo.join("vault.enc");
    let vault_content = fs::read(&vault_path).expect("vault file");
    assert_eq!(vault_content, vault_payload);
}

#[test]
fn pull_command_uses_in_memory_transport_and_store() {
    let temp = tempdir().expect("tempdir");
    let repo_path = temp.path().join("memory/repo");
    fs::create_dir_all(&repo_path).expect("create repo");
    let args = RepoArgs {
        repo: repo_path,
        credentials: temp.path().join("creds"),
        signing_pubkey: None,
    };

    fs::write(&args.credentials, json!({}).to_string()).expect("write credentials");

    let vault_payload = vec![1, 2, 3, 4];
    let vault_checksum = chunk_checksum(&vault_payload);
    let responses = vec![
        DeviceResponse::Head(PullHeadResponse {
            protocol_version: PROTOCOL_VERSION,
            vault_generation: 1,
            vault_hash: hash_with_crc(0x11, &vault_payload),
            recipients_hash: [0u8; 32],
            signature_hash: [0u8; 32],
        }),
        DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 1,
            total_size: 4,
            remaining_bytes: 0,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: vault_payload.clone(),
            checksum: vault_checksum,
            is_last: true,
            artifact: VaultArtifact::Vault,
        }),
    ];

    let mut transport = InMemoryDeviceTransport::new(responses);
    let mut store = InMemoryArtifactStore::default();

    commands::pull::run(&mut transport, &mut store, &args).expect("pull succeeds");

    let requests = transport.requests();
    assert!(matches!(requests.first(), Some(HostRequest::PullHead(_))));
    assert!(matches!(requests.get(1), Some(HostRequest::PullVault(_))));

    assert_eq!(
        store.artifact_bytes(VaultArtifact::Vault),
        Some(vault_payload)
    );
    assert!(store.artifact_bytes(VaultArtifact::Recipients).is_none());
}

#[test]
fn pull_errors_when_expected_recipients_missing() {
    let temp = tempdir().expect("tempdir");
    let repo_path = temp.path().join("missing-recipients/repo");
    fs::create_dir_all(&repo_path).expect("create repo");
    let args = RepoArgs {
        repo: repo_path,
        credentials: temp.path().join("creds"),
        signing_pubkey: None,
    };

    fs::write(&args.credentials, json!({}).to_string()).expect("write credentials");

    let vault_payload = vec![1, 2, 3, 4];
    let recipients_payload = vec![9, 8, 7, 6];
    let vault_len = vault_payload.len() as u64;
    let vault_checksum = chunk_checksum(&vault_payload);
    let responses = vec![
        DeviceResponse::Head(PullHeadResponse {
            protocol_version: PROTOCOL_VERSION,
            vault_generation: 1,
            vault_hash: hash_with_crc(0x21, &vault_payload),
            recipients_hash: hash_with_crc(0x34, &recipients_payload),
            signature_hash: [0u8; 32],
        }),
        DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 1,
            total_size: vault_len,
            remaining_bytes: 0,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: vault_payload,
            checksum: vault_checksum,
            is_last: true,
            artifact: VaultArtifact::Vault,
        }),
        DeviceResponse::Ack(AckResponse {
            protocol_version: PROTOCOL_VERSION,
            message: "complete".into(),
        }),
    ];

    let mut transport = InMemoryDeviceTransport::new(responses);
    let mut store = InMemoryArtifactStore::default();

    let err = commands::pull::run(&mut transport, &mut store, &args)
        .expect_err("expected recipients failure");
    match err {
        SharedError::Transport(message) => {
            assert!(message.contains("recipients manifest missing"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn pull_errors_when_signature_expected_without_verifying_key() {
    let temp = tempdir().expect("tempdir");
    let args = RepoArgs {
        repo: temp.path().join("missing-key/repo"),
        credentials: temp.path().join("creds"),
        signing_pubkey: None,
    };

    write_empty_credentials(&args.credentials);
    let signing = SigningKey::from_bytes(&TEST_SIGNING_SEED);
    let vault_payload = vec![1, 2, 3, 4];
    let signature = sign_artifacts(&signing, &vault_payload, None, None);

    let responses = [
        encode_response(DeviceResponse::Head(PullHeadResponse {
            protocol_version: PROTOCOL_VERSION,
            vault_generation: 4,
            vault_hash: hash_with_crc(0x55, &vault_payload),
            recipients_hash: [0u8; 32],
            signature_hash: hash_with_crc(0x77, &signature),
        })),
        encode_response(DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 1,
            total_size: vault_payload.len() as u64,
            remaining_bytes: 0,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: vault_payload.clone(),
            checksum: chunk_checksum(&vault_payload),
            is_last: true,
            artifact: VaultArtifact::Vault,
        })),
        encode_response(DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 2,
            total_size: SIGNATURE_SIZE as u64,
            remaining_bytes: 0,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: signature.clone(),
            checksum: chunk_checksum(&signature),
            is_last: true,
            artifact: VaultArtifact::Signature,
        })),
    ]
    .concat();

    let mut port = MockPort::new(responses);
    let mut store = commands::FilesystemArtifactStore::new(&args.repo);
    let err = commands::pull::run(&mut port, &mut store, &args).expect_err("pull should fail");

    match err {
        SharedError::Transport(message) => {
            assert!(message.contains("verifying key is missing"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    assert!(
        !args.repo.join(VAULT_FILE).exists(),
        "vault should not be persisted on failure",
    );
}

#[test]
fn pull_errors_when_signature_verification_fails() {
    let temp = tempdir().expect("tempdir");
    let args = RepoArgs {
        repo: temp.path().join("bad-signature/repo"),
        credentials: temp.path().join("creds"),
        signing_pubkey: None,
    };

    let signing = write_credentials_with_keys(&args.credentials, false, false);
    let vault_payload = vec![4, 3, 2, 1];
    let mut signature = sign_artifacts(&signing, &vault_payload, None, None);
    signature[0] ^= 0xFF;

    let responses = [
        encode_response(DeviceResponse::Head(PullHeadResponse {
            protocol_version: PROTOCOL_VERSION,
            vault_generation: 9,
            vault_hash: hash_with_crc(0x66, &vault_payload),
            recipients_hash: [0u8; 32],
            signature_hash: hash_with_crc(0x88, &signature),
        })),
        encode_response(DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 1,
            total_size: vault_payload.len() as u64,
            remaining_bytes: 0,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: vault_payload.clone(),
            checksum: chunk_checksum(&vault_payload),
            is_last: true,
            artifact: VaultArtifact::Vault,
        })),
        encode_response(DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 2,
            total_size: SIGNATURE_SIZE as u64,
            remaining_bytes: 0,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: signature.clone(),
            checksum: chunk_checksum(&signature),
            is_last: true,
            artifact: VaultArtifact::Signature,
        })),
    ]
    .concat();

    let mut port = MockPort::new(responses);
    let mut store = commands::FilesystemArtifactStore::new(&args.repo);
    let err = commands::pull::run(&mut port, &mut store, &args).expect_err("pull should fail");

    match err {
        SharedError::Transport(message) => {
            assert!(message.contains("vault signature verification failed"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    assert!(
        !args.repo.join(VAULT_FILE).exists(),
        "vault should not be persisted on failure",
    );
}

#[test]
fn pull_persists_multi_chunk_recipients_manifest() {
    let first_fragment = br#"{"recipients":[{"#.to_vec();
    let second_fragment = br#"address":"deadbeef"}]}"#.to_vec();
    let mut recipients_payload = first_fragment.clone();
    recipients_payload.extend_from_slice(&second_fragment);
    let responses = [
        encode_response(DeviceResponse::Head(PullHeadResponse {
            protocol_version: PROTOCOL_VERSION,
            vault_generation: 11,
            vault_hash: hash_with_crc(0x33, &[1, 3, 3, 7]),
            recipients_hash: hash_with_crc(0x44, &recipients_payload),
            signature_hash: [0u8; 32],
        })),
        encode_response(DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 1,
            total_size: 4,
            remaining_bytes: 0,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: vec![1, 3, 3, 7],
            checksum: chunk_checksum(&[1, 3, 3, 7]),
            is_last: true,
            artifact: VaultArtifact::Vault,
        })),
        encode_response(DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 2,
            total_size: (first_fragment.len() + second_fragment.len()) as u64,
            remaining_bytes: second_fragment.len() as u64,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: first_fragment.clone(),
            checksum: chunk_checksum(&first_fragment),
            is_last: false,
            artifact: VaultArtifact::Recipients,
        })),
        encode_response(DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 3,
            total_size: (first_fragment.len() + second_fragment.len()) as u64,
            remaining_bytes: 0,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: second_fragment.clone(),
            checksum: chunk_checksum(&second_fragment),
            is_last: true,
            artifact: VaultArtifact::Recipients,
        })),
    ]
    .concat();

    let mut port = MockPort::new(responses);
    let temp = tempdir().expect("tempdir");
    let args = RepoArgs {
        repo: temp.path().join("multi/recipients"),
        credentials: temp.path().join("creds"),
        signing_pubkey: None,
    };

    write_empty_credentials(&args.credentials);
    let mut store = commands::FilesystemArtifactStore::new(&args.repo);
    commands::pull::run(&mut port, &mut store, &args).expect("pull succeeds");

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
            "expected pull request #{index}"
        );
        let decoded: HostRequest = decode_written_host_request(&payload);
        assert!(matches!(decoded, HostRequest::PullVault(_)));
    }

    assert_eq!(
        reader.position(),
        reader.get_ref().len() as u64,
        "expected one head request followed by three pull requests",
    );

    let recipients_path = args.repo.join("recips.json");
    let recipients_content = fs::read(&recipients_path).expect("recipients file");
    assert_eq!(recipients_content, recipients_payload);
    let signature_path = args.repo.join("vault.sig");
    assert!(!signature_path.exists(), "unexpected signature artifact");
}

#[test]
fn pull_streams_into_in_memory_store() {
    let vault_hash = hash_with_crc(0xAA, b"vault");
    let head = DeviceResponse::Head(PullHeadResponse {
        protocol_version: PROTOCOL_VERSION,
        vault_generation: 7,
        vault_hash,
        recipients_hash: [0u8; 32],
        signature_hash: [0u8; 32],
    });
    let chunk = DeviceResponse::VaultChunk(VaultChunk {
        protocol_version: PROTOCOL_VERSION,
        sequence: 1,
        total_size: 5,
        remaining_bytes: 0,
        device_chunk_size: MAX_CHUNK_SIZE,
        data: b"vault".to_vec(),
        checksum: chunk_checksum(b"vault"),
        is_last: true,
        artifact: VaultArtifact::Vault,
    });
    let responses = [encode_response(head), encode_response(chunk)].concat();

    let temp = tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    fs::create_dir_all(&repo_path).expect("create repo directory");
    let args = RepoArgs {
        repo: repo_path,
        credentials: temp.path().join("creds"),
        signing_pubkey: None,
    };
    write_empty_credentials(&args.credentials);

    let mut transport = MockPort::new(responses);
    let mut store = InMemoryArtifactStore::default();

    commands::pull::run(&mut transport, &mut store, &args).expect("pull succeeds");

    assert_eq!(
        store.artifact_bytes(VaultArtifact::Vault),
        Some(b"vault".to_vec()),
        "vault bytes persisted in memory",
    );
}
