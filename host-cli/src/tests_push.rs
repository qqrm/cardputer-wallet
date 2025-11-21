use std::fs;
use std::io::Cursor;

use ed25519_dalek::{Signature, Verifier};
use tempfile::tempdir;
use uuid::Uuid;

use shared::cdc::CdcCommand;
use shared::schema::{
    AckResponse, DeviceResponse, HostRequest, PROTOCOL_VERSION, VaultArtifact,
    encode_journal_operations,
};
use shared::vault::{EntryUpdate, JournalOperation as VaultJournalOperation};

use crate::RepoArgs;
use crate::commands;
use crate::constants::{SIGNATURE_FILE, VAULT_FILE};
use crate::test_support::{
    InMemoryArtifactStore, InMemoryDeviceTransport, MockPort, SIGNATURE_SIZE, TEST_VAULT_KEY,
    assert_mock_port_is_device_transport, encode_response, sample_entry, sample_snapshot,
    write_credentials_with_keys, write_empty_credentials, write_encrypted_vault,
};
use crate::transport::read_framed_message_for_tests as read_framed_message;

#[test]
fn push_serializes_local_operations() {
    let temp = tempdir().expect("tempdir");
    let args = RepoArgs {
        repo: temp.path().to_path_buf(),
        credentials: temp.path().join("creds"),
        signing_pubkey: None,
    };

    let signing = write_credentials_with_keys(&args.credentials, true, true);

    let base_entry = sample_entry(Uuid::new_v4(), "existing");
    let initial_snapshot = sample_snapshot(vec![base_entry.clone()]);
    write_encrypted_vault(&args.repo, &initial_snapshot);

    let new_entry = sample_entry(Uuid::new_v4(), "added");
    let host_operations = vec![
        VaultJournalOperation::Add {
            entry: new_entry.clone(),
        },
        VaultJournalOperation::Update {
            id: base_entry.id,
            changes: EntryUpdate {
                username: Some("updated".into()),
                ..EntryUpdate::default()
            },
        },
    ];
    let encoded_ops = postcard::to_allocvec(&host_operations).expect("encode operations");
    fs::write(
        commands::push::operations_log_path(&args.repo),
        &encoded_ops,
    )
    .expect("write operations");

    let ack_response = encode_response(DeviceResponse::Ack(AckResponse {
        protocol_version: PROTOCOL_VERSION,
        message: String::from("acknowledged"),
    }));

    let mut port = MockPort::new(ack_response.repeat(3));
    let mut store = commands::FilesystemArtifactStore::new(&args.repo);
    commands::push::run(&mut port, &mut store, &args).expect("push succeeds");

    let mut reader = Cursor::new(port.writes);
    let payload = loop {
        let (command, payload) = read_framed_message(&mut reader).expect("decode written frame");
        if command == CdcCommand::PushOps {
            break payload;
        }

        assert_eq!(command, CdcCommand::PushVault);
    };
    let decoded = crate::test_support::decode_written_host_request(&payload);

    match decoded {
        HostRequest::PushOps(frame) => {
            assert_eq!(frame.sequence, 1);
            assert!(frame.is_last);
            let mut expected = Vec::new();
            for op in &host_operations {
                expected
                    .extend(commands::push::operations_for_device(op).expect("flatten host ops"));
            }
            assert_eq!(frame.operations, expected);
            assert_eq!(
                frame.checksum,
                commands::push::compute_local_journal_checksum(&frame.operations)
            );
        }
        other => panic!("unexpected request written: {:?}", other),
    }

    assert_eq!(reader.position(), reader.get_ref().len() as u64);

    assert!(
        !commands::push::operations_log_path(&args.repo).exists(),
        "operations file should be cleared after push",
    );

    let vault_path = args.repo.join(VAULT_FILE);
    let encrypted_vault = fs::read(&vault_path).expect("encrypted vault");
    let snapshot =
        commands::push::decrypt_vault(&encrypted_vault, &TEST_VAULT_KEY).expect("decrypt vault");

    let added = snapshot
        .entries
        .iter()
        .find(|entry| entry.id == new_entry.id)
        .expect("added entry persisted");
    assert_eq!(added.title, new_entry.title);
    assert_eq!(added.username, new_entry.username);

    let updated = snapshot
        .entries
        .iter()
        .find(|entry| entry.id == base_entry.id)
        .expect("updated entry present");
    assert_eq!(updated.username, "updated");

    let signature_path = args.repo.join(SIGNATURE_FILE);
    let signature_bytes = fs::read(&signature_path).expect("signature file");
    assert_eq!(signature_bytes.len(), SIGNATURE_SIZE);
    let signature_array: [u8; SIGNATURE_SIZE] = signature_bytes
        .as_slice()
        .try_into()
        .expect("signature length");
    let signature = Signature::from_bytes(&signature_array);
    let message =
        crate::commands::signature::compute_signature_message(&encrypted_vault, None, None);
    signing
        .verifying_key()
        .verify(&message, &signature)
        .expect("signature verifies");
}

#[test]
fn push_command_uses_in_memory_transport_and_store() {
    let temp = tempdir().expect("tempdir");
    let repo_path = temp.path().join("memory/push");
    fs::create_dir_all(&repo_path).expect("create repo");
    let args = RepoArgs {
        repo: repo_path,
        credentials: temp.path().join("creds"),
        signing_pubkey: None,
    };

    write_credentials_with_keys(&args.credentials, true, true);
    let entry = sample_entry(Uuid::new_v4(), "demo");
    let snapshot = sample_snapshot(vec![entry.clone()]);
    write_encrypted_vault(&args.repo, &snapshot);

    let operations = vec![VaultJournalOperation::Delete { id: entry.id }];
    let encoded_ops = postcard::to_allocvec(&operations).expect("encode operations");
    fs::write(
        commands::push::operations_log_path(&args.repo),
        &encoded_ops,
    )
    .expect("write operations");

    let ack = DeviceResponse::Ack(AckResponse {
        protocol_version: PROTOCOL_VERSION,
        message: "ok".into(),
    });
    let responses = vec![ack.clone(), ack.clone(), ack];

    let mut transport = InMemoryDeviceTransport::new(responses);
    let mut store = InMemoryArtifactStore::default();
    store.set(VaultArtifact::Vault, vec![0xAA, 0xBB, 0xCC]);

    commands::push::run(&mut transport, &mut store, &args).expect("push succeeds");

    let requests = transport.requests();
    let vault_frame = requests
        .iter()
        .find_map(|request| match request {
            HostRequest::PushVault(frame) => Some(frame.clone()),
            _ => None,
        })
        .expect("vault frame sent");
    assert_eq!(vault_frame.data, vec![0xAA, 0xBB, 0xCC]);
    assert!(
        requests
            .iter()
            .any(|request| matches!(request, HostRequest::PushOps(_)))
    );
}

#[test]
fn load_local_operations_migrates_device_format() {
    let temp = tempdir().expect("tempdir");
    let repo = temp.path();
    let credentials = repo.join("creds.json");
    write_credentials_with_keys(&credentials, true, true);

    let existing_id = Uuid::new_v4();
    let mut updated_entry = sample_entry(existing_id, "existing");
    updated_entry.username = "updated-user".into();
    updated_entry.tags = vec!["tag".into()];
    updated_entry.updated_at = "2024-02-01T00:00:00Z".into();

    let new_entry = sample_entry(Uuid::new_v4(), "added");
    let snapshot = sample_snapshot(vec![updated_entry.clone(), new_entry.clone()]);
    write_encrypted_vault(repo, &snapshot);

    let host_operations = vec![
        VaultJournalOperation::Update {
            id: existing_id,
            changes: EntryUpdate {
                username: Some(updated_entry.username.clone()),
                tags: Some(updated_entry.tags.clone()),
                updated_at: Some(updated_entry.updated_at.clone()),
                ..EntryUpdate::default()
            },
        },
        VaultJournalOperation::Add {
            entry: new_entry.clone(),
        },
    ];

    let mut device_operations = Vec::new();
    for operation in &host_operations {
        device_operations
            .extend(commands::push::operations_for_device(operation).expect("flatten host ops"));
    }

    let encoded_device = encode_journal_operations(&device_operations).expect("encode device ops");
    fs::write(commands::push::operations_log_path(repo), &encoded_device)
        .expect("write legacy operations");

    let config = commands::host_config::HostConfig::load(&credentials).expect("load config");
    let loaded =
        commands::push::load_local_operations(repo, &config).expect("load migrated operations");
    assert_eq!(loaded, host_operations);

    let rewritten =
        fs::read(commands::push::operations_log_path(repo)).expect("read rewritten operations");
    let decoded: Vec<VaultJournalOperation> =
        postcard::from_bytes(&rewritten).expect("decode rewritten operations");
    assert_eq!(decoded, host_operations);
}

#[test]
fn push_runs_with_mock_transport_and_in_memory_store() {
    let temp = tempdir().expect("tempdir");
    let args = RepoArgs {
        repo: temp.path().join("repo"),
        credentials: temp.path().join("creds"),
        signing_pubkey: None,
    };

    if let Some(parent) = args.repo.parent() {
        fs::create_dir_all(parent).expect("create repo parent");
    }
    fs::create_dir_all(&args.repo).expect("create repo directory");
    write_empty_credentials(&args.credentials);

    let mut transport = MockPort::new(Vec::new());
    let mut store = InMemoryArtifactStore::default();

    commands::push::run(&mut transport, &mut store, &args)
        .expect("push exits early without pending operations");
}

#[test]
fn mock_port_is_a_device_transport() {
    assert_mock_port_is_device_transport();
}
