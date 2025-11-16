use super::*;
use crate::commands::signature::compute_signature_message;
use crate::commands::{ArtifactStore, DeviceTransport};
use crate::constants::{
    CARDPUTER_USB_PID, CARDPUTER_USB_VID, HOST_BUFFER_SIZE, MAX_CHUNK_SIZE, SIGNATURE_FILE,
    VAULT_FILE,
};
use crate::transport::{
    read_device_response, read_framed_message_for_tests as read_framed_message, select_serial_port,
    write_framed_message_for_tests as write_framed_message,
};
use base64::{Engine, engine::general_purpose::STANDARD as Base64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use postcard::{from_bytes as postcard_from_bytes, to_allocvec as postcard_to_allocvec};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Map, json};
use serialport::SerialPortType;
use shared::cdc::transport::{command_for_request, command_for_response, encode_frame};
use shared::cdc::{CdcCommand, FRAME_HEADER_SIZE, FrameHeader, compute_crc32};
use shared::checksum::accumulate_checksum;
use shared::error::SharedError;
use shared::schema::{
    AckResponse, DeviceErrorCode, DeviceResponse, HostRequest, JournalFrame, NackResponse,
    PROTOCOL_VERSION, PullHeadResponse, PullVaultRequest, StatusRequest, StatusResponse,
    VaultArtifact, VaultChunk, decode_host_request, encode_device_response, encode_host_request,
    encode_journal_operations,
};
use shared::vault::{
    EntryUpdate, JournalOperation as VaultJournalOperation, SecretString, VaultEntry, VaultMetadata,
};
use std::collections::VecDeque;
use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::path::Path;
use tempfile::tempdir;
use uuid::Uuid;

const SIGNATURE_SIZE: usize = 64;
const TEST_SIGNING_SEED: [u8; 32] = [0x21; 32];
const TEST_VAULT_KEY: [u8; 32] = [0x34; 32];

fn write_empty_credentials(path: &Path) {
    fs::write(path, json!({}).to_string()).expect("write empty credentials");
}

fn write_credentials_with_keys(
    path: &Path,
    include_secret: bool,
    include_vault: bool,
) -> SigningKey {
    let signing = SigningKey::from_bytes(&TEST_SIGNING_SEED);
    let verifying = signing.verifying_key();
    let mut content = Map::new();
    content.insert(
        "signing_public_key".into(),
        json!(Base64.encode(verifying.to_bytes())),
    );
    if include_secret {
        content.insert(
            "signing_secret_key".into(),
            json!(Base64.encode(signing.to_bytes())),
        );
    }
    if include_vault {
        content.insert("vault_key".into(), json!(Base64.encode(TEST_VAULT_KEY)));
    }
    fs::write(path, serde_json::Value::Object(content).to_string()).expect("write credentials");
    signing
}

fn deterministic_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0xAA; 32])
}

fn write_encrypted_vault(repo: &Path, snapshot: &commands::host_config::VaultSnapshot) {
    let mut rng = deterministic_rng();
    let encrypted = commands::push::encrypt_vault_with_rng(snapshot, &TEST_VAULT_KEY, &mut rng)
        .expect("encrypt vault");
    let path = repo.join(VAULT_FILE);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create vault directory");
    }
    fs::write(path, encrypted).expect("write vault");
}

fn sample_metadata() -> VaultMetadata {
    VaultMetadata {
        generation: 1,
        created_at: "2024-01-01T00:00:00Z".into(),
        updated_at: "2024-01-01T00:00:00Z".into(),
    }
}

fn sample_entry(id: Uuid, title: &str) -> VaultEntry {
    VaultEntry {
        id,
        title: title.into(),
        service: "service".into(),
        domains: vec![],
        username: "user".into(),
        password: SecretString::from("password"),
        totp: None,
        tags: vec![],
        r#macro: None,
        updated_at: "2024-01-01T00:00:00Z".into(),
        used_at: None,
    }
}

fn sample_snapshot(entries: Vec<VaultEntry>) -> commands::host_config::VaultSnapshot {
    commands::host_config::VaultSnapshot {
        version: 1,
        metadata: sample_metadata(),
        entries,
    }
}

fn sign_artifacts(
    signing: &SigningKey,
    vault: &[u8],
    recipients: Option<&[u8]>,
    config: Option<&[u8]>,
) -> Vec<u8> {
    let message = compute_signature_message(vault, recipients, config);
    signing.sign(&message).to_bytes().to_vec()
}

fn usb_port(
    name: &str,
    vid: u16,
    pid: u16,
    serial: Option<&str>,
    manufacturer: Option<&str>,
    product: Option<&str>,
) -> serialport::SerialPortInfo {
    serialport::SerialPortInfo {
        port_name: name.to_string(),
        port_type: SerialPortType::UsbPort(serialport::UsbPortInfo {
            vid,
            pid,
            serial_number: serial.map(|value| value.to_string()),
            manufacturer: manufacturer.map(|value| value.to_string()),
            product: product.map(|value| value.to_string()),
            interface: None,
        }),
    }
}

fn non_usb_port(name: &str) -> serialport::SerialPortInfo {
    serialport::SerialPortInfo {
        port_name: name.to_string(),
        port_type: SerialPortType::PciPort,
    }
}

fn encode_response(response: DeviceResponse) -> Vec<u8> {
    let payload = encode_device_response(&response).expect("encode response");
    let mut cursor = Cursor::new(Vec::new());
    let command = command_for_response(&response);
    write_framed_message(&mut cursor, command, &payload).expect("write frame");
    cursor.into_inner()
}

fn chunk_checksum(data: &[u8]) -> u32 {
    accumulate_checksum(0, data)
}

fn hash_with_crc(fill: u8, data: &[u8]) -> [u8; 32] {
    let mut hash = [fill; 32];
    let checksum = compute_crc32(data);
    hash[..4].copy_from_slice(&checksum.to_le_bytes());
    hash
}

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
fn framing_roundtrip() {
    let request = HostRequest::PullVault(PullVaultRequest {
        protocol_version: PROTOCOL_VERSION,
        host_buffer_size: HOST_BUFFER_SIZE,
        max_chunk_size: MAX_CHUNK_SIZE,
        known_generation: Some(7),
    });

    let payload = encode_host_request(&request).expect("encode request");
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
    let payload = encode_host_request(&request).expect("encode request");
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
    let payload = encode_device_response(&response).expect("encode response");
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

struct InMemoryDeviceTransport {
    requests: Vec<HostRequest>,
    responses: VecDeque<DeviceResponse>,
}

impl InMemoryDeviceTransport {
    fn new(responses: Vec<DeviceResponse>) -> Self {
        Self {
            requests: Vec::new(),
            responses: VecDeque::from(responses),
        }
    }

    fn requests(&self) -> &[HostRequest] {
        &self.requests
    }
}

impl DeviceTransport for InMemoryDeviceTransport {
    fn send(&mut self, request: &HostRequest) -> Result<(), SharedError> {
        self.requests.push(request.clone());
        Ok(())
    }

    fn receive(&mut self) -> Result<DeviceResponse, SharedError> {
        self.responses.pop_front().ok_or_else(|| {
            SharedError::Transport("in-memory transport ran out of responses".into())
        })
    }
}

#[derive(Default)]
struct InMemoryArtifactStore {
    vault: Option<Vec<u8>>,
    recipients: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
}

impl InMemoryArtifactStore {
    fn set(&mut self, artifact: VaultArtifact, data: Vec<u8>) {
        match artifact {
            VaultArtifact::Vault => self.vault = Some(data),
            VaultArtifact::Recipients => self.recipients = Some(data),
            VaultArtifact::Signature => self.signature = Some(data),
        }
    }

    fn artifact_bytes(&self, artifact: VaultArtifact) -> Option<Vec<u8>> {
        match artifact {
            VaultArtifact::Vault => self.vault.clone(),
            VaultArtifact::Recipients => self.recipients.clone(),
            VaultArtifact::Signature => self.signature.clone(),
        }
    }
}

impl ArtifactStore for InMemoryArtifactStore {
    fn load(&self, artifact: VaultArtifact) -> Result<Option<Vec<u8>>, SharedError> {
        Ok(self.artifact_bytes(artifact))
    }

    fn persist(&mut self, artifact: VaultArtifact, data: &[u8]) -> Result<(), SharedError> {
        self.set(artifact, data.to_vec());
        Ok(())
    }
}

#[test]
fn pull_reissues_request_until_completion() {
    let responses = [
        encode_response(DeviceResponse::Head(PullHeadResponse {
            protocol_version: PROTOCOL_VERSION,
            vault_generation: 1,
            vault_hash: [0u8; 32],
            recipients_hash: [0u8; 32],
            signature_hash: [0u8; 32],
        })),
        encode_response(DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 1,
            total_size: 16,
            remaining_bytes: 8,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: vec![0; 8],
            checksum: chunk_checksum(&[0u8; 8]),
            is_last: false,
            artifact: VaultArtifact::Vault,
        })),
        encode_response(DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 2,
            total_size: 16,
            remaining_bytes: 0,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: vec![0; 8],
            checksum: chunk_checksum(&[0u8; 8]),
            is_last: true,
            artifact: VaultArtifact::Vault,
        })),
    ]
    .concat();

    let mut port = MockPort::new(responses);
    let temp = tempdir().expect("tempdir");
    let args = RepoArgs {
        repo: temp.path().to_path_buf(),
        credentials: temp.path().join("creds"),
        signing_pubkey: None,
    };

    write_empty_credentials(&args.credentials);
    let mut store = commands::FilesystemArtifactStore::new(&args.repo);
    commands::pull::run(&mut port, &mut store, &args).expect("pull succeeds");

    let mut reader = Cursor::new(port.writes);
    let (command_one, payload_one) =
        read_framed_message(&mut reader).expect("decode first written frame");
    assert_eq!(command_one, CdcCommand::PullHead);
    let decoded_one: HostRequest = decode_host_request(&payload_one).expect("decode first request");
    assert!(matches!(decoded_one, HostRequest::PullHead(_)));

    let (command_two, payload_two) =
        read_framed_message(&mut reader).expect("decode second written frame");
    assert_eq!(command_two, CdcCommand::PullVault);
    let decoded_two: HostRequest =
        decode_host_request(&payload_two).expect("decode second request");
    assert!(matches!(decoded_two, HostRequest::PullVault(_)));

    let (command_three, payload_three) =
        read_framed_message(&mut reader).expect("decode third written frame");
    assert_eq!(command_three, CdcCommand::PullVault);
    let decoded_three: HostRequest =
        decode_host_request(&payload_three).expect("decode third request");
    assert!(matches!(decoded_three, HostRequest::PullVault(_)));

    assert_eq!(
        reader.position(),
        reader.get_ref().len() as u64,
        "expected head request followed by two pull requests"
    );
}

#[test]
fn pull_persists_vault_chunks_to_file() {
    let vault_payload = vec![1, 2, 3, 4, 5];
    let responses = [
        encode_response(DeviceResponse::Head(PullHeadResponse {
            protocol_version: PROTOCOL_VERSION,
            vault_generation: 3,
            vault_hash: hash_with_crc(0xAA, &vault_payload),
            recipients_hash: [0u8; 32],
            signature_hash: [0u8; 32],
        })),
        encode_response(DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 1,
            total_size: 5,
            remaining_bytes: 2,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: vault_payload[..3].to_vec(),
            checksum: chunk_checksum(&vault_payload[..3]),
            is_last: false,
            artifact: VaultArtifact::Vault,
        })),
        encode_response(DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 2,
            total_size: 5,
            remaining_bytes: 0,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: vault_payload[3..].to_vec(),
            checksum: chunk_checksum(&vault_payload[3..]),
            is_last: true,
            artifact: VaultArtifact::Vault,
        })),
    ]
    .concat();

    let mut port = MockPort::new(responses);
    let temp = tempdir().expect("tempdir");
    let args = RepoArgs {
        repo: temp.path().join("nested/repo"),
        credentials: temp.path().join("creds"),
        signing_pubkey: None,
    };

    write_empty_credentials(&args.credentials);
    let mut store = commands::FilesystemArtifactStore::new(&args.repo);
    commands::pull::run(&mut port, &mut store, &args).expect("pull succeeds");

    let vault_path = args.repo.join("vault.enc");
    let content = fs::read(&vault_path).expect("vault file");
    assert_eq!(content, vault_payload);

    let recipients_path = args.repo.join("recips.json");
    assert!(!recipients_path.exists(), "unexpected recipients manifest");
    let signature_path = args.repo.join("vault.sig");
    assert!(!signature_path.exists(), "unexpected signature artifact");
}

#[test]
fn pull_persists_vault_and_recipients_chunks_to_files() {
    let temp = tempdir().expect("tempdir");
    let args = RepoArgs {
        repo: temp.path().join("combined/repo"),
        credentials: temp.path().join("creds"),
        signing_pubkey: None,
    };

    let signing = write_credentials_with_keys(&args.credentials, false, false);
    let vault_payload = vec![9, 8, 7, 6, 5];
    let recipients_payload = br#"{"recipients":[]}"#.to_vec();
    let signature = sign_artifacts(&signing, &vault_payload, Some(&recipients_payload), None);

    let responses = [
        encode_response(DeviceResponse::Head(PullHeadResponse {
            protocol_version: PROTOCOL_VERSION,
            vault_generation: 7,
            vault_hash: hash_with_crc(0x11, &vault_payload),
            recipients_hash: hash_with_crc(0x22, &recipients_payload),
            signature_hash: hash_with_crc(0x33, &signature),
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
            total_size: recipients_payload.len() as u64,
            remaining_bytes: 0,
            device_chunk_size: MAX_CHUNK_SIZE,
            data: recipients_payload.clone(),
            checksum: chunk_checksum(&recipients_payload),
            is_last: true,
            artifact: VaultArtifact::Recipients,
        })),
        encode_response(DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: 3,
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
    commands::pull::run(&mut port, &mut store, &args).expect("pull succeeds");

    let mut reader = Cursor::new(port.writes);
    let (first_command, first_payload) =
        read_framed_message(&mut reader).expect("decode head request frame");
    assert_eq!(first_command, CdcCommand::PullHead);
    let decoded_head: HostRequest =
        decode_host_request(&first_payload).expect("decode head request");
    assert!(matches!(decoded_head, HostRequest::PullHead(_)));

    let (second_command, _) =
        read_framed_message(&mut reader).expect("decode first pull request frame");
    assert_eq!(second_command, CdcCommand::PullVault);

    let (third_command, _) =
        read_framed_message(&mut reader).expect("decode second pull request frame");
    assert_eq!(third_command, CdcCommand::PullVault);

    let (fourth_command, _) =
        read_framed_message(&mut reader).expect("decode third pull request frame");
    assert_eq!(fourth_command, CdcCommand::PullVault);

    assert_eq!(
        reader.position(),
        reader.get_ref().len() as u64,
        "expected head request followed by three pull requests",
    );

    let vault_path = args.repo.join("vault.enc");
    let vault_content = fs::read(&vault_path).expect("vault file");
    assert_eq!(vault_content, vault_payload);

    let recipients_path = args.repo.join("recips.json");
    let recipients_content = fs::read(&recipients_path).expect("recipients file");
    assert_eq!(recipients_content, recipients_payload);
    let signature_path = args.repo.join("vault.sig");
    let signature_content = fs::read(&signature_path).expect("signature file");
    assert_eq!(signature_content, signature);
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
    let decoded_head: HostRequest =
        decode_host_request(&first_payload).expect("decode head request");
    assert!(matches!(decoded_head, HostRequest::PullHead(_)));

    for index in 0..3 {
        let (command, payload) =
            read_framed_message(&mut reader).expect("decode pull request frame");
        assert_eq!(
            command,
            CdcCommand::PullVault,
            "expected pull request #{index}"
        );
        let decoded: HostRequest = decode_host_request(&payload).expect("decode pull request");
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
    let decoded = decode_host_request(&payload).expect("decode request");
    assert!(matches!(decoded, HostRequest::Status(_)));
}

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
    let encoded_ops = postcard_to_allocvec(&host_operations).expect("encode operations");
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
    let decoded = decode_host_request(&payload).expect("decode push request");

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
    let message = compute_signature_message(&encrypted_vault, None, None);
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
    let encoded_ops = postcard_to_allocvec(&operations).expect("encode operations");
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
        postcard_from_bytes(&rewritten).expect("decode rewritten operations");
    assert_eq!(decoded, host_operations);
}

#[test]
fn confirm_sends_ack_request_with_saved_state() {
    let sequence = 7;
    let frame_checksum = 0xAABBCCDD;
    let pull_responses = [
        encode_response(DeviceResponse::Head(PullHeadResponse {
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
            operations: Vec::new(),
            checksum: frame_checksum,
        })),
    ]
    .concat();

    let temp = tempdir().expect("tempdir");
    let args = RepoArgs {
        repo: temp.path().to_path_buf(),
        credentials: temp.path().join("creds"),
        signing_pubkey: None,
    };

    write_empty_credentials(&args.credentials);
    {
        let mut port = MockPort::new(pull_responses);
        let mut store = commands::FilesystemArtifactStore::new(&args.repo);
        commands::pull::run(&mut port, &mut store, &args).expect("pull succeeds");
    }

    let push_responses = encode_response(DeviceResponse::Ack(AckResponse {
        protocol_version: PROTOCOL_VERSION,
        message: String::from("acknowledged"),
    }));

    let mut push_port = MockPort::new(push_responses);
    commands::confirm::run(&mut push_port, &args).expect("confirm succeeds");

    let mut reader = Cursor::new(push_port.writes);
    let (command, payload) = read_framed_message(&mut reader).expect("decode written frame");
    assert_eq!(command, CdcCommand::Ack);
    let decoded = decode_host_request(&payload).expect("decode request");

    match decoded {
        HostRequest::Ack(ack) => {
            assert_eq!(ack.last_frame_sequence, sequence);
            assert_eq!(ack.journal_checksum, frame_checksum);
        }
        other => panic!("unexpected request written: {:?}", other),
    }
}

struct MockPort {
    read_cursor: Cursor<Vec<u8>>,
    writes: Vec<u8>,
}

impl MockPort {
    fn new(read_data: Vec<u8>) -> Self {
        Self {
            read_cursor: Cursor::new(read_data),
            writes: Vec::new(),
        }
    }
}

impl Read for MockPort {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_cursor.read(buf)
    }
}

impl Write for MockPort {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
