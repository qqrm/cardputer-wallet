use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD as Base64};
use ed25519_dalek::{Signer, SigningKey};
use postcard::{from_bytes as postcard_from_bytes, to_allocvec as postcard_to_allocvec};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Map, json};
use serialport::SerialPortType;
use shared::cdc::transport::command_for_response;
use shared::cdc::{CdcCommand, compute_crc32};
use shared::checksum::accumulate_checksum;
use shared::error::SharedError;
use shared::schema::{
    DeviceResponse, HostRequest, VaultArtifact, decode_host_request, encode_device_response,
};
use shared::vault::{SecretString, VaultEntry, VaultMetadata};
use uuid::Uuid;

use crate::commands::signature::compute_signature_message;
use crate::commands::{self, DeviceTransport, RepoArtifactStore, TransportProvider};
use crate::constants::VAULT_FILE;
use crate::transport::write_framed_message_for_tests as write_framed_message;

pub(crate) const SIGNATURE_SIZE: usize = 64;
pub(crate) const TEST_SIGNING_SEED: [u8; 32] = [0x21; 32];
pub(crate) const TEST_VAULT_KEY: [u8; 32] = [0x34; 32];

pub(crate) fn write_empty_credentials(path: &Path) {
    fs::write(path, json!({}).to_string()).expect("write empty credentials");
}

pub(crate) fn write_credentials_with_keys(
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

pub(crate) fn deterministic_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0xAA; 32])
}

pub(crate) fn write_encrypted_vault(repo: &Path, snapshot: &commands::host_config::VaultSnapshot) {
    let mut rng = deterministic_rng();
    let encrypted =
        commands::push::artifacts::encrypt_vault_with_rng(snapshot, &TEST_VAULT_KEY, &mut rng)
            .expect("encrypt vault");
    let path = repo.join(VAULT_FILE);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create vault directory");
    }
    fs::write(path, encrypted).expect("write vault");
}

pub(crate) fn sample_metadata() -> VaultMetadata {
    VaultMetadata {
        generation: 1,
        created_at: "2024-01-01T00:00:00Z".into(),
        updated_at: "2024-01-01T00:00:00Z".into(),
    }
}

pub(crate) fn sample_entry(id: Uuid, title: &str) -> VaultEntry {
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

pub(crate) fn sample_snapshot(entries: Vec<VaultEntry>) -> commands::host_config::VaultSnapshot {
    commands::host_config::VaultSnapshot {
        version: 1,
        metadata: sample_metadata(),
        entries,
    }
}

pub(crate) fn sign_artifacts(
    signing: &SigningKey,
    vault: &[u8],
    recipients: Option<&[u8]>,
    config: Option<&[u8]>,
) -> Vec<u8> {
    let message = compute_signature_message(vault, recipients, config);
    signing.sign(&message).to_bytes().to_vec()
}

pub(crate) fn usb_port(
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

pub(crate) fn non_usb_port(name: &str) -> serialport::SerialPortInfo {
    serialport::SerialPortInfo {
        port_name: name.to_string(),
        port_type: SerialPortType::PciPort,
    }
}

pub(crate) fn encode_response(response: DeviceResponse) -> Vec<u8> {
    let payload = encode_device_response(&response).expect("encode response");
    let mut cursor = Cursor::new(Vec::new());
    let command = command_for_response(&response);
    write_framed_message(&mut cursor, command, &payload).expect("write frame");
    cursor.into_inner()
}

pub(crate) fn chunk_checksum(data: &[u8]) -> u32 {
    accumulate_checksum(0, data)
}

pub(crate) fn hash_with_crc(fill: u8, data: &[u8]) -> [u8; 32] {
    let mut hash = [fill; 32];
    let checksum = compute_crc32(data);
    hash[..4].copy_from_slice(&checksum.to_le_bytes());
    hash
}

#[derive(Default)]
pub(crate) struct RecordingTransportProvider {
    pub(crate) requested_ports: RefCell<Vec<String>>,
}

impl TransportProvider for RecordingTransportProvider {
    type Transport = dyn DeviceTransport;

    fn connect(&self, port_path: &str) -> Result<Box<Self::Transport>, SharedError> {
        self.requested_ports
            .borrow_mut()
            .push(port_path.to_string());
        Ok(
            Box::new(crate::transport::memory::MemoryDeviceTransport::new())
                as Box<Self::Transport>,
        )
    }
}

pub(crate) struct InMemoryDeviceTransport {
    requests: Vec<HostRequest>,
    responses: VecDeque<DeviceResponse>,
}

impl InMemoryDeviceTransport {
    pub(crate) fn new(responses: Vec<DeviceResponse>) -> Self {
        Self {
            requests: Vec::new(),
            responses: VecDeque::from(responses),
        }
    }

    pub(crate) fn requests(&self) -> &[HostRequest] {
        &self.requests
    }
}

impl DeviceTransport for InMemoryDeviceTransport {
    fn write_frame(&mut self, _command: CdcCommand, payload: &[u8]) -> Result<(), SharedError> {
        let request: HostRequest = postcard_from_bytes(payload).map_err(SharedError::from)?;
        self.requests.push(request);
        Ok(())
    }

    fn read_frame(&mut self) -> Result<(CdcCommand, Vec<u8>), SharedError> {
        let response = self.responses.pop_front().ok_or_else(|| {
            SharedError::Transport("in-memory transport ran out of responses".into())
        })?;
        let command = command_for_response(&response);
        let payload = postcard_to_allocvec(&response).map_err(SharedError::from)?;
        Ok((command, payload))
    }
}

#[derive(Default)]
pub(crate) struct InMemoryArtifactStore {
    vault: Option<Vec<u8>>,
    recipients: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
}

impl InMemoryArtifactStore {
    pub(crate) fn set(&mut self, artifact: VaultArtifact, data: Vec<u8>) {
        match artifact {
            VaultArtifact::Vault => self.vault = Some(data),
            VaultArtifact::Recipients => self.recipients = Some(data),
            VaultArtifact::Signature => self.signature = Some(data),
        }
    }

    pub(crate) fn artifact_bytes(&self, artifact: VaultArtifact) -> Option<Vec<u8>> {
        match artifact {
            VaultArtifact::Vault => self.vault.clone(),
            VaultArtifact::Recipients => self.recipients.clone(),
            VaultArtifact::Signature => self.signature.clone(),
        }
    }
}

impl RepoArtifactStore for InMemoryArtifactStore {
    fn load(&self, artifact: VaultArtifact) -> Result<Option<Vec<u8>>, SharedError> {
        Ok(self.artifact_bytes(artifact))
    }

    fn persist(&mut self, artifact: VaultArtifact, data: &[u8]) -> Result<(), SharedError> {
        self.set(artifact, data.to_vec());
        Ok(())
    }
}

pub(crate) struct MockPort {
    pub(crate) read_cursor: Cursor<Vec<u8>>,
    pub(crate) writes: Vec<u8>,
}

impl MockPort {
    pub(crate) fn new(read_data: Vec<u8>) -> Self {
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

pub(crate) fn assert_mock_port_is_device_transport() {
    fn assert_transport<T: commands::DeviceTransport>() {}
    assert_transport::<MockPort>();
}

pub(crate) fn decode_written_host_request(payload: &[u8]) -> HostRequest {
    decode_host_request(payload).expect("decode request")
}
