//! Host synchronization state machine, frame encoding, and protocol validation tests.
use alloc::{format, string::String, string::ToString, vec, vec::Vec};
use core::{
    cmp,
    convert::{TryFrom, TryInto},
    ops::Range,
};

use crate::crypto::{
    CryptoMaterial, KeyError, KeyRecord, PinLockState, PinLockStatus, PinUnlockError,
};
#[cfg(any(test, target_arch = "xtensa"))]
use crate::hid::actions::DeviceAction;
use crate::storage::StorageError;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use embedded_storage_async::nor_flash::NorFlash;
use postcard::{from_bytes as postcard_from_bytes, to_allocvec as postcard_to_allocvec};
use sequential_storage::{cache::NoCache, map};

use shared::cdc::transport::{FrameTransportError, command_for_request, command_for_response};
use shared::cdc::{CdcCommand, FRAME_HEADER_SIZE, compute_crc32};
use shared::checksum::accumulate_checksum;
use shared::journal::{FrameTracker, JournalHasher};
use shared::schema::{
    AckRequest, AckResponse, DeviceErrorCode, DeviceResponse, GetTimeRequest, HelloRequest,
    HelloResponse, HostRequest, JournalFrame, JournalOperation, NackResponse, PROTOCOL_VERSION,
    PullHeadRequest, PullHeadResponse, PullVaultRequest, PushOperationsFrame, PushVaultFrame,
    SetTimeRequest, StatusRequest, StatusResponse, TimeResponse, VaultArtifact, VaultChunk,
    decode_host_request, decode_journal_operations, encode_device_response,
};
use shared::transfer::{ArtifactLengths, ArtifactStream};
use zeroize::Zeroizing;

/// Maximum payload size (in bytes) that a single postcard frame is allowed to occupy on the wire.
pub const FRAME_MAX_SIZE: usize = 4096;

/// Capacity provisioned for the encrypted vault image buffer.
const VAULT_BUFFER_CAPACITY: usize = 64 * 1024;
/// Capacity provisioned for the recipients manifest buffer.
const RECIPIENTS_BUFFER_CAPACITY: usize = 4 * 1024;
/// Capacity provisioned for the detached signature buffer.
const SIGNATURE_BUFFER_CAPACITY: usize = 64;
/// Ed25519 public key that signs repository vault artifacts.
const VAULT_SIGNATURE_PUBLIC_KEY: [u8; 32] = [
    0xD7, 0x5A, 0x98, 0x01, 0x82, 0xB1, 0x0A, 0xB7, 0xD5, 0x4B, 0xFE, 0xD3, 0xC9, 0x64, 0x07, 0x3A,
    0x0E, 0xE1, 0x72, 0xF3, 0xDA, 0xA6, 0x23, 0x25, 0xAF, 0x02, 0x1A, 0x68, 0xF7, 0x07, 0x51, 0x1A,
];
/// Scratch buffer used when interacting with sequential storage.
const STORAGE_DATA_BUFFER_CAPACITY: usize =
    VAULT_BUFFER_CAPACITY + RECIPIENTS_BUFFER_CAPACITY + SIGNATURE_BUFFER_CAPACITY;

const STORAGE_KEY_VAULT: u8 = 0x01;
const STORAGE_KEY_RECIPIENTS: u8 = 0x02;
const STORAGE_KEY_JOURNAL: u8 = 0x03;
const STORAGE_KEY_GENERATION: u8 = 0x04;
const STORAGE_KEY_VAULT_KEYS: u8 = 0x05;
const STORAGE_KEY_SIGNATURE: u8 = 0x06;

/// Errors produced while processing host commands.
#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolError {
    /// Host declared a frame length that exceeds our receive buffer.
    FrameTooLarge(usize),
    /// Transport layer could not deliver or send a frame.
    Transport,
    /// Incoming postcard payload could not be decoded.
    Decode(String),
    /// Outgoing postcard payload could not be encoded.
    Encode(String),
    /// Host requested a protocol version that we do not understand.
    UnsupportedProtocol(u16),
    /// Header contained a command that does not match the encoded payload.
    InvalidCommand,
    /// CRC validation failed for an incoming frame.
    ChecksumMismatch,
    /// Host acknowledged a journal frame with mismatching metadata.
    InvalidAcknowledgement,
    /// Host advertised a receive buffer that cannot fit even the smallest response chunk.
    HostBufferTooSmall { required: usize, provided: usize },
}

#[cfg_attr(not(target_arch = "xtensa"), allow(dead_code))]
impl ProtocolError {
    fn as_nack(&self) -> NackResponse {
        let (code, message) = match self {
            ProtocolError::FrameTooLarge(len) => (
                DeviceErrorCode::ResourceExhausted,
                format!("frame length {len} exceeds device buffer"),
            ),
            ProtocolError::Transport => (
                DeviceErrorCode::InternalFailure,
                "transport failure while using USB CDC".into(),
            ),
            ProtocolError::Decode(err) => (
                DeviceErrorCode::InternalFailure,
                format!("failed to decode postcard request: {err}"),
            ),
            ProtocolError::Encode(err) => (
                DeviceErrorCode::InternalFailure,
                format!("failed to encode postcard response: {err}"),
            ),
            ProtocolError::UnsupportedProtocol(version) => (
                DeviceErrorCode::StaleGeneration,
                format!("unsupported protocol version: {version}"),
            ),
            ProtocolError::InvalidCommand => (
                DeviceErrorCode::ChecksumMismatch,
                "command identifier did not match the encoded payload".into(),
            ),
            ProtocolError::ChecksumMismatch => (
                DeviceErrorCode::ChecksumMismatch,
                "frame checksum validation failed".into(),
            ),
            ProtocolError::InvalidAcknowledgement => (
                DeviceErrorCode::ChecksumMismatch,
                "received acknowledgement that does not match the last frame".into(),
            ),
            ProtocolError::HostBufferTooSmall { required, provided } => (
                DeviceErrorCode::ResourceExhausted,
                format!(
                    "host receive buffer {provided} bytes cannot fit the smallest chunk (needs {required})"
                ),
            ),
        };

        NackResponse {
            protocol_version: PROTOCOL_VERSION,
            code,
            message,
        }
    }
}

impl From<FrameTransportError> for ProtocolError {
    fn from(value: FrameTransportError) -> Self {
        match value {
            FrameTransportError::PayloadTooLarge { actual, .. } => {
                ProtocolError::FrameTooLarge(actual)
            }
            FrameTransportError::UnsupportedVersion { found, .. } => {
                ProtocolError::UnsupportedProtocol(found)
            }
            FrameTransportError::LengthMismatch { .. }
            | FrameTransportError::ChecksumMismatch { .. } => ProtocolError::ChecksumMismatch,
            FrameTransportError::Header(err) => ProtocolError::Decode(err.to_string()),
        }
    }
}

/// Runtime state required to service synchronization requests from the host.
#[derive(Debug)]
pub struct SyncContext {
    journal_ops: Vec<JournalOperation>,
    frame_tracker: FrameTracker,
    next_sequence: u32,
    vault_image: Zeroizing<Vec<u8>>,
    recipients_manifest: Zeroizing<Vec<u8>>,
    signature: Zeroizing<Vec<u8>>,
    expected_signature: Option<[u8; SIGNATURE_BUFFER_CAPACITY]>,
    incoming_vault: Zeroizing<Vec<u8>>,
    incoming_recipients: Zeroizing<Vec<u8>>,
    incoming_signature: Zeroizing<Vec<u8>>,
    incoming_vault_complete: bool,
    incoming_recipients_complete: bool,
    incoming_signature_complete: bool,
    transfer: ArtifactStream,
    crypto: CryptoMaterial,
    pin_lock: PinLockState,
    session_id: u32,
    device_name: String,
    firmware_version: String,
    vault_generation: u64,
    current_time_ms: u64,
}

impl Default for SyncContext {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncContext {
    /// Construct a new synchronization context with pre-allocated buffers.
    pub fn new() -> Self {
        Self {
            journal_ops: Vec::new(),
            frame_tracker: FrameTracker::new(),
            next_sequence: 1,
            vault_image: Zeroizing::new(Vec::with_capacity(VAULT_BUFFER_CAPACITY)),
            recipients_manifest: Zeroizing::new(Vec::with_capacity(RECIPIENTS_BUFFER_CAPACITY)),
            signature: Zeroizing::new(Vec::with_capacity(SIGNATURE_BUFFER_CAPACITY)),
            expected_signature: None,
            incoming_vault: Zeroizing::new(Vec::with_capacity(VAULT_BUFFER_CAPACITY)),
            incoming_recipients: Zeroizing::new(Vec::with_capacity(RECIPIENTS_BUFFER_CAPACITY)),
            incoming_signature: Zeroizing::new(Vec::with_capacity(SIGNATURE_BUFFER_CAPACITY)),
            incoming_vault_complete: false,
            incoming_recipients_complete: false,
            incoming_signature_complete: false,
            transfer: ArtifactStream::new(),
            crypto: CryptoMaterial::default(),
            pin_lock: PinLockState::new(),
            session_id: 0,
            device_name: String::from("Cardputer Wallet"),
            firmware_version: String::from(env!("CARGO_PKG_VERSION")),
            vault_generation: 0,
            current_time_ms: 0,
        }
    }

    /// Load persistent state from sequential flash storage.
    pub async fn load_from_flash<S>(
        &mut self,
        flash: &mut S,
        range: Range<u32>,
    ) -> Result<(), StorageError<S::Error>>
    where
        S: NorFlash,
    {
        let mut cache = NoCache::new();
        let mut scratch = Zeroizing::new(vec![0u8; STORAGE_DATA_BUFFER_CAPACITY]);

        self.vault_image = Zeroizing::new(Vec::new());
        if let Some(vault) = map::fetch_item::<u8, Vec<u8>, _>(
            flash,
            range.clone(),
            &mut cache,
            scratch.as_mut_slice(),
            &STORAGE_KEY_VAULT,
        )
        .await
        .map_err(StorageError::Flash)?
        {
            self.vault_image =
                Self::validate_flash_blob::<S::Error>(vault, VAULT_BUFFER_CAPACITY, "vault image")?;
        }

        self.recipients_manifest = Zeroizing::new(Vec::new());
        if let Some(recipients) = map::fetch_item::<u8, Vec<u8>, _>(
            flash,
            range.clone(),
            &mut cache,
            scratch.as_mut_slice(),
            &STORAGE_KEY_RECIPIENTS,
        )
        .await
        .map_err(StorageError::Flash)?
        {
            let blob = Self::validate_flash_blob::<S::Error>(
                recipients,
                RECIPIENTS_BUFFER_CAPACITY,
                "recipients manifest",
            )
            .map_err(|err| self.reset_vault_on_error(err))?;
            self.recipients_manifest = blob;
        }

        self.signature = Zeroizing::new(Vec::new());
        self.expected_signature = None;
        if let Some(signature) = map::fetch_item::<u8, Vec<u8>, _>(
            flash,
            range.clone(),
            &mut cache,
            scratch.as_mut_slice(),
            &STORAGE_KEY_SIGNATURE,
        )
        .await
        .map_err(StorageError::Flash)?
        {
            let blob = Self::validate_signature_blob::<S::Error>(signature)
                .map_err(|err| self.reset_vault_on_error(err))?;
            self.signature = blob;
            if self.signature.len() == SIGNATURE_BUFFER_CAPACITY
                && let Ok(bytes) = self.signature.as_slice().try_into()
            {
                self.expected_signature = Some(bytes);
            }
        }

        if let Some(journal_bytes) = map::fetch_item::<u8, Vec<u8>, _>(
            flash,
            range.clone(),
            &mut cache,
            scratch.as_mut_slice(),
            &STORAGE_KEY_JOURNAL,
        )
        .await
        .map_err(StorageError::Flash)?
        {
            self.journal_ops = decode_journal_operations(&journal_bytes).map_err(|err| {
                StorageError::Decode(format!("failed to decode journal operations: {err}"))
            })?;
        } else {
            self.journal_ops.clear();
        }

        if let Some(generation) = map::fetch_item::<u8, u64, _>(
            flash,
            range.clone(),
            &mut cache,
            scratch.as_mut_slice(),
            &STORAGE_KEY_GENERATION,
        )
        .await
        .map_err(StorageError::Flash)?
        {
            self.vault_generation = generation;
        }

        if let Some(key_bytes) = map::fetch_item::<u8, Vec<u8>, _>(
            flash,
            range,
            &mut cache,
            scratch.as_mut_slice(),
            &STORAGE_KEY_VAULT_KEYS,
        )
        .await
        .map_err(StorageError::Flash)?
        {
            let record: KeyRecord = postcard_from_bytes(&key_bytes).map_err(|err| {
                StorageError::Decode(format!("failed to decode key record: {err}"))
            })?;
            self.crypto.configure_from_record(&record)?;
        }

        self.reset_transfer_state();
        self.frame_tracker.clear();
        self.next_sequence = 1;

        Ok(())
    }

    fn reset_vault_buffers(&mut self) {
        self.vault_image = Zeroizing::new(Vec::new());
    }

    fn reset_vault_on_error<E>(&mut self, err: StorageError<E>) -> StorageError<E> {
        self.reset_vault_buffers();
        err
    }

    fn validate_flash_blob<E>(
        data: Vec<u8>,
        capacity: usize,
        label: &'static str,
    ) -> Result<Zeroizing<Vec<u8>>, StorageError<E>> {
        if data.len() > capacity {
            return Err(StorageError::Decode(format!(
                "{label} exceeds capacity ({} > {})",
                data.len(),
                capacity
            )));
        }

        Ok(Zeroizing::new(data))
    }

    fn validate_signature_blob<E>(data: Vec<u8>) -> Result<Zeroizing<Vec<u8>>, StorageError<E>> {
        if data.len() > SIGNATURE_BUFFER_CAPACITY {
            return Err(StorageError::Decode(format!(
                "signature exceeds capacity ({} > {})",
                data.len(),
                SIGNATURE_BUFFER_CAPACITY
            )));
        }

        if !(data.is_empty() || data.len() == SIGNATURE_BUFFER_CAPACITY) {
            return Err(StorageError::Decode(format!(
                "signature must be exactly {} bytes when present (found {})",
                SIGNATURE_BUFFER_CAPACITY,
                data.len()
            )));
        }

        Ok(Zeroizing::new(data))
    }

    /// Persist key material into flash storage.
    pub async fn persist_crypto_material<S>(
        &self,
        flash: &mut S,
        range: Range<u32>,
    ) -> Result<(), StorageError<S::Error>>
    where
        S: NorFlash,
    {
        if let Some(record) = self.crypto.record() {
            let mut cache = NoCache::new();
            let mut scratch = Zeroizing::new(vec![0u8; STORAGE_DATA_BUFFER_CAPACITY]);
            let encoded = postcard_to_allocvec(&record)
                .map_err(|err| StorageError::Decode(err.to_string()))?;

            map::store_item(
                flash,
                range,
                &mut cache,
                scratch.as_mut_slice(),
                &STORAGE_KEY_VAULT_KEYS,
                &encoded,
            )
            .await
            .map_err(StorageError::Flash)?;
        }

        Ok(())
    }

    pub fn unlock_with_pin(&mut self, pin: &[u8], now_ms: u64) -> Result<(), PinUnlockError> {
        if self.pin_lock.wipe_pending() {
            self.current_time_ms = now_ms;
            return Err(PinUnlockError::WipeRequired);
        }

        if let Some(remaining) = self.pin_lock.remaining_backoff(now_ms) {
            self.current_time_ms = now_ms;
            return Err(PinUnlockError::Backoff {
                remaining_ms: remaining,
            });
        }

        match self.crypto.unlock_vault_key(pin) {
            Ok(()) => {
                self.pin_lock.register_success();
                self.current_time_ms = now_ms;
                Ok(())
            }
            Err(err) => {
                self.current_time_ms = now_ms;
                if matches!(err, KeyError::CryptoFailure) {
                    self.pin_lock.register_failure(now_ms);
                    if self.pin_lock.wipe_pending() {
                        return Err(PinUnlockError::WipeRequired);
                    }
                    if let Some(remaining) = self.pin_lock.remaining_backoff(now_ms)
                        && remaining > 0
                    {
                        return Err(PinUnlockError::Backoff {
                            remaining_ms: remaining,
                        });
                    }
                }
                Err(PinUnlockError::Key(err))
            }
        }
    }

    pub fn pin_lock_status(&self, now_ms: u64) -> PinLockStatus {
        self.pin_lock.status(now_ms)
    }

    /// Register a journal operation that should be emitted on the next pull.
    pub fn record_operation(&mut self, operation: JournalOperation) {
        self.journal_ops.push(operation);
    }

    /// Number of pending journal operations waiting to be synced.
    pub fn pending_operations(&self) -> usize {
        self.journal_ops.len()
    }

    /// Clear the in-memory journal backlog once it has been acknowledged.
    pub fn clear_pending_operations(&mut self) {
        self.journal_ops.clear();
    }

    /// Reset sensitive buffers once a session finishes.
    pub fn wipe_sensitive(&mut self) {
        self.vault_image.iter_mut().for_each(|byte| *byte = 0);
        self.vault_image.clear();

        self.recipients_manifest
            .iter_mut()
            .for_each(|byte| *byte = 0);
        self.recipients_manifest.clear();

        self.signature.iter_mut().for_each(|byte| *byte = 0);
        self.signature.clear();
        self.expected_signature = None;
        self.reset_incoming_state();

        self.crypto.wipe();
        self.reset_transfer_state();
        self.frame_tracker.clear();
    }

    fn reset_transfer_state(&mut self) {
        let lengths = ArtifactLengths {
            vault: self.vault_image.len(),
            recipients: self.recipients_manifest.len(),
            signature: self.signature.len(),
        };
        self.transfer.reset(lengths);
    }

    fn reset_incoming_state(&mut self) {
        self.incoming_vault.iter_mut().for_each(|byte| *byte = 0);
        self.incoming_vault.clear();
        self.incoming_recipients
            .iter_mut()
            .for_each(|byte| *byte = 0);
        self.incoming_recipients.clear();
        self.incoming_signature
            .iter_mut()
            .for_each(|byte| *byte = 0);
        self.incoming_signature.clear();
        self.incoming_vault_complete = false;
        self.incoming_recipients_complete = false;
        self.incoming_signature_complete = false;
    }

    fn finalize_incoming_payload(&mut self) -> Result<String, NackResponse> {
        if self.incoming_signature.len() != SIGNATURE_BUFFER_CAPACITY {
            self.reset_incoming_state();
            return Err(NackResponse {
                protocol_version: PROTOCOL_VERSION,
                code: DeviceErrorCode::ChecksumMismatch,
                message: format!(
                    "signature must contain exactly {} bytes",
                    SIGNATURE_BUFFER_CAPACITY
                ),
            });
        }

        let signature_bytes: [u8; SIGNATURE_BUFFER_CAPACITY] =
            match self.incoming_signature.as_slice().try_into() {
                Ok(bytes) => bytes,
                Err(_) => {
                    self.reset_incoming_state();
                    return Err(NackResponse {
                        protocol_version: PROTOCOL_VERSION,
                        code: DeviceErrorCode::ChecksumMismatch,
                        message: "failed to decode signature payload".into(),
                    });
                }
            };

        let verifying_key = match VerifyingKey::from_bytes(&VAULT_SIGNATURE_PUBLIC_KEY) {
            Ok(key) => key,
            Err(_) => {
                self.reset_incoming_state();
                return Err(NackResponse {
                    protocol_version: PROTOCOL_VERSION,
                    code: DeviceErrorCode::InternalFailure,
                    message: "invalid vault signing public key".into(),
                });
            }
        };

        let signature = match Ed25519Signature::try_from(signature_bytes.as_slice()) {
            Ok(sig) => sig,
            Err(_) => {
                self.reset_incoming_state();
                return Err(NackResponse {
                    protocol_version: PROTOCOL_VERSION,
                    code: DeviceErrorCode::ChecksumMismatch,
                    message: "signature payload rejected".into(),
                });
            }
        };

        let mut signed_payload =
            Vec::with_capacity(self.incoming_vault.len() + self.incoming_recipients.len());
        signed_payload.extend_from_slice(self.incoming_vault.as_slice());
        signed_payload.extend_from_slice(self.incoming_recipients.as_slice());

        if verifying_key.verify(&signed_payload, &signature).is_err() {
            self.reset_incoming_state();
            return Err(NackResponse {
                protocol_version: PROTOCOL_VERSION,
                code: DeviceErrorCode::ChecksumMismatch,
                message: "vault signature verification failed".into(),
            });
        }

        self.vault_image.iter_mut().for_each(|byte| *byte = 0);
        self.vault_image = Zeroizing::new(self.incoming_vault.as_slice().to_vec());
        self.recipients_manifest
            .iter_mut()
            .for_each(|byte| *byte = 0);
        self.recipients_manifest = Zeroizing::new(self.incoming_recipients.as_slice().to_vec());
        self.signature.iter_mut().for_each(|byte| *byte = 0);
        self.signature = Zeroizing::new(signature_bytes.to_vec());
        self.expected_signature = Some(signature_bytes);

        self.vault_generation = self.vault_generation.saturating_add(1);
        self.reset_transfer_state();
        self.reset_incoming_state();

        Ok(format!(
            "updated vault artifacts (vault {} bytes, recipients {} bytes)",
            self.vault_image.len(),
            self.recipients_manifest.len()
        ))
    }

    fn next_transfer_chunk(
        &mut self,
        max_chunk: usize,
        host_buffer_size: usize,
    ) -> Result<VaultChunk, ProtocolError> {
        if host_buffer_size < FRAME_HEADER_SIZE {
            return Err(ProtocolError::HostBufferTooSmall {
                required: FRAME_HEADER_SIZE,
                provided: host_buffer_size,
            });
        }

        let frame_budget = cmp::min(host_buffer_size - FRAME_HEADER_SIZE, FRAME_MAX_SIZE);
        let max_payload = cmp::min(max_chunk, frame_budget);
        let device_chunk_size = cmp::max(1, max_payload) as u32;
        let mut chunk_size = max_payload;

        loop {
            let pending = self.transfer.prepare_chunk(
                self.next_sequence,
                chunk_size,
                device_chunk_size,
                |artifact| match artifact {
                    VaultArtifact::Vault => self.vault_image.as_slice(),
                    VaultArtifact::Recipients => self.recipients_manifest.as_slice(),
                    VaultArtifact::Signature => self.signature.as_slice(),
                },
            );
            let chunk = pending.chunk().clone();
            let response = DeviceResponse::VaultChunk(chunk.clone());
            let encoded_len = match encode_device_response(&response) {
                Ok(bytes) => bytes.len(),
                Err(_) => {
                    if let DeviceResponse::VaultChunk(chunk) = response {
                        return Ok(chunk);
                    }
                    unreachable!("response must be a vault chunk");
                }
            };

            if encoded_len <= frame_budget {
                if chunk_size == 0 && chunk.remaining_bytes > 0 {
                    return Err(ProtocolError::HostBufferTooSmall {
                        required: encoded_len + FRAME_HEADER_SIZE,
                        provided: host_buffer_size,
                    });
                }
                return Ok(self.transfer.commit_chunk(pending));
            }

            if chunk_size == 0 {
                if chunk.remaining_bytes > 0 || frame_budget < encoded_len {
                    return Err(ProtocolError::HostBufferTooSmall {
                        required: encoded_len + FRAME_HEADER_SIZE,
                        provided: host_buffer_size,
                    });
                }

                return Ok(self.transfer.commit_chunk(pending));
            }

            let overhead = encoded_len.saturating_sub(chunk.data.len());
            if overhead >= frame_budget {
                chunk_size = 0;
                continue;
            }

            let target_size = frame_budget - overhead;
            let available = chunk
                .data
                .len()
                .saturating_add(chunk.remaining_bytes as usize);
            let new_size = cmp::min(target_size, available);

            if new_size >= chunk_size {
                chunk_size = chunk_size.saturating_sub(1);
            } else {
                chunk_size = new_size;
            }
        }
    }
}

fn artifact_hash(data: &[u8]) -> [u8; 32] {
    let checksum = compute_crc32(data);
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&checksum.to_le_bytes());
    hash
}

fn decode_request(frame: &[u8]) -> Result<HostRequest, ProtocolError> {
    decode_host_request(frame).map_err(|err| ProtocolError::Decode(err.to_string()))
}

pub(crate) fn encode_response(response: &DeviceResponse) -> Result<Vec<u8>, ProtocolError> {
    encode_device_response(response).map_err(|err| ProtocolError::Encode(err.to_string()))
}

/// Decode a host frame, dispatch to the appropriate handler and encode the response.
pub fn process_host_frame(
    command: CdcCommand,
    frame: &[u8],
    ctx: &mut SyncContext,
) -> Result<(CdcCommand, Vec<u8>), ProtocolError> {
    let request = decode_request(frame)?;
    if command_for_request(&request) != command {
        return Err(ProtocolError::InvalidCommand);
    }

    let response = match request {
        HostRequest::Hello(hello) => handle_hello(&hello, ctx)?,
        HostRequest::Status(status) => handle_status(&status, ctx)?,
        HostRequest::SetTime(set_time) => handle_set_time(&set_time, ctx)?,
        HostRequest::GetTime(get_time) => handle_get_time(&get_time, ctx)?,
        HostRequest::PullHead(head) => handle_pull_head(&head, ctx)?,
        HostRequest::PullVault(pull) => handle_pull(&pull, ctx)?,
        HostRequest::PushVault(frame) => handle_push_vault(&frame, ctx)?,
        HostRequest::PushOps(push) => handle_push_ops(&push, ctx)?,
        HostRequest::Ack(ack) => handle_ack(&ack, ctx)?,
    };

    let response_command = command_for_response(&response);
    Ok((response_command, encode_response(&response)?))
}

fn handle_hello(
    request: &HelloRequest,
    ctx: &mut SyncContext,
) -> Result<DeviceResponse, ProtocolError> {
    if request.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocol(request.protocol_version));
    }

    ctx.session_id = ctx.session_id.wrapping_add(1);
    if ctx.session_id == 0 {
        ctx.session_id = 1;
    }
    ctx.frame_tracker.clear();
    ctx.next_sequence = 1;
    ctx.reset_transfer_state();

    #[cfg(any(test, target_arch = "xtensa"))]
    crate::hid::actions::publish(DeviceAction::StartSession {
        session_id: ctx.session_id,
    });

    Ok(DeviceResponse::Hello(HelloResponse {
        protocol_version: PROTOCOL_VERSION,
        device_name: ctx.device_name.clone(),
        firmware_version: ctx.firmware_version.clone(),
        session_id: ctx.session_id,
    }))
}

fn handle_status(
    request: &StatusRequest,
    ctx: &mut SyncContext,
) -> Result<DeviceResponse, ProtocolError> {
    if request.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocol(request.protocol_version));
    }

    Ok(DeviceResponse::Status(StatusResponse {
        protocol_version: PROTOCOL_VERSION,
        vault_generation: ctx.vault_generation,
        pending_operations: ctx.journal_ops.len() as u32,
        current_time_ms: ctx.current_time_ms,
    }))
}

fn handle_set_time(
    request: &SetTimeRequest,
    ctx: &mut SyncContext,
) -> Result<DeviceResponse, ProtocolError> {
    if request.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocol(request.protocol_version));
    }

    ctx.current_time_ms = request.epoch_millis;

    Ok(DeviceResponse::Ack(AckResponse {
        protocol_version: PROTOCOL_VERSION,
        message: format!("clock set to {} ms", request.epoch_millis),
    }))
}

fn handle_get_time(
    request: &GetTimeRequest,
    ctx: &mut SyncContext,
) -> Result<DeviceResponse, ProtocolError> {
    if request.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocol(request.protocol_version));
    }

    Ok(DeviceResponse::Time(TimeResponse {
        protocol_version: PROTOCOL_VERSION,
        epoch_millis: ctx.current_time_ms,
    }))
}

fn handle_pull_head(
    request: &PullHeadRequest,
    ctx: &mut SyncContext,
) -> Result<DeviceResponse, ProtocolError> {
    if request.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocol(request.protocol_version));
    }

    let vault_hash = artifact_hash(&ctx.vault_image);
    let recipients_hash = artifact_hash(&ctx.recipients_manifest);
    let signature_hash = artifact_hash(&ctx.signature);

    Ok(DeviceResponse::Head(PullHeadResponse {
        protocol_version: PROTOCOL_VERSION,
        vault_generation: ctx.vault_generation,
        vault_hash,
        recipients_hash,
        signature_hash,
    }))
}

fn handle_pull(
    request: &PullVaultRequest,
    ctx: &mut SyncContext,
) -> Result<DeviceResponse, ProtocolError> {
    if request.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocol(request.protocol_version));
    }

    let host_in_sync = request
        .known_generation
        .map(|generation| generation == ctx.vault_generation)
        .unwrap_or(false);

    if host_in_sync && ctx.journal_ops.is_empty() && !ctx.frame_tracker.is_pending() {
        let response = DeviceResponse::VaultChunk(ctx.next_transfer_chunk(
            request.max_chunk_size as usize,
            request.host_buffer_size as usize,
        )?);
        let encoded_len = encode_response(&response)?.len();
        let frame_size = encoded_len + FRAME_HEADER_SIZE;
        if frame_size > request.host_buffer_size as usize {
            return Err(ProtocolError::HostBufferTooSmall {
                required: frame_size,
                provided: request.host_buffer_size as usize,
            });
        }
        let (checksum, sequence) = match &response {
            DeviceResponse::VaultChunk(chunk) => (chunk.checksum, chunk.sequence),
            _ => unreachable!("response must be a vault chunk"),
        };
        ctx.frame_tracker.record(sequence, checksum);
        ctx.next_sequence = ctx.next_sequence.wrapping_add(1);

        return Ok(response);
    }

    if !ctx.journal_ops.is_empty() {
        let operations = core::mem::take(&mut ctx.journal_ops);
        let checksum = JournalHasher::digest(&operations);
        let sequence = ctx.next_sequence;
        ctx.next_sequence = ctx.next_sequence.wrapping_add(1);
        ctx.frame_tracker.record(sequence, checksum);

        Ok(DeviceResponse::JournalFrame(JournalFrame {
            protocol_version: PROTOCOL_VERSION,
            sequence,
            remaining_operations: 0,
            operations,
            checksum,
        }))
    } else {
        let response = DeviceResponse::VaultChunk(ctx.next_transfer_chunk(
            request.max_chunk_size as usize,
            request.host_buffer_size as usize,
        )?);
        let encoded_len = encode_response(&response)?.len();
        let frame_size = encoded_len + FRAME_HEADER_SIZE;
        if frame_size > request.host_buffer_size as usize {
            return Err(ProtocolError::HostBufferTooSmall {
                required: frame_size,
                provided: request.host_buffer_size as usize,
            });
        }
        let (checksum, sequence) = match &response {
            DeviceResponse::VaultChunk(chunk) => (chunk.checksum, chunk.sequence),
            _ => unreachable!("response must be a vault chunk"),
        };
        ctx.frame_tracker.record(sequence, checksum);
        ctx.next_sequence = ctx.next_sequence.wrapping_add(1);

        Ok(response)
    }
}

fn handle_push_ops(
    push: &PushOperationsFrame,
    ctx: &mut SyncContext,
) -> Result<DeviceResponse, ProtocolError> {
    if push.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocol(push.protocol_version));
    }

    let calculated = JournalHasher::digest(&push.operations);
    if calculated != push.checksum {
        return Err(ProtocolError::ChecksumMismatch);
    }

    if push.is_last {
        ctx.vault_generation = ctx.vault_generation.saturating_add(1);
        ctx.frame_tracker.clear();
    }

    Ok(DeviceResponse::Ack(AckResponse {
        protocol_version: PROTOCOL_VERSION,
        message: format!(
            "applied {} push operation{} (frame #{} checksum 0x{:08X})",
            push.operations.len(),
            if push.operations.len() == 1 { "" } else { "s" },
            push.sequence,
            push.checksum
        ),
    }))
}

fn handle_ack(ack: &AckRequest, ctx: &mut SyncContext) -> Result<DeviceResponse, ProtocolError> {
    if ack.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocol(ack.protocol_version));
    }

    if ctx
        .frame_tracker
        .confirm(ack.last_frame_sequence, ack.journal_checksum)
    {
        ctx.wipe_sensitive();

        #[cfg(any(test, target_arch = "xtensa"))]
        crate::hid::actions::publish(DeviceAction::EndSession);

        Ok(DeviceResponse::Ack(AckResponse {
            protocol_version: PROTOCOL_VERSION,
            message: format!(
                "acknowledged journal frame #{} (checksum 0x{:08X})",
                ack.last_frame_sequence, ack.journal_checksum
            ),
        }))
    } else {
        Err(ProtocolError::InvalidAcknowledgement)
    }
}

fn handle_push_vault(
    frame: &PushVaultFrame,
    ctx: &mut SyncContext,
) -> Result<DeviceResponse, ProtocolError> {
    if frame.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocol(frame.protocol_version));
    }

    let calculated = accumulate_checksum(0, &frame.data);
    if calculated != frame.checksum {
        return Err(ProtocolError::ChecksumMismatch);
    }

    if frame.artifact == VaultArtifact::Vault && frame.sequence == 1 {
        ctx.reset_incoming_state();
    }

    let (buffer, capacity, complete_flag) = match frame.artifact {
        VaultArtifact::Vault => (
            &mut ctx.incoming_vault,
            VAULT_BUFFER_CAPACITY,
            &mut ctx.incoming_vault_complete,
        ),
        VaultArtifact::Recipients => (
            &mut ctx.incoming_recipients,
            RECIPIENTS_BUFFER_CAPACITY,
            &mut ctx.incoming_recipients_complete,
        ),
        VaultArtifact::Signature => (
            &mut ctx.incoming_signature,
            SIGNATURE_BUFFER_CAPACITY,
            &mut ctx.incoming_signature_complete,
        ),
    };

    if frame.sequence == 1 {
        buffer.iter_mut().for_each(|byte| *byte = 0);
        buffer.clear();
        *complete_flag = false;
    }

    if buffer.len().saturating_add(frame.data.len()) > capacity {
        ctx.reset_incoming_state();
        return Ok(DeviceResponse::Nack(NackResponse {
            protocol_version: PROTOCOL_VERSION,
            code: DeviceErrorCode::ResourceExhausted,
            message: format!(
                "{} payload exceeds device capacity",
                match frame.artifact {
                    VaultArtifact::Vault => "vault",
                    VaultArtifact::Recipients => "recipients",
                    VaultArtifact::Signature => "signature",
                }
            ),
        }));
    }

    buffer.extend_from_slice(&frame.data);

    if frame.is_last {
        *complete_flag = true;
        if matches!(frame.artifact, VaultArtifact::Signature)
            && buffer.len() != SIGNATURE_BUFFER_CAPACITY
        {
            ctx.reset_incoming_state();
            return Ok(DeviceResponse::Nack(NackResponse {
                protocol_version: PROTOCOL_VERSION,
                code: DeviceErrorCode::ChecksumMismatch,
                message: format!(
                    "signature must contain exactly {} bytes",
                    SIGNATURE_BUFFER_CAPACITY
                ),
            }));
        }
    } else if matches!(frame.artifact, VaultArtifact::Signature)
        && buffer.len() >= SIGNATURE_BUFFER_CAPACITY
    {
        ctx.reset_incoming_state();
        return Ok(DeviceResponse::Nack(NackResponse {
            protocol_version: PROTOCOL_VERSION,
            code: DeviceErrorCode::ResourceExhausted,
            message: "signature chunk exceeds capacity".into(),
        }));
    }

    if ctx.incoming_vault_complete
        && ctx.incoming_recipients_complete
        && ctx.incoming_signature_complete
    {
        match ctx.finalize_incoming_payload() {
            Ok(message) => Ok(DeviceResponse::Ack(AckResponse {
                protocol_version: PROTOCOL_VERSION,
                message,
            })),
            Err(nack) => Ok(DeviceResponse::Nack(nack)),
        }
    } else {
        Ok(DeviceResponse::Ack(AckResponse {
            protocol_version: PROTOCOL_VERSION,
            message: format!(
                "received {:?} chunk #{} ({} bytes, {} remaining)",
                frame.artifact,
                frame.sequence,
                frame.data.len(),
                frame.remaining_bytes
            ),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use sequential_storage::mock_flash::{MockFlashBase, WriteCountCheck};
    use shared::cdc::FrameHeader;
    use shared::cdc::transport::{decode_frame, encode_frame};
    use shared::journal::FrameState;
    use shared::schema::{decode_device_response, encode_host_request, encode_journal_operations};

    fn fresh_context() -> SyncContext {
        crate::hid::actions::clear();
        SyncContext::new()
    }

    #[test]
    fn pull_request_with_matching_generation_returns_placeholder_chunk() {
        let mut ctx = fresh_context();
        ctx.vault_generation = 7;

        let request = PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: 64 * 1024,
            max_chunk_size: 1024,
            known_generation: Some(7),
        };

        let response = handle_pull(&request, &mut ctx).expect("pull chunk");
        match response {
            DeviceResponse::VaultChunk(chunk) => {
                assert_eq!(chunk.protocol_version, PROTOCOL_VERSION);
                assert_eq!(chunk.sequence, 1);
                assert!(chunk.data.is_empty());
                assert_eq!(chunk.total_size, 0);
                assert_eq!(chunk.remaining_bytes, 0);
                assert!(chunk.is_last);
                assert_eq!(
                    ctx.frame_tracker.state(),
                    Some(FrameState {
                        sequence: chunk.sequence,
                        checksum: chunk.checksum,
                    })
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }

        assert!(ctx.journal_ops.is_empty());
        assert_eq!(ctx.next_sequence, 2);
    }

    #[test]
    fn pull_request_emits_journal_frame() {
        let mut ctx = fresh_context();
        ctx.record_operation(JournalOperation::Add {
            entry_id: String::from("entry-42"),
        });

        let request = HostRequest::PullVault(PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: 64 * 1024,
            max_chunk_size: 1024,
            known_generation: None,
        });

        let encoded = encode_host_request(&request).expect("encode request");
        let (command, response_bytes) =
            process_host_frame(CdcCommand::PullVault, &encoded, &mut ctx).expect("process pull");
        assert_eq!(command, CdcCommand::PushOps);
        let response = decode_device_response(&response_bytes).expect("decode response");

        match response {
            DeviceResponse::JournalFrame(frame) => {
                assert_eq!(frame.protocol_version, PROTOCOL_VERSION);
                assert_eq!(frame.sequence, 1);
                assert_eq!(frame.operations.len(), 1);
                assert_eq!(
                    ctx.frame_tracker.state(),
                    Some(FrameState {
                        sequence: frame.sequence,
                        checksum: frame.checksum,
                    })
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn pull_request_streams_vault_then_recipients() {
        let mut ctx = fresh_context();
        ctx.vault_image.extend_from_slice(b"vault-data");
        ctx.recipients_manifest.extend_from_slice(b"rec");
        ctx.reset_transfer_state();

        let request = PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: 64 * 1024,
            max_chunk_size: 4,
            known_generation: None,
        };

        let mut chunks = Vec::new();
        for _ in 0..6 {
            let response = handle_pull(&request, &mut ctx).expect("pull chunk");
            match response {
                DeviceResponse::VaultChunk(chunk) => chunks.push(chunk),
                other => panic!("unexpected response: {other:?}"),
            }

            if let Some(last) = chunks.last()
                && last.artifact == VaultArtifact::Recipients
                && last.is_last
            {
                break;
            }
        }

        assert!(
            chunks
                .iter()
                .any(|chunk| chunk.artifact == VaultArtifact::Vault)
        );
        assert!(
            chunks
                .iter()
                .any(|chunk| chunk.artifact == VaultArtifact::Vault && chunk.is_last)
        );
        let last = chunks.last().expect("at least one chunk");
        assert_eq!(last.artifact, VaultArtifact::Recipients);
        assert!(last.is_last);
        assert_eq!(last.data, b"rec");
        assert_eq!(
            ctx.frame_tracker.state(),
            Some(FrameState {
                sequence: last.sequence,
                checksum: last.checksum,
            })
        );
    }

    #[test]
    fn pull_request_respects_host_buffer_limit() {
        let mut ctx = fresh_context();
        ctx.vault_image.extend_from_slice(&[0xAA; 64]);
        ctx.reset_transfer_state();

        let request = PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: 96,
            max_chunk_size: 256,
            known_generation: None,
        };

        let response = handle_pull(&request, &mut ctx).expect("pull chunk");
        let chunk = match response {
            DeviceResponse::VaultChunk(chunk) => chunk,
            other => panic!("unexpected response: {other:?}"),
        };

        assert!(chunk.data.len() as u32 <= request.max_chunk_size);

        let encoded =
            encode_device_response(&DeviceResponse::VaultChunk(chunk.clone())).expect("encode");
        assert!(encoded.len() as u32 <= request.host_buffer_size);
    }

    #[test]
    fn pull_request_rejects_tiny_host_buffer() {
        let mut ctx = fresh_context();
        ctx.vault_image.extend_from_slice(b"payload");
        ctx.reset_transfer_state();

        let request = PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: 24,
            max_chunk_size: 1024,
            known_generation: None,
        };

        let error = handle_pull(&request, &mut ctx).expect_err("expected buffer error");
        assert!(matches!(
            error,
            ProtocolError::HostBufferTooSmall {
                required: _,
                provided: 24
            }
        ));
    }

    #[test]
    fn acknowledgement_clears_pending_sequence() {
        let mut ctx = fresh_context();
        ctx.record_operation(JournalOperation::Delete {
            entry_id: String::from("obsolete"),
        });

        let pull_request = HostRequest::PullVault(PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: 64 * 1024,
            max_chunk_size: 1024,
            known_generation: None,
        });
        let encoded_pull = encode_host_request(&pull_request).unwrap();
        let (response_command, response_bytes) =
            process_host_frame(CdcCommand::PullVault, &encoded_pull, &mut ctx).unwrap();
        assert_eq!(response_command, CdcCommand::PushOps);
        let frame = decode_device_response(&response_bytes).unwrap();
        let (sequence, checksum) = match frame {
            DeviceResponse::JournalFrame(frame) => (frame.sequence, frame.checksum),
            other => panic!("unexpected response: {other:?}"),
        };

        let ack = HostRequest::Ack(AckRequest {
            protocol_version: PROTOCOL_VERSION,
            last_frame_sequence: sequence,
            journal_checksum: checksum,
        });
        let encoded_ack = encode_host_request(&ack).unwrap();
        let (ack_command, ack_response) =
            process_host_frame(CdcCommand::Ack, &encoded_ack, &mut ctx).unwrap();
        assert_eq!(ack_command, CdcCommand::Ack);
        let decoded = decode_device_response(&ack_response).unwrap();

        match decoded {
            DeviceResponse::Ack(message) => {
                assert_eq!(message.protocol_version, PROTOCOL_VERSION);
                assert!(message.message.contains(&sequence.to_string()));
            }
            other => panic!("unexpected response: {other:?}"),
        }

        assert!(!ctx.frame_tracker.is_pending());
    }

    #[test]
    fn hello_enqueues_ble_session_action() {
        let mut ctx = fresh_context();
        let request = HostRequest::Hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            client_name: "cli".into(),
            client_version: "0.1.0".into(),
        });

        let encoded = encode_host_request(&request).unwrap();
        let _ = process_host_frame(CdcCommand::Hello, &encoded, &mut ctx).unwrap();

        let actions = crate::hid::actions::drain();
        assert_eq!(
            actions,
            vec![DeviceAction::StartSession {
                session_id: ctx.session_id,
            }]
        );
    }

    #[test]
    fn ack_enqueues_session_end_action() {
        let mut ctx = fresh_context();
        ctx.record_operation(JournalOperation::Add {
            entry_id: String::from("to-sync"),
        });

        let pull = HostRequest::PullVault(PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: 64 * 1024,
            max_chunk_size: 1024,
            known_generation: None,
        });
        let encoded_pull = encode_host_request(&pull).unwrap();
        let (_, response_bytes) =
            process_host_frame(CdcCommand::PullVault, &encoded_pull, &mut ctx).unwrap();
        let (sequence, checksum) = match decode_device_response(&response_bytes).unwrap() {
            DeviceResponse::JournalFrame(frame) => (frame.sequence, frame.checksum),
            other => panic!("unexpected response: {other:?}"),
        };

        crate::hid::actions::drain();

        let ack = HostRequest::Ack(AckRequest {
            protocol_version: PROTOCOL_VERSION,
            last_frame_sequence: sequence,
            journal_checksum: checksum,
        });
        let encoded_ack = encode_host_request(&ack).unwrap();
        let _ = process_host_frame(CdcCommand::Ack, &encoded_ack, &mut ctx).unwrap();

        let actions = crate::hid::actions::drain();
        assert!(
            !actions.is_empty()
                && actions
                    .iter()
                    .all(|action| matches!(action, DeviceAction::EndSession))
        );
    }

    #[test]
    fn acknowledgement_keeps_vault_generation() {
        let mut ctx = fresh_context();
        ctx.vault_generation = 7;
        let expected_generation = ctx.vault_generation;
        let pending = FrameState {
            sequence: 12,
            checksum: 0xABCD_1234,
        };
        ctx.frame_tracker.record_state(pending);

        let ack = AckRequest {
            protocol_version: PROTOCOL_VERSION,
            last_frame_sequence: pending.sequence,
            journal_checksum: pending.checksum,
        };

        let response = handle_ack(&ack, &mut ctx).expect("ack should succeed");

        match response {
            DeviceResponse::Ack(message) => {
                assert_eq!(message.protocol_version, PROTOCOL_VERSION);
                assert!(message.message.contains(&pending.sequence.to_string()));
            }
            other => panic!("unexpected response: {other:?}"),
        }

        assert!(!ctx.frame_tracker.is_pending());
        assert_eq!(ctx.vault_generation, expected_generation);
    }

    #[test]
    fn push_operations_are_acknowledged() {
        let mut ctx = fresh_context();
        let operations = vec![JournalOperation::Add {
            entry_id: String::from("pushed"),
        }];
        let checksum = JournalHasher::digest(&operations);

        let request = HostRequest::PushOps(PushOperationsFrame {
            protocol_version: PROTOCOL_VERSION,
            sequence: 3,
            operations,
            checksum,
            is_last: true,
        });

        let encoded = encode_host_request(&request).expect("encode push frame");
        let (command, response_bytes) =
            process_host_frame(CdcCommand::PushOps, &encoded, &mut ctx).expect("process push");
        assert_eq!(command, CdcCommand::Ack);
        let response = decode_device_response(&response_bytes).expect("decode ack response");

        match response {
            DeviceResponse::Ack(message) => {
                assert!(message.message.contains("frame #3"));
                assert!(message.message.contains("0x"));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn push_vault_with_valid_signature_applies_changes() {
        let mut ctx = fresh_context();
        let vault = b"vault-bytes".to_vec();
        let recipients = b"{\"recipients\":[]}".to_vec();

        let signing_key = SigningKey::from_bytes(&[
            0x9D, 0x61, 0xB1, 0x9D, 0xEF, 0xFD, 0x5A, 0x60, 0xBA, 0x84, 0x4A, 0xF4, 0x92, 0xEC,
            0x2C, 0xC4, 0x44, 0x49, 0xC5, 0x69, 0x7B, 0x32, 0x69, 0x19, 0x70, 0x3B, 0xAC, 0x03,
            0x1C, 0xAE, 0x7F, 0x60,
        ]);
        let mut signed_payload = Vec::new();
        signed_payload.extend_from_slice(&vault);
        signed_payload.extend_from_slice(&recipients);
        let signature = signing_key.sign(&signed_payload);
        let signature_bytes = signature.to_bytes();

        let vault_request = HostRequest::PushVault(PushVaultFrame {
            protocol_version: PROTOCOL_VERSION,
            sequence: 1,
            artifact: VaultArtifact::Vault,
            total_size: vault.len() as u64,
            remaining_bytes: 0,
            data: vault.clone(),
            checksum: accumulate_checksum(0, &vault),
            is_last: true,
        });
        let encoded_vault = encode_host_request(&vault_request).expect("encode vault frame");
        let (command_vault, response_vault) =
            process_host_frame(CdcCommand::PushVault, &encoded_vault, &mut ctx)
                .expect("process vault chunk");
        assert_eq!(command_vault, CdcCommand::Ack);
        match decode_device_response(&response_vault).expect("decode vault ack") {
            DeviceResponse::Ack(message) => {
                assert!(message.message.contains("Vault"));
            }
            other => panic!("unexpected response: {other:?}"),
        }

        let recipients_request = HostRequest::PushVault(PushVaultFrame {
            protocol_version: PROTOCOL_VERSION,
            sequence: 2,
            artifact: VaultArtifact::Recipients,
            total_size: recipients.len() as u64,
            remaining_bytes: 0,
            data: recipients.clone(),
            checksum: accumulate_checksum(0, &recipients),
            is_last: true,
        });
        let encoded_recipients =
            encode_host_request(&recipients_request).expect("encode recipients frame");
        let (command_recips, response_recips) =
            process_host_frame(CdcCommand::PushVault, &encoded_recipients, &mut ctx)
                .expect("process recipients chunk");
        assert_eq!(command_recips, CdcCommand::Ack);
        match decode_device_response(&response_recips).expect("decode recipients ack") {
            DeviceResponse::Ack(message) => {
                assert!(message.message.contains("Recipients"));
            }
            other => panic!("unexpected response: {other:?}"),
        }

        let signature_vec = signature_bytes.to_vec();
        let signature_request = HostRequest::PushVault(PushVaultFrame {
            protocol_version: PROTOCOL_VERSION,
            sequence: 3,
            artifact: VaultArtifact::Signature,
            total_size: SIGNATURE_BUFFER_CAPACITY as u64,
            remaining_bytes: 0,
            data: signature_vec.clone(),
            checksum: accumulate_checksum(0, &signature_vec),
            is_last: true,
        });
        let encoded_signature =
            encode_host_request(&signature_request).expect("encode signature frame");
        let (command_sig, response_sig) =
            process_host_frame(CdcCommand::PushVault, &encoded_signature, &mut ctx)
                .expect("process signature chunk");
        assert_eq!(command_sig, CdcCommand::Ack);
        match decode_device_response(&response_sig).expect("decode signature ack") {
            DeviceResponse::Ack(message) => {
                assert!(message.message.contains("updated vault artifacts"));
            }
            other => panic!("unexpected response: {other:?}"),
        }

        assert_eq!(ctx.vault_image.as_slice(), vault.as_slice());
        assert_eq!(ctx.recipients_manifest.as_slice(), recipients.as_slice());
        assert_eq!(ctx.signature.as_slice(), signature_vec.as_slice());
        assert_eq!(ctx.expected_signature, Some(signature_bytes));
        assert_eq!(ctx.vault_generation, 1);
        assert!(ctx.incoming_vault.is_empty());
        assert!(ctx.incoming_recipients.is_empty());
        assert!(ctx.incoming_signature.is_empty());
    }

    #[test]
    fn push_vault_with_invalid_signature_is_rejected() {
        let mut ctx = fresh_context();
        let vault = b"vault".to_vec();
        let recipients = b"recipients".to_vec();

        let signing_key = SigningKey::from_bytes(&[
            0x9D, 0x61, 0xB1, 0x9D, 0xEF, 0xFD, 0x5A, 0x60, 0xBA, 0x84, 0x4A, 0xF4, 0x92, 0xEC,
            0x2C, 0xC4, 0x44, 0x49, 0xC5, 0x69, 0x7B, 0x32, 0x69, 0x19, 0x70, 0x3B, 0xAC, 0x03,
            0x1C, 0xAE, 0x7F, 0x60,
        ]);
        let mut signed_payload = Vec::new();
        signed_payload.extend_from_slice(&vault);
        signed_payload.extend_from_slice(&recipients);
        let mut signature = signing_key.sign(&signed_payload).to_bytes();
        signature[0] ^= 0xFF;

        let frames = [
            HostRequest::PushVault(PushVaultFrame {
                protocol_version: PROTOCOL_VERSION,
                sequence: 1,
                artifact: VaultArtifact::Vault,
                total_size: vault.len() as u64,
                remaining_bytes: 0,
                data: vault.clone(),
                checksum: accumulate_checksum(0, &vault),
                is_last: true,
            }),
            HostRequest::PushVault(PushVaultFrame {
                protocol_version: PROTOCOL_VERSION,
                sequence: 2,
                artifact: VaultArtifact::Recipients,
                total_size: recipients.len() as u64,
                remaining_bytes: 0,
                data: recipients.clone(),
                checksum: accumulate_checksum(0, &recipients),
                is_last: true,
            }),
            HostRequest::PushVault(PushVaultFrame {
                protocol_version: PROTOCOL_VERSION,
                sequence: 3,
                artifact: VaultArtifact::Signature,
                total_size: SIGNATURE_BUFFER_CAPACITY as u64,
                remaining_bytes: 0,
                data: signature.to_vec(),
                checksum: accumulate_checksum(0, &signature),
                is_last: true,
            }),
        ];

        for request in frames.into_iter() {
            let encoded = encode_host_request(&request).expect("encode frame");
            let (command, response_bytes) =
                process_host_frame(CdcCommand::PushVault, &encoded, &mut ctx)
                    .expect("process frame");

            let response = decode_device_response(&response_bytes).expect("decode response");
            match request {
                HostRequest::PushVault(ref push)
                    if matches!(push.artifact, VaultArtifact::Signature) =>
                {
                    assert_eq!(command, CdcCommand::Nack);
                    match response {
                        DeviceResponse::Nack(nack) => {
                            assert!(nack.message.contains("vault signature verification failed"));
                        }
                        other => panic!("unexpected response: {other:?}"),
                    }
                }
                _ => {
                    assert_eq!(command, CdcCommand::Ack);
                    assert!(matches!(response, DeviceResponse::Ack(_)));
                }
            }
        }

        assert!(ctx.vault_image.is_empty());
        assert!(ctx.recipients_manifest.is_empty());
        assert!(ctx.signature.is_empty());
        assert!(ctx.expected_signature.is_none());
        assert_eq!(ctx.vault_generation, 0);
        assert!(ctx.incoming_vault.is_empty());
        assert!(ctx.incoming_recipients.is_empty());
        assert!(ctx.incoming_signature.is_empty());
    }

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
        let request = HostRequest::PullVault(PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: 1,
            max_chunk_size: 1,
            known_generation: None,
        });
        let encoded = encode_host_request(&request).unwrap();
        let error = process_host_frame(CdcCommand::Ack, &encoded, &mut ctx)
            .expect_err("expected command mismatch");
        assert_eq!(error, ProtocolError::InvalidCommand);
    }

    #[test]
    fn checksum_validation_detects_corruption() {
        crate::hid::actions::clear();
        let payload = b"payload".to_vec();
        let mut header = FrameHeader::new(
            PROTOCOL_VERSION,
            CdcCommand::PullVault,
            payload.len() as u32,
            compute_crc32(&payload),
        );

        // Good checksum passes validation.
        decode_frame(&header, &payload).expect("valid checksum");

        header.checksum ^= 0xFFFF_FFFF;
        let error = decode_frame(&header, &payload).expect_err("expected checksum error");
        assert_eq!(ProtocolError::from(error), ProtocolError::ChecksumMismatch);
    }

    #[test]
    fn transport_limit_matches_firmware_max_size() {
        crate::hid::actions::clear();
        let payload = vec![0u8; FRAME_MAX_SIZE + 1];
        let err = encode_frame(
            PROTOCOL_VERSION,
            CdcCommand::Hello,
            &payload,
            FRAME_MAX_SIZE,
        )
        .expect_err("frame too large");
        assert!(matches!(
            ProtocolError::from(err),
            ProtocolError::FrameTooLarge(_)
        ));
    }

    #[test]
    fn hello_establishes_session() {
        let mut ctx = fresh_context();
        let request = HostRequest::Hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            client_name: "cli".into(),
            client_version: "0.1.0".into(),
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
        ctx.current_time_ms = 1_234_567;
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

    #[test]
    fn pull_head_reports_hashes() {
        let mut ctx = fresh_context();
        ctx.vault_image.extend_from_slice(b"encrypted");
        ctx.recipients_manifest
            .extend_from_slice(b"{\"recipients\":[\"device\"]}");
        ctx.signature
            .extend_from_slice(&[0x99; SIGNATURE_BUFFER_CAPACITY]);
        ctx.vault_generation = 2;

        let request = HostRequest::PullHead(PullHeadRequest {
            protocol_version: PROTOCOL_VERSION,
        });
        let encoded = encode_host_request(&request).unwrap();
        let (command, response_bytes) =
            process_host_frame(CdcCommand::PullHead, &encoded, &mut ctx).unwrap();
        assert_eq!(command, CdcCommand::PullHead);
        let response = decode_device_response(&response_bytes).unwrap();

        match response {
            DeviceResponse::Head(head) => {
                assert_eq!(head.vault_generation, ctx.vault_generation);
                assert_ne!(head.vault_hash, [0u8; 32]);
                assert_ne!(head.signature_hash, [0u8; 32]);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn load_from_flash_populates_context() {
        type Flash = MockFlashBase<16, 4, 1_048_576>;
        let mut flash = Flash::new(WriteCountCheck::Twice, None, false);
        let range = Flash::FULL_FLASH_RANGE;
        let mut cache = NoCache::new();
        let mut buffer = vec![0u8; STORAGE_DATA_BUFFER_CAPACITY];

        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let pin = b"123456";
        let mut crypto = CryptoMaterial::default();
        crypto.wrap_new_keys(pin, &mut rng).unwrap();
        let key_record = crypto.record().expect("key record");
        let encoded_record = postcard_to_allocvec(&key_record).unwrap();

        crate::storage::block_on(async {
            map::store_item(
                &mut flash,
                range.clone(),
                &mut cache,
                buffer.as_mut_slice(),
                &STORAGE_KEY_VAULT,
                &Vec::from(&b"vault-image"[..]),
            )
            .await
            .unwrap();

            map::store_item(
                &mut flash,
                range.clone(),
                &mut cache,
                buffer.as_mut_slice(),
                &STORAGE_KEY_RECIPIENTS,
                &Vec::from(&b"recipients"[..]),
            )
            .await
            .unwrap();

            map::store_item(
                &mut flash,
                range.clone(),
                &mut cache,
                buffer.as_mut_slice(),
                &STORAGE_KEY_SIGNATURE,
                &Vec::from(&[0xAB; SIGNATURE_BUFFER_CAPACITY]),
            )
            .await
            .unwrap();

            let journal_bytes = encode_journal_operations(&[JournalOperation::Add {
                entry_id: String::from("flash-entry"),
            }])
            .unwrap();

            map::store_item(
                &mut flash,
                range.clone(),
                &mut cache,
                buffer.as_mut_slice(),
                &STORAGE_KEY_JOURNAL,
                &journal_bytes,
            )
            .await
            .unwrap();

            map::store_item(
                &mut flash,
                range.clone(),
                &mut cache,
                buffer.as_mut_slice(),
                &STORAGE_KEY_GENERATION,
                &7u64,
            )
            .await
            .unwrap();

            map::store_item(
                &mut flash,
                range.clone(),
                &mut cache,
                buffer.as_mut_slice(),
                &STORAGE_KEY_VAULT_KEYS,
                &encoded_record,
            )
            .await
            .unwrap();
        });

        let mut ctx = fresh_context();
        crate::storage::block_on(ctx.load_from_flash(&mut flash, range)).unwrap();

        assert_eq!(ctx.vault_image.as_slice(), b"vault-image");
        assert_eq!(ctx.recipients_manifest.as_slice(), b"recipients");
        assert_eq!(ctx.signature.as_slice(), &[0xAB; SIGNATURE_BUFFER_CAPACITY]);
        assert_eq!(ctx.vault_generation, 7);
        assert_eq!(ctx.journal_ops.len(), 1);

        ctx.crypto.unlock_vault_key(pin).unwrap();
        let payload = b"record-data".to_vec();
        let mut session_rng = ChaCha20Rng::from_seed([0x55; 32]);
        let (nonce, ciphertext) = ctx
            .crypto
            .encrypt_record(&mut session_rng, &payload)
            .unwrap();
        let roundtrip = ctx.crypto.decrypt_record(&nonce, &ciphertext).unwrap();
        assert_eq!(roundtrip, payload);
    }

    #[test]
    fn initial_context_loaded_before_request_handling() {
        type Flash = MockFlashBase<16, 4, 1024>;
        let mut flash = Flash::new(WriteCountCheck::Twice, None, false);
        let range = Flash::FULL_FLASH_RANGE;
        let mut cache = NoCache::new();
        let mut buffer = vec![0u8; STORAGE_DATA_BUFFER_CAPACITY];

        crate::storage::block_on(async {
            map::store_item(
                &mut flash,
                range.clone(),
                &mut cache,
                buffer.as_mut_slice(),
                &STORAGE_KEY_GENERATION,
                &42u64,
            )
            .await
            .unwrap();

            map::store_item(
                &mut flash,
                range.clone(),
                &mut cache,
                buffer.as_mut_slice(),
                &STORAGE_KEY_VAULT,
                &Vec::from(&b"flash-vault"[..]),
            )
            .await
            .unwrap();
        });

        let mut ctx = crate::storage::block_on(crate::storage::initialize_context_from_flash(
            &mut flash, range,
        ))
        .expect("context from flash");

        let request = HostRequest::PullHead(PullHeadRequest {
            protocol_version: PROTOCOL_VERSION,
        });
        let encoded = encode_host_request(&request).unwrap();
        let (command, response_bytes) =
            process_host_frame(CdcCommand::PullHead, &encoded, &mut ctx).unwrap();
        assert_eq!(command, CdcCommand::PullHead);

        let response = decode_device_response(&response_bytes).unwrap();
        match response {
            DeviceResponse::Head(head) => {
                assert_eq!(head.vault_generation, 42);
                assert!(!ctx.vault_image.is_empty());
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn initialize_context_from_flash_propagates_errors() {
        type Flash = MockFlashBase<16, 4, 1024>;
        let mut flash = Flash::new(WriteCountCheck::Twice, None, false);
        let range = Flash::FULL_FLASH_RANGE;
        let mut cache = NoCache::new();
        let mut buffer = vec![0u8; STORAGE_DATA_BUFFER_CAPACITY];

        crate::storage::block_on(async {
            map::store_item(
                &mut flash,
                range.clone(),
                &mut cache,
                buffer.as_mut_slice(),
                &STORAGE_KEY_VAULT_KEYS,
                &[0x01],
            )
            .await
            .unwrap();
        });

        let error = crate::storage::block_on(crate::storage::initialize_context_from_flash(
            &mut flash,
            range.clone(),
        ))
        .expect_err("corrupted key record should fail");

        match error {
            StorageError::Decode(message) => {
                assert!(message.contains("failed to decode key record"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn load_from_flash_rejects_oversized_vault_image() {
        let oversized_vault = vec![0xAA; VAULT_BUFFER_CAPACITY + 1];
        let error = SyncContext::validate_flash_blob::<()>(
            oversized_vault,
            VAULT_BUFFER_CAPACITY,
            "vault image",
        )
        .expect_err("oversized vault should be rejected");

        match error {
            StorageError::Decode(message) => {
                assert!(message.contains("vault image exceeds capacity"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn load_from_flash_rejects_oversized_recipients_manifest() {
        let oversized_recipients = vec![0xBB; RECIPIENTS_BUFFER_CAPACITY + 1];
        let error = SyncContext::validate_flash_blob::<()>(
            oversized_recipients,
            RECIPIENTS_BUFFER_CAPACITY,
            "recipients manifest",
        )
        .expect_err("oversized recipients should be rejected");

        match error {
            StorageError::Decode(message) => {
                assert!(message.contains("recipients manifest exceeds capacity"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn load_from_flash_rejects_oversized_signature() {
        let oversized_signature = vec![0xCC; SIGNATURE_BUFFER_CAPACITY + 1];
        let error = SyncContext::validate_signature_blob::<()>(oversized_signature)
            .expect_err("oversized signature should be rejected");

        match error {
            StorageError::Decode(message) => {
                assert!(message.contains("signature exceeds capacity"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn load_from_flash_rejects_partial_signature() {
        let partial_signature = vec![0xDD; SIGNATURE_BUFFER_CAPACITY - 1];
        let error = SyncContext::validate_signature_blob::<()>(partial_signature)
            .expect_err("incomplete signature should be rejected");

        match error {
            StorageError::Decode(message) => {
                assert!(message.contains("signature must be exactly"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn wrap_new_keys_and_wipe_clears_sensitive_state() {
        let mut ctx = fresh_context();
        ctx.vault_image.extend_from_slice(b"data");
        ctx.recipients_manifest.extend_from_slice(b"recips");
        ctx.signature
            .extend_from_slice(&[0xEE; SIGNATURE_BUFFER_CAPACITY]);

        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        ctx.crypto.wrap_new_keys(b"222222", &mut rng).unwrap();
        ctx.crypto.unlock_vault_key(b"222222").unwrap();

        assert!(ctx.crypto.vault_key().is_ok());
        assert!(ctx.crypto.device_private_key().is_ok());
        assert!(ctx.crypto.device_public_key().is_some());

        ctx.wipe_sensitive();

        assert!(ctx.crypto.vault_key().is_err());
        assert!(ctx.crypto.device_private_key().is_err());
        assert!(ctx.vault_image.is_empty());
        assert!(ctx.recipients_manifest.is_empty());
        assert!(ctx.signature.is_empty());
    }

    #[test]
    fn unlock_with_wrong_pin_is_rejected() {
        let mut ctx = fresh_context();
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        ctx.crypto.wrap_new_keys(b"123456", &mut rng).unwrap();
        ctx.crypto.wipe();

        let error = ctx
            .crypto
            .unlock_vault_key(b"654321")
            .expect_err("wrong PIN should not decrypt");
        assert_eq!(error, KeyError::CryptoFailure);
        assert!(ctx.crypto.vault_key().is_err());
    }

    #[test]
    fn device_key_is_unlocked_with_correct_pin() {
        let mut ctx = fresh_context();
        let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
        ctx.crypto.wrap_new_keys(b"333333", &mut rng).unwrap();
        let public = ctx
            .crypto
            .device_public_key()
            .expect("public key available");
        assert_ne!(public, [0u8; 32]);
        ctx.crypto.wipe();

        ctx.unlock_with_pin(b"333333", 0).expect("unlock succeeds");
        let private = ctx.crypto.device_private_key().expect("private key");
        assert_ne!(private.as_ref(), &[0u8; 32]);
    }

    #[test]
    fn pin_failures_apply_backoff_and_wipe() {
        let mut ctx = fresh_context();
        let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
        ctx.crypto.wrap_new_keys(b"444444", &mut rng).unwrap();
        ctx.crypto.wipe();

        let mut now = 0u64;
        let wrong_pin = b"000000";
        loop {
            match ctx.unlock_with_pin(wrong_pin, now) {
                Err(PinUnlockError::Key(KeyError::CryptoFailure)) => {
                    now = now.saturating_add(500);
                }
                Err(PinUnlockError::Backoff { remaining_ms }) => {
                    now = now.saturating_add(remaining_ms + 1);
                }
                Err(PinUnlockError::WipeRequired) => {
                    break;
                }
                other => panic!("unexpected unlock result: {other:?}"),
            }
        }

        let mut status = ctx.pin_lock_status(now);
        if let Some(remaining) = status.backoff_remaining_ms {
            status = ctx.pin_lock_status(now.saturating_add(remaining + 1));
        }
        assert!(status.total_failures >= crate::crypto::PIN_WIPE_THRESHOLD);
        assert!(status.wipe_required);
        assert!(status.backoff_remaining_ms.is_none());
    }

    #[test]
    fn wipe_lockout_blocks_subsequent_successful_pin() {
        let mut ctx = fresh_context();
        let mut rng = ChaCha20Rng::from_seed([15u8; 32]);
        ctx.crypto.wrap_new_keys(b"666666", &mut rng).unwrap();
        ctx.crypto.wipe();

        let mut now = 0u64;
        let wrong_pin = b"000000";

        loop {
            match ctx.unlock_with_pin(wrong_pin, now) {
                Err(PinUnlockError::Key(KeyError::CryptoFailure)) => now += 250,
                Err(PinUnlockError::Backoff { remaining_ms }) => now += remaining_ms + 1,
                Err(PinUnlockError::WipeRequired) => break,
                other => panic!("unexpected unlock result: {other:?}"),
            }
        }

        let error = ctx
            .unlock_with_pin(b"666666", now)
            .expect_err("wipe lockout should reject correct PIN");
        assert_eq!(error, PinUnlockError::WipeRequired);
        assert!(ctx.crypto.vault_key().is_err());
    }

    #[test]
    fn successful_pin_resets_backoff() {
        let mut ctx = fresh_context();
        let mut rng = ChaCha20Rng::from_seed([14u8; 32]);
        ctx.crypto.wrap_new_keys(b"555555", &mut rng).unwrap();
        ctx.crypto.wipe();

        let wrong_pin = b"000000";
        let mut now = 0u64;

        loop {
            match ctx.unlock_with_pin(wrong_pin, now) {
                Err(PinUnlockError::Key(KeyError::CryptoFailure)) => now += 1_000,
                Err(PinUnlockError::Backoff { remaining_ms }) => {
                    now += remaining_ms + 1;
                    break;
                }
                other => panic!("unexpected result: {other:?}"),
            }
        }

        ctx.unlock_with_pin(b"555555", now).expect("pin accepted");
        let status = ctx.pin_lock_status(now);
        assert_eq!(status.consecutive_failures, 0);
        assert!(status.backoff_remaining_ms.is_none());
    }
}
