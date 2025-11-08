#![cfg_attr(not(test), no_std)]
#![cfg_attr(all(not(test), target_arch = "xtensa"), no_main)]

extern crate alloc;

use alloc::{format, string::String, string::ToString, vec, vec::Vec};
use core::{cmp, ops::Range};

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use embedded_storage_async::nor_flash::NorFlash;
use postcard::{from_bytes as postcard_from_bytes, to_allocvec as postcard_to_allocvec};
use rand_core::{CryptoRng, RngCore};
use scrypt::{
    Params as ScryptParams,
    errors::{InvalidOutputLen, InvalidParams},
};
use sequential_storage::{Error as FlashStorageError, cache::NoCache, map};
use serde::{Deserialize, Serialize};

#[cfg(any(test, target_arch = "xtensa"))]
mod actions {
    use super::*;
    use embassy_sync::blocking_mutex::raw::{NoopRawMutex, ThreadModeRawMutex};
    use embassy_sync::channel::{Channel, Receiver, Sender};

    #[cfg(target_arch = "xtensa")]
    type QueueMutex = ThreadModeRawMutex;
    #[cfg(not(target_arch = "xtensa"))]
    type QueueMutex = NoopRawMutex;

    const ACTION_QUEUE_DEPTH: usize = 8;

    static ACTION_CHANNEL: Channel<QueueMutex, DeviceAction, ACTION_QUEUE_DEPTH> = Channel::new();

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DeviceAction {
        StartSession { session_id: u32 },
        EndSession,
    }

    pub type ActionSender = Sender<'static, QueueMutex, DeviceAction, ACTION_QUEUE_DEPTH>;
    pub type ActionReceiver = Receiver<'static, QueueMutex, DeviceAction, ACTION_QUEUE_DEPTH>;

    pub fn action_sender() -> ActionSender {
        ACTION_CHANNEL.sender()
    }

    pub fn action_receiver() -> ActionReceiver {
        ACTION_CHANNEL.receiver()
    }

    pub fn publish(action: DeviceAction) {
        let sender = action_sender();
        let _ = sender.try_send(action);
    }

    #[cfg(test)]
    pub fn clear() {
        action_sender().clear();
        // Drain any pending receivers to ensure deterministic tests.
        let receiver = action_receiver();
        while receiver.try_receive().is_ok() {}
    }

    #[cfg(test)]
    pub fn drain() -> Vec<DeviceAction> {
        let receiver = action_receiver();
        let mut collected = Vec::new();
        while let Ok(action) = receiver.try_receive() {
            collected.push(action);
        }
        collected
    }
}

#[cfg(any(test, target_arch = "xtensa"))]
use actions::DeviceAction;

#[cfg(target_arch = "xtensa")]
use shared::cdc::FRAME_HEADER_SIZE;
use shared::cdc::{CdcCommand, FrameHeader, compute_crc32};
use shared::schema::{
    AckRequest, AckResponse, DeviceErrorCode, DeviceResponse, GetTimeRequest, HelloRequest,
    HelloResponse, HostRequest, JournalFrame, JournalOperation, NackResponse, PROTOCOL_VERSION,
    PullHeadRequest, PullHeadResponse, PullVaultRequest, PushOperationsFrame, SetTimeRequest,
    StatusRequest, StatusResponse, TimeResponse, VaultArtifact, VaultChunk, decode_device_response,
    decode_host_request, decode_journal_operations, encode_device_response, encode_host_request,
    encode_journal_operations,
};
use zeroize::Zeroizing;

/// Maximum payload size (in bytes) that a single postcard frame is allowed to occupy on the wire.
pub const FRAME_MAX_SIZE: usize = 4096;

/// Capacity provisioned for the encrypted vault image buffer.
const VAULT_BUFFER_CAPACITY: usize = 64 * 1024;
/// Capacity provisioned for the recipients manifest buffer.
const RECIPIENTS_BUFFER_CAPACITY: usize = 4 * 1024;
/// Scratch buffer used when interacting with sequential storage.
const STORAGE_DATA_BUFFER_CAPACITY: usize = VAULT_BUFFER_CAPACITY + 64;

const STORAGE_KEY_VAULT: u8 = 0x01;
const STORAGE_KEY_RECIPIENTS: u8 = 0x02;
const STORAGE_KEY_JOURNAL: u8 = 0x03;
const STORAGE_KEY_GENERATION: u8 = 0x04;
const STORAGE_KEY_VAULT_KEYS: u8 = 0x05;

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

#[derive(Debug)]
pub enum StorageError<E> {
    Flash(FlashStorageError<E>),
    Decode(String),
    Key(KeyError),
}

impl<E> From<FlashStorageError<E>> for StorageError<E> {
    fn from(error: FlashStorageError<E>) -> Self {
        StorageError::Flash(error)
    }
}

impl<E> From<KeyError> for StorageError<E> {
    fn from(error: KeyError) -> Self {
        StorageError::Key(error)
    }
}

impl<E> core::fmt::Display for StorageError<E>
where
    FlashStorageError<E>: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StorageError::Flash(err) => write!(f, "flash error: {err}"),
            StorageError::Decode(err) => write!(f, "decode error: {err}"),
            StorageError::Key(err) => write!(f, "key error: {err}"),
        }
    }
}

impl<E> core::error::Error for StorageError<E>
where
    FlashStorageError<E>: core::fmt::Debug + core::fmt::Display,
    E: core::fmt::Debug,
{
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    InvalidParameters,
    InvalidOutput,
    KekUnavailable,
    VaultKeyUnavailable,
    VaultKeyLength,
    CryptoFailure,
}

impl From<InvalidParams> for KeyError {
    fn from(_: InvalidParams) -> Self {
        KeyError::InvalidParameters
    }
}

impl From<InvalidOutputLen> for KeyError {
    fn from(_: InvalidOutputLen) -> Self {
        KeyError::InvalidOutput
    }
}

impl From<chacha20poly1305::aead::Error> for KeyError {
    fn from(_: chacha20poly1305::aead::Error) -> Self {
        KeyError::CryptoFailure
    }
}

impl core::fmt::Display for KeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let label = match self {
            KeyError::InvalidParameters => "invalid scrypt parameters",
            KeyError::InvalidOutput => "invalid scrypt output length",
            KeyError::KekUnavailable => "missing KEK",
            KeyError::VaultKeyUnavailable => "vault key unavailable",
            KeyError::VaultKeyLength => "unexpected vault key length",
            KeyError::CryptoFailure => "encryption failure",
        };
        write!(f, "{label}")
    }
}

impl core::error::Error for KeyError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ScryptParamsRecord {
    log_n: u8,
    r: u32,
    p: u32,
}

impl ScryptParamsRecord {
    fn to_params(&self) -> Result<ScryptParams, KeyError> {
        ScryptParams::new(self.log_n, self.r, self.p).map_err(Into::into)
    }
}

impl From<ScryptParams> for ScryptParamsRecord {
    fn from(params: ScryptParams) -> Self {
        Self {
            log_n: params.log_n(),
            r: params.r(),
            p: params.p(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct KeyRecord {
    salt: [u8; 16],
    nonce: [u8; 12],
    wrapped_key: Vec<u8>,
    scrypt: ScryptParamsRecord,
}

/// Placeholder for future cryptographic material associated with a sync session.
pub struct CryptoMaterial {
    kek: Option<Zeroizing<[u8; 32]>>,
    vault_key: Option<Zeroizing<[u8; 32]>>,
    pin_salt: [u8; 16],
    kek_nonce: [u8; 12],
    wrapped_vault_key: Zeroizing<Vec<u8>>,
    scrypt_params: ScryptParams,
}

impl Default for CryptoMaterial {
    fn default() -> Self {
        Self {
            kek: None,
            vault_key: None,
            pin_salt: [0u8; 16],
            kek_nonce: [0u8; 12],
            wrapped_vault_key: Zeroizing::new(Vec::new()),
            scrypt_params: ScryptParams::recommended(),
        }
    }
}

impl CryptoMaterial {
    fn derive_kek(&mut self, pin: &[u8]) -> Result<(), KeyError> {
        let mut derived = Zeroizing::new([0u8; 32]);
        scrypt::scrypt(pin, &self.pin_salt, &self.scrypt_params, derived.as_mut())
            .map_err(KeyError::from)?;
        self.kek = Some(derived);
        Ok(())
    }

    fn cipher_from_kek(&self) -> Result<ChaCha20Poly1305, KeyError> {
        let kek = self.kek.as_ref().ok_or(KeyError::KekUnavailable)?;
        ChaCha20Poly1305::new_from_slice(kek.as_ref()).map_err(|_| KeyError::CryptoFailure)
    }

    fn ensure_vault_key(&self) -> Result<&Zeroizing<[u8; 32]>, KeyError> {
        self.vault_key.as_ref().ok_or(KeyError::VaultKeyUnavailable)
    }

    pub(crate) fn configure_from_record(&mut self, record: &KeyRecord) -> Result<(), KeyError> {
        self.pin_salt = record.salt;
        self.kek_nonce = record.nonce;
        self.wrapped_vault_key = Zeroizing::new(record.wrapped_key.clone());
        self.scrypt_params = record.scrypt.to_params()?;
        self.kek = None;
        self.vault_key = None;
        Ok(())
    }

    pub(crate) fn record(&self) -> Option<KeyRecord> {
        if self.wrapped_vault_key.is_empty() {
            None
        } else {
            Some(KeyRecord {
                salt: self.pin_salt,
                nonce: self.kek_nonce,
                wrapped_key: (*self.wrapped_vault_key).clone(),
                scrypt: self.scrypt_params.into(),
            })
        }
    }

    pub fn wrap_new_keys<R: RngCore + CryptoRng>(
        &mut self,
        pin: &[u8],
        rng: &mut R,
    ) -> Result<(), KeyError> {
        rng.fill_bytes(&mut self.pin_salt);
        rng.fill_bytes(&mut self.kek_nonce);

        self.scrypt_params =
            ScryptParams::new(14, ScryptParams::RECOMMENDED_R, ScryptParams::RECOMMENDED_P)?;

        let mut fresh_vault_key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(fresh_vault_key.as_mut());

        self.derive_kek(pin)?;
        let cipher = self.cipher_from_kek()?;
        let nonce = Nonce::from(self.kek_nonce);
        let ciphertext = cipher.encrypt(&nonce, fresh_vault_key.as_ref())?;
        self.wrapped_vault_key = Zeroizing::new(ciphertext);
        self.vault_key = Some(fresh_vault_key);
        Ok(())
    }

    pub fn unlock_vault_key(&mut self, pin: &[u8]) -> Result<(), KeyError> {
        if self.wrapped_vault_key.is_empty() {
            return Err(KeyError::VaultKeyUnavailable);
        }

        self.derive_kek(pin)?;
        let cipher = self.cipher_from_kek()?;
        let nonce = Nonce::from(self.kek_nonce);
        let plaintext = Zeroizing::new(cipher.decrypt(&nonce, self.wrapped_vault_key.as_slice())?);

        if plaintext.len() != 32 {
            return Err(KeyError::VaultKeyLength);
        }

        let mut vault_key = Zeroizing::new([0u8; 32]);
        vault_key.copy_from_slice(&plaintext[..32]);
        self.vault_key = Some(vault_key);
        Ok(())
    }

    pub fn encrypt_record(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, KeyError> {
        let vault_key = self.ensure_vault_key()?;
        let cipher = ChaCha20Poly1305::new_from_slice(vault_key.as_ref())
            .map_err(|_| KeyError::CryptoFailure)?;
        let nonce = Nonce::from(*nonce);
        cipher.encrypt(&nonce, plaintext).map_err(KeyError::from)
    }

    pub fn decrypt_record(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, KeyError> {
        let vault_key = self.ensure_vault_key()?;
        let cipher = ChaCha20Poly1305::new_from_slice(vault_key.as_ref())
            .map_err(|_| KeyError::CryptoFailure)?;
        let nonce = Nonce::from(*nonce);
        cipher.decrypt(&nonce, ciphertext).map_err(KeyError::from)
    }

    /// Clear any secrets that might still be resident in memory.
    pub fn wipe(&mut self) {
        if let Some(kek) = self.kek.take() {
            drop(kek);
        }
        if let Some(vault_key) = self.vault_key.take() {
            drop(vault_key);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferStage {
    Vault,
    Recipients,
    Complete,
}

/// Runtime state required to service synchronization requests from the host.
pub struct SyncContext {
    journal_ops: Vec<JournalOperation>,
    pending_sequence: Option<(u32, u32)>,
    next_sequence: u32,
    vault_image: Zeroizing<Vec<u8>>,
    vault_offset: usize,
    recipients_offset: usize,
    recipients_manifest: Zeroizing<Vec<u8>>,
    transfer_stage: TransferStage,
    last_artifact: VaultArtifact,
    crypto: CryptoMaterial,
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
            pending_sequence: None,
            next_sequence: 1,
            vault_image: Zeroizing::new(Vec::with_capacity(VAULT_BUFFER_CAPACITY)),
            vault_offset: 0,
            recipients_offset: 0,
            recipients_manifest: Zeroizing::new(Vec::with_capacity(RECIPIENTS_BUFFER_CAPACITY)),
            transfer_stage: TransferStage::Vault,
            last_artifact: VaultArtifact::Vault,
            crypto: CryptoMaterial::default(),
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
            match Self::validate_flash_blob::<S::Error>(
                recipients,
                RECIPIENTS_BUFFER_CAPACITY,
                "recipients manifest",
            ) {
                Ok(blob) => {
                    self.recipients_manifest = blob;
                }
                Err(err) => {
                    self.vault_image = Zeroizing::new(Vec::new());
                    self.vault_offset = 0;
                    return Err(err);
                }
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
        self.pending_sequence = None;
        self.next_sequence = 1;

        Ok(())
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

    /// Register a journal operation that should be emitted on the next pull.
    pub fn record_operation(&mut self, operation: JournalOperation) {
        self.journal_ops.push(operation);
    }

    /// Reset sensitive buffers once a session finishes.
    pub fn wipe_sensitive(&mut self) {
        self.vault_image.iter_mut().for_each(|byte| *byte = 0);
        self.vault_image.clear();

        self.recipients_manifest
            .iter_mut()
            .for_each(|byte| *byte = 0);
        self.recipients_manifest.clear();

        self.crypto.wipe();
        self.reset_transfer_state();
        self.pending_sequence = None;
    }

    fn compute_journal_checksum(&self, operations: &[JournalOperation]) -> u32 {
        operations
            .iter()
            .fold(0xA5A5_5A5Au32, |acc, operation| match operation {
                JournalOperation::Add { entry_id } => accumulate_checksum(acc, entry_id.as_bytes()),
                JournalOperation::UpdateField {
                    entry_id,
                    field,
                    value_checksum,
                } => {
                    accumulate_checksum(
                        accumulate_checksum(acc, entry_id.as_bytes()),
                        field.as_bytes(),
                    ) ^ value_checksum
                }
                JournalOperation::Delete { entry_id } => {
                    accumulate_checksum(acc, entry_id.as_bytes()) ^ 0xFFFF_FFFF
                }
            })
    }

    fn reset_transfer_state(&mut self) {
        self.vault_offset = 0;
        self.recipients_offset = 0;
        self.transfer_stage = if self.vault_image.is_empty() {
            if self.recipients_manifest.is_empty() {
                TransferStage::Complete
            } else {
                TransferStage::Recipients
            }
        } else {
            TransferStage::Vault
        };
        self.last_artifact = match self.transfer_stage {
            TransferStage::Recipients => VaultArtifact::Recipients,
            _ => VaultArtifact::Vault,
        };
    }

    fn next_transfer_chunk(
        &mut self,
        max_chunk: usize,
        host_buffer_size: usize,
    ) -> Result<VaultChunk, ProtocolError> {
        let artifact = match self.transfer_stage {
            TransferStage::Vault => VaultArtifact::Vault,
            TransferStage::Recipients => VaultArtifact::Recipients,
            TransferStage::Complete => self.last_artifact,
        };

        let (buffer, offset) = match artifact {
            VaultArtifact::Vault => (self.vault_image.as_slice(), &mut self.vault_offset),
            VaultArtifact::Recipients => (
                self.recipients_manifest.as_slice(),
                &mut self.recipients_offset,
            ),
        };

        let available = buffer.len().saturating_sub(*offset);
        let frame_budget = cmp::min(host_buffer_size, FRAME_MAX_SIZE);
        let max_payload = cmp::min(max_chunk, frame_budget);
        let mut chunk_size = cmp::min(max_payload, available);
        let device_chunk_size = cmp::max(1, max_payload) as u32;

        loop {
            let slice_end = *offset + chunk_size;
            let payload = if chunk_size == 0 {
                Vec::new()
            } else {
                buffer[*offset..slice_end].to_vec()
            };

            let remaining = buffer.len().saturating_sub(slice_end) as u64;
            let checksum = accumulate_checksum(0, &payload);

            let chunk = VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: self.next_sequence,
                total_size: buffer.len() as u64,
                remaining_bytes: remaining,
                device_chunk_size,
                data: payload,
                checksum,
                is_last: remaining == 0,
                artifact,
            };

            let encoded_len =
                match encode_device_response(&DeviceResponse::VaultChunk(chunk.clone())) {
                    Ok(bytes) => bytes.len(),
                    Err(_) => return Ok(chunk),
                };

            if encoded_len <= frame_budget {
                if chunk_size == 0 && available > 0 {
                    return Err(ProtocolError::HostBufferTooSmall {
                        required: encoded_len,
                        provided: host_buffer_size,
                    });
                }

                *offset = slice_end;
                self.last_artifact = artifact;

                if chunk.is_last {
                    match artifact {
                        VaultArtifact::Vault => {
                            if self.recipients_manifest.is_empty() {
                                self.transfer_stage = TransferStage::Complete;
                            } else {
                                self.transfer_stage = TransferStage::Recipients;
                                self.recipients_offset = 0;
                            }
                        }
                        VaultArtifact::Recipients => {
                            self.transfer_stage = TransferStage::Complete;
                        }
                    }
                } else {
                    self.transfer_stage = match artifact {
                        VaultArtifact::Vault => TransferStage::Vault,
                        VaultArtifact::Recipients => TransferStage::Recipients,
                    };
                }

                return Ok(chunk);
            }

            if chunk_size == 0 {
                if available > 0 || frame_budget < encoded_len {
                    return Err(ProtocolError::HostBufferTooSmall {
                        required: encoded_len,
                        provided: host_buffer_size,
                    });
                }

                return Ok(chunk);
            }

            let overhead = encoded_len.saturating_sub(chunk.data.len());
            if overhead >= frame_budget {
                chunk_size = 0;
                continue;
            }

            let target_size = frame_budget - overhead;
            let max_allowed = cmp::min(max_payload, available);
            let new_size = cmp::min(target_size, max_allowed);

            if new_size >= chunk_size {
                chunk_size = chunk_size.saturating_sub(1);
            } else {
                chunk_size = new_size;
            }
        }
    }
}

fn accumulate_checksum(mut seed: u32, payload: &[u8]) -> u32 {
    for byte in payload {
        seed = seed.wrapping_mul(16777619) ^ (*byte as u32);
    }
    seed
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

fn encode_response(response: &DeviceResponse) -> Result<Vec<u8>, ProtocolError> {
    encode_device_response(response).map_err(|err| ProtocolError::Encode(err.to_string()))
}

fn command_for_request(request: &HostRequest) -> CdcCommand {
    match request {
        HostRequest::Hello(_) => CdcCommand::Hello,
        HostRequest::Status(_) => CdcCommand::Status,
        HostRequest::SetTime(_) => CdcCommand::SetTime,
        HostRequest::GetTime(_) => CdcCommand::GetTime,
        HostRequest::PullHead(_) => CdcCommand::PullHead,
        HostRequest::PullVault(_) => CdcCommand::PullVault,
        HostRequest::PushOps(_) => CdcCommand::PushOps,
        HostRequest::Ack(_) => CdcCommand::Ack,
    }
}

fn command_for_response(response: &DeviceResponse) -> CdcCommand {
    match response {
        DeviceResponse::Hello(_) => CdcCommand::Hello,
        DeviceResponse::Status(_) => CdcCommand::Status,
        DeviceResponse::Time(_) => CdcCommand::GetTime,
        DeviceResponse::Head(_) => CdcCommand::PullHead,
        DeviceResponse::JournalFrame(_) => CdcCommand::PushOps,
        DeviceResponse::VaultChunk(_) => CdcCommand::PullVault,
        DeviceResponse::Ack(_) => CdcCommand::Ack,
        DeviceResponse::Nack(_) => CdcCommand::Nack,
    }
}

#[cfg_attr(not(target_arch = "xtensa"), allow(dead_code))]
fn validate_checksum(header: &FrameHeader, payload: &[u8]) -> Result<(), ProtocolError> {
    let checksum = compute_crc32(payload);
    if checksum == header.checksum {
        Ok(())
    } else {
        Err(ProtocolError::ChecksumMismatch)
    }
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
    ctx.pending_sequence = None;
    ctx.next_sequence = 1;
    ctx.reset_transfer_state();

    #[cfg(any(test, target_arch = "xtensa"))]
    crate::actions::publish(DeviceAction::StartSession {
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

    Ok(DeviceResponse::Head(PullHeadResponse {
        protocol_version: PROTOCOL_VERSION,
        vault_generation: ctx.vault_generation,
        vault_hash,
        recipients_hash,
    }))
}

fn handle_pull(
    request: &PullVaultRequest,
    ctx: &mut SyncContext,
) -> Result<DeviceResponse, ProtocolError> {
    if request.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocol(request.protocol_version));
    }

    if !ctx.journal_ops.is_empty() {
        let operations = core::mem::take(&mut ctx.journal_ops);
        let checksum = ctx.compute_journal_checksum(&operations);
        let sequence = ctx.next_sequence;
        ctx.next_sequence = ctx.next_sequence.wrapping_add(1);
        ctx.pending_sequence = Some((sequence, checksum));

        Ok(DeviceResponse::JournalFrame(JournalFrame {
            protocol_version: PROTOCOL_VERSION,
            sequence,
            remaining_operations: 0,
            operations,
            checksum,
        }))
    } else {
        let chunk = ctx.next_transfer_chunk(
            request.max_chunk_size as usize,
            request.host_buffer_size as usize,
        )?;
        let checksum = chunk.checksum;
        let sequence = chunk.sequence;
        ctx.pending_sequence = Some((sequence, checksum));
        ctx.next_sequence = ctx.next_sequence.wrapping_add(1);

        Ok(DeviceResponse::VaultChunk(chunk))
    }
}

fn handle_push_ops(
    push: &PushOperationsFrame,
    ctx: &mut SyncContext,
) -> Result<DeviceResponse, ProtocolError> {
    if push.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocol(push.protocol_version));
    }

    let calculated = ctx.compute_journal_checksum(&push.operations);
    if calculated != push.checksum {
        return Err(ProtocolError::ChecksumMismatch);
    }

    if push.is_last {
        ctx.vault_generation = ctx.vault_generation.saturating_add(1);
        ctx.pending_sequence = None;
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

    match ctx.pending_sequence {
        Some((sequence, checksum))
            if ack.last_frame_sequence == sequence && ack.journal_checksum == checksum =>
        {
            ctx.pending_sequence = None;
            ctx.wipe_sensitive();

            #[cfg(any(test, target_arch = "xtensa"))]
            crate::actions::publish(DeviceAction::EndSession);

            Ok(DeviceResponse::Ack(AckResponse {
                protocol_version: PROTOCOL_VERSION,
                message: format!(
                    "acknowledged journal frame #{sequence} (checksum 0x{checksum:08X})"
                ),
            }))
        }
        _ => Err(ProtocolError::InvalidAcknowledgement),
    }
}

#[cfg(target_arch = "xtensa")]
mod runtime {
    use super::*;
    use embassy_executor::Executor;
    use esp_alloc::EspHeap;
    use esp_hal::{
        Blocking, Config, clock::CpuClock, timer::timg::TimerGroup, usb_serial_jtag::UsbSerialJtag,
    };
    use static_cell::StaticCell;

    #[global_allocator]
    static ALLOCATOR: EspHeap = EspHeap::empty();

    fn init_allocator() {
        const HEAP_SIZE: usize = 96 * 1024;
        static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
        unsafe { ALLOCATOR.init(HEAP.as_ptr() as usize, HEAP.len()) };
    }

    static EXECUTOR: StaticCell<Executor> = StaticCell::new();

    #[esp_hal::entry]
    fn main() -> ! {
        init_allocator();

        let mut peripherals = esp_hal::init(Config::default().with_cpu_clock(CpuClock::max()));
        let mut timg0 = TimerGroup::new(peripherals.TIMG0);
        timg0.wdt.disable();

        let timer0 = timg0.timer0;
        esp_hal_embassy::init(timer0);

        let usb = UsbSerialJtag::new(peripherals.USB_DEVICE);

        let executor = EXECUTOR.init(Executor::new());
        executor.run(|spawner| {
            let mut ctx = SyncContext::new();
            let ble_actions = crate::actions::action_receiver();
            spawner
                .spawn(crate::tasks::ble_profile(ble_actions))
                .expect("spawn BLE task");
            spawner
                .spawn(crate::tasks::cdc_server(usb, ctx))
                .expect("spawn CDC task");
        });
    }
}

#[cfg(target_arch = "xtensa")]
mod tasks {
    use super::*;
    use embassy_executor::task;
    use embassy_time::{Duration, Timer};
    use esp_hal::{Blocking, usb_serial_jtag::UsbSerialJtag};
    use nb::Error as NbError;

    #[cfg(target_arch = "xtensa")]
    use trouble_host::types::capabilities::IoCapabilities;

    #[task]
    pub async fn cdc_server(mut serial: UsbSerialJtag<'static, Blocking>, mut ctx: SyncContext) {
        loop {
            match read_frame(&mut serial).await {
                Ok((command, frame)) => match process_host_frame(command, &frame, &mut ctx) {
                    Ok((response_command, response)) => {
                        let _ = write_frame(&mut serial, response_command, &response);
                    }
                    Err(err) => {
                        let payload = match encode_response(&DeviceResponse::Nack(err.as_nack())) {
                            Ok(encoded) => encoded,
                            Err(encode_err) => {
                                let fatal = encode_err.as_nack();
                                encode_device_response(&DeviceResponse::Nack(fatal))
                                    .unwrap_or_default()
                            }
                        };
                        let _ = write_frame(&mut serial, CdcCommand::Nack, &payload);
                    }
                },
                Err(err) => {
                    let payload = match encode_response(&DeviceResponse::Nack(err.as_nack())) {
                        Ok(encoded) => encoded,
                        Err(encode_err) => {
                            let fatal = encode_err.as_nack();
                            encode_device_response(&DeviceResponse::Nack(fatal)).unwrap_or_default()
                        }
                    };
                    let _ = write_frame(&mut serial, CdcCommand::Nack, &payload);
                }
            }
        }
    }

    async fn read_frame(
        serial: &mut UsbSerialJtag<'static, Blocking>,
    ) -> Result<(CdcCommand, Vec<u8>), ProtocolError> {
        let mut header_bytes = [0u8; FRAME_HEADER_SIZE];
        for byte in header_bytes.iter_mut() {
            *byte = read_byte(serial).await?;
        }

        let header = FrameHeader::from_bytes(header_bytes)
            .map_err(|err| ProtocolError::Decode(err.to_string()))?;

        if header.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedProtocol(header.version));
        }

        if header.length as usize > FRAME_MAX_SIZE {
            return Err(ProtocolError::FrameTooLarge(header.length as usize));
        }

        let mut buffer = Vec::with_capacity(header.length as usize);
        for _ in 0..header.length {
            buffer.push(read_byte(serial).await?);
        }

        validate_checksum(&header, &buffer)?;

        Ok((header.command, buffer))
    }

    async fn read_byte(serial: &mut UsbSerialJtag<'static, Blocking>) -> Result<u8, ProtocolError> {
        loop {
            match serial.read_byte() {
                Ok(byte) => return Ok(byte),
                Err(NbError::WouldBlock) => Timer::after(Duration::from_micros(250)).await,
                Err(NbError::Other(_)) => return Err(ProtocolError::Transport),
            }
        }
    }

    fn write_frame(
        serial: &mut UsbSerialJtag<'static, Blocking>,
        command: CdcCommand,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        if payload.len() > FRAME_MAX_SIZE {
            return Err(ProtocolError::FrameTooLarge(payload.len()));
        }

        let length = payload.len() as u32;
        let checksum = compute_crc32(payload);
        let header = FrameHeader::new(PROTOCOL_VERSION, command, length, checksum).to_bytes();

        serial
            .write(&header)
            .map_err(|_| ProtocolError::Transport)?;
        if !payload.is_empty() {
            serial
                .write(payload)
                .map_err(|_| ProtocolError::Transport)?;
        }
        serial.flush_tx().map_err(|_| ProtocolError::Transport)
    }

    #[task]
    pub async fn ble_profile(mut receiver: crate::actions::ActionReceiver) {
        let _capabilities = IoCapabilities::KeyboardDisplay;

        loop {
            let action = receiver.receive().await;
            match action {
                crate::actions::DeviceAction::StartSession { session_id } => {
                    let _ = session_id;
                }
                crate::actions::DeviceAction::EndSession => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use core::{
        future::Future,
        ptr,
        task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use sequential_storage::mock_flash::{MockFlashBase, WriteCountCheck};

    fn fresh_context() -> SyncContext {
        super::actions::clear();
        SyncContext::new()
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

            if let Some(last) = chunks.last() {
                if last.artifact == VaultArtifact::Recipients && last.is_last {
                    break;
                }
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

        let actions = super::actions::drain();
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

        super::actions::drain();

        let ack = HostRequest::Ack(AckRequest {
            protocol_version: PROTOCOL_VERSION,
            last_frame_sequence: sequence,
            journal_checksum: checksum,
        });
        let encoded_ack = encode_host_request(&ack).unwrap();
        let _ = process_host_frame(CdcCommand::Ack, &encoded_ack, &mut ctx).unwrap();

        let actions = super::actions::drain();
        assert_eq!(actions, vec![DeviceAction::EndSession]);
    }

    #[test]
    fn acknowledgement_keeps_vault_generation() {
        let mut ctx = fresh_context();
        ctx.vault_generation = 7;
        let expected_generation = ctx.vault_generation;
        let pending = (12, 0xABCD_1234);
        ctx.pending_sequence = Some(pending);

        let ack = AckRequest {
            protocol_version: PROTOCOL_VERSION,
            last_frame_sequence: pending.0,
            journal_checksum: pending.1,
        };

        let response = handle_ack(&ack, &mut ctx).expect("ack should succeed");

        match response {
            DeviceResponse::Ack(message) => {
                assert_eq!(message.protocol_version, PROTOCOL_VERSION);
                assert!(message.message.contains(&pending.0.to_string()));
            }
            other => panic!("unexpected response: {other:?}"),
        }

        assert!(ctx.pending_sequence.is_none());
        assert_eq!(ctx.vault_generation, expected_generation);
    }

    #[test]
    fn push_operations_are_acknowledged() {
        let mut ctx = fresh_context();
        let operations = vec![JournalOperation::Add {
            entry_id: String::from("pushed"),
        }];
        let checksum = ctx.compute_journal_checksum(&operations);

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
        super::actions::clear();
        let payload = b"payload".to_vec();
        let mut header = FrameHeader::new(
            PROTOCOL_VERSION,
            CdcCommand::PullVault,
            payload.len() as u32,
            compute_crc32(&payload),
        );

        // Good checksum passes validation.
        validate_checksum(&header, &payload).expect("valid checksum");

        header.checksum ^= 0xFFFF_FFFF;
        let error = validate_checksum(&header, &payload).expect_err("expected checksum error");
        assert_eq!(error, ProtocolError::ChecksumMismatch);
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

    unsafe fn noop_clone(_: *const ()) -> RawWaker {
        noop_raw_waker()
    }

    unsafe fn noop_wake(_: *const ()) {}
    unsafe fn noop_wake_by_ref(_: *const ()) {}
    unsafe fn noop_drop(_: *const ()) {}

    fn noop_raw_waker() -> RawWaker {
        RawWaker::new(
            ptr::null(),
            &RawWakerVTable::new(noop_clone, noop_wake, noop_wake_by_ref, noop_drop),
        )
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
        let mut future = Box::pin(future);
        let mut cx = Context::from_waker(&waker);

        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(output) => break output,
                Poll::Pending => {}
            }
        }
    }

    #[test]
    fn pull_head_reports_hashes() {
        let mut ctx = fresh_context();
        ctx.vault_image.extend_from_slice(b"encrypted");
        ctx.recipients_manifest
            .extend_from_slice(b"{\"recipients\":[\"device\"]}");
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
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn load_from_flash_populates_context() {
        type Flash = MockFlashBase<16, 4, 1024>;
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

        block_on(async {
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

            let journal_bytes = encode_journal_operations(&vec![JournalOperation::Add {
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
        block_on(ctx.load_from_flash(&mut flash, range)).unwrap();

        assert_eq!(ctx.vault_image.as_slice(), b"vault-image");
        assert_eq!(ctx.recipients_manifest.as_slice(), b"recipients");
        assert_eq!(ctx.vault_generation, 7);
        assert_eq!(ctx.journal_ops.len(), 1);
        assert_eq!(ctx.vault_offset, 0);
        assert_eq!(ctx.recipients_offset, 0);
        assert_eq!(ctx.transfer_stage, TransferStage::Vault);
        assert_eq!(ctx.last_artifact, VaultArtifact::Vault);

        ctx.crypto.unlock_vault_key(pin).unwrap();
        let nonce = [0xAA; 12];
        let payload = b"record-data".to_vec();
        let ciphertext = ctx.crypto.encrypt_record(&nonce, &payload).unwrap();
        let roundtrip = ctx.crypto.decrypt_record(&nonce, &ciphertext).unwrap();
        assert_eq!(roundtrip, payload);
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
    fn wrap_new_keys_and_wipe_clears_sensitive_state() {
        let mut ctx = fresh_context();
        ctx.vault_image.extend_from_slice(b"data");
        ctx.recipients_manifest.extend_from_slice(b"recips");

        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        ctx.crypto.wrap_new_keys(b"222222", &mut rng).unwrap();
        ctx.crypto.unlock_vault_key(b"222222").unwrap();

        assert!(ctx.crypto.kek.is_some());
        assert!(ctx.crypto.vault_key.is_some());

        ctx.wipe_sensitive();

        assert!(ctx.crypto.kek.is_none());
        assert!(ctx.crypto.vault_key.is_none());
        assert!(ctx.vault_image.is_empty());
        assert!(ctx.recipients_manifest.is_empty());
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
        assert!(ctx.crypto.vault_key.is_none());
    }
}
