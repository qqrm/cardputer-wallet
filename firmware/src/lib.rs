#![cfg_attr(not(test), no_std)]
#![cfg_attr(all(not(test), target_arch = "xtensa"), no_main)]

extern crate alloc;

use alloc::{format, string::String, string::ToString, vec, vec::Vec};
use core::{cmp, ops::Range};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use embedded_storage_async::nor_flash::NorFlash;
use rand_core::{CryptoRng, RngCore};
use scrypt::{
    errors::{InvalidOutputLen, InvalidParams},
    Params as ScryptParams,
};
use sequential_storage::{cache::NoCache, map, Error as FlashStorageError};
use serde::{Deserialize, Serialize};

#[cfg(target_arch = "xtensa")]
use shared::cdc::FRAME_HEADER_SIZE;
use shared::cdc::{compute_crc32, CdcCommand, FrameHeader};
use shared::schema::{
    AckRequest, AckResponse, DeviceErrorCode, DeviceResponse, GetTimeRequest, HelloRequest,
    HelloResponse, HostRequest, JournalFrame, JournalOperation, NackResponse, PullHeadRequest,
    PullHeadResponse, PullVaultRequest, SetTimeRequest, StatusRequest, StatusResponse,
    TimeResponse, VaultChunk, PROTOCOL_VERSION,
};
use zeroize::Zeroizing;

/// Maximum payload size (in bytes) that a single CBOR frame is allowed to occupy on the wire.
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
    /// Incoming CBOR payload could not be decoded.
    Decode(String),
    /// Outgoing CBOR payload could not be encoded.
    Encode(String),
    /// Host requested a protocol version that we do not understand.
    UnsupportedProtocol(u16),
    /// Header contained a command that does not match the encoded payload.
    InvalidCommand,
    /// CRC validation failed for an incoming frame.
    ChecksumMismatch,
    /// Host acknowledged a journal frame with mismatching metadata.
    InvalidAcknowledgement,
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
                format!("failed to decode CBOR request: {err}"),
            ),
            ProtocolError::Encode(err) => (
                DeviceErrorCode::InternalFailure,
                format!("failed to encode CBOR response: {err}"),
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
    wrapped_vault_key: Vec<u8>,
    scrypt_params: ScryptParams,
}

impl Default for CryptoMaterial {
    fn default() -> Self {
        Self {
            kek: None,
            vault_key: None,
            pin_salt: [0u8; 16],
            kek_nonce: [0u8; 12],
            wrapped_vault_key: Vec::new(),
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
        self.wrapped_vault_key = record.wrapped_key.clone();
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
                wrapped_key: self.wrapped_vault_key.clone(),
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
        self.wrapped_vault_key = ciphertext;
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
        let plaintext = Zeroizing::new(cipher.decrypt(&nonce, self.wrapped_vault_key.as_ref())?);

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

/// Runtime state required to service synchronization requests from the host.
pub struct SyncContext {
    journal_ops: Vec<JournalOperation>,
    pending_sequence: Option<(u32, u32)>,
    next_sequence: u32,
    vault_image: Zeroizing<Vec<u8>>,
    vault_offset: usize,
    recipients_manifest: Zeroizing<Vec<u8>>,
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
            recipients_manifest: Zeroizing::new(Vec::with_capacity(RECIPIENTS_BUFFER_CAPACITY)),
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
            self.vault_image = Zeroizing::new(vault);
        } else {
            self.vault_image = Zeroizing::new(Vec::new());
        }

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
            self.recipients_manifest = Zeroizing::new(recipients);
        } else {
            self.recipients_manifest = Zeroizing::new(Vec::new());
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
            let operations: Vec<JournalOperation> = serde_cbor::from_slice(&journal_bytes)
                .map_err(|err| StorageError::Decode(err.to_string()))?;
            self.journal_ops = operations;
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
            let record: KeyRecord = serde_cbor::from_slice(&key_bytes)
                .map_err(|err| StorageError::Decode(err.to_string()))?;
            self.crypto.configure_from_record(&record)?;
        }

        self.vault_offset = 0;
        self.pending_sequence = None;
        self.next_sequence = 1;

        Ok(())
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
            let encoded =
                serde_cbor::to_vec(&record).map_err(|err| StorageError::Decode(err.to_string()))?;

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
        self.vault_offset = 0;
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

    fn next_vault_chunk(&mut self, max_chunk: usize) -> VaultChunk {
        let available = self.vault_image.len().saturating_sub(self.vault_offset);
        let max_payload = cmp::min(max_chunk, FRAME_MAX_SIZE);
        let mut chunk_size = cmp::min(max_payload, available);
        let device_chunk_size = cmp::max(1, max_payload) as u32;

        loop {
            let slice_end = self.vault_offset + chunk_size;
            let payload = if chunk_size == 0 {
                Vec::new()
            } else {
                self.vault_image[self.vault_offset..slice_end].to_vec()
            };

            let remaining = self.vault_image.len().saturating_sub(slice_end) as u64;
            let checksum = accumulate_checksum(0, &payload);

            let chunk = VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: self.next_sequence,
                total_size: self.vault_image.len() as u64,
                remaining_bytes: remaining,
                device_chunk_size,
                data: payload,
                checksum,
                is_last: remaining == 0,
            };

            let encoded_len = match serde_cbor::to_vec(&DeviceResponse::VaultChunk(chunk.clone())) {
                Ok(bytes) => bytes.len(),
                Err(_) => return chunk,
            };

            if encoded_len <= FRAME_MAX_SIZE {
                self.vault_offset = slice_end;
                return chunk;
            }

            if chunk_size == 0 {
                return chunk;
            }

            let overhead = encoded_len.saturating_sub(chunk.data.len());
            if overhead >= FRAME_MAX_SIZE {
                chunk_size = 0;
                continue;
            }

            let target_size = FRAME_MAX_SIZE - overhead;
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
    serde_cbor::from_slice(frame).map_err(|err| ProtocolError::Decode(err.to_string()))
}

fn encode_response(response: &DeviceResponse) -> Result<Vec<u8>, ProtocolError> {
    serde_cbor::to_vec(response).map_err(|err| ProtocolError::Encode(err.to_string()))
}

fn command_for_request(request: &HostRequest) -> CdcCommand {
    match request {
        HostRequest::Hello(_) => CdcCommand::Hello,
        HostRequest::Status(_) => CdcCommand::Status,
        HostRequest::SetTime(_) => CdcCommand::SetTime,
        HostRequest::GetTime(_) => CdcCommand::GetTime,
        HostRequest::PullHead(_) => CdcCommand::PullHead,
        HostRequest::PullVault(_) => CdcCommand::PullVault,
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
    ctx.vault_offset = 0;

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
        let chunk = ctx.next_vault_chunk(request.max_chunk_size as usize);
        let checksum = chunk.checksum;
        let sequence = chunk.sequence;
        ctx.pending_sequence = Some((sequence, checksum));
        ctx.next_sequence = ctx.next_sequence.wrapping_add(1);

        Ok(DeviceResponse::VaultChunk(chunk))
    }
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
            ctx.vault_offset = 0;
            ctx.wipe_sensitive();
            ctx.vault_generation = ctx.vault_generation.saturating_add(1);
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
        clock::CpuClock, timer::timg::TimerGroup, usb_serial_jtag::UsbSerialJtag, Blocking, Config,
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
    use esp_hal::{usb_serial_jtag::UsbSerialJtag, Blocking};
    use nb::Error as NbError;

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
                                serde_cbor::to_vec(&DeviceResponse::Nack(fatal)).unwrap_or_default()
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
                            serde_cbor::to_vec(&DeviceResponse::Nack(fatal)).unwrap_or_default()
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

    #[test]
    fn pull_request_emits_journal_frame() {
        let mut ctx = SyncContext::new();
        ctx.record_operation(JournalOperation::Add {
            entry_id: String::from("entry-42"),
        });

        let request = HostRequest::PullVault(PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: 64 * 1024,
            max_chunk_size: 1024,
            known_generation: None,
        });

        let encoded = serde_cbor::to_vec(&request).expect("encode request");
        let (command, response_bytes) =
            process_host_frame(CdcCommand::PullVault, &encoded, &mut ctx).expect("process pull");
        assert_eq!(command, CdcCommand::PushOps);
        let response: DeviceResponse =
            serde_cbor::from_slice(&response_bytes).expect("decode response");

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
    fn acknowledgement_clears_pending_sequence() {
        let mut ctx = SyncContext::new();
        ctx.record_operation(JournalOperation::Delete {
            entry_id: String::from("obsolete"),
        });

        let pull_request = HostRequest::PullVault(PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: 64 * 1024,
            max_chunk_size: 1024,
            known_generation: None,
        });
        let encoded_pull = serde_cbor::to_vec(&pull_request).unwrap();
        let (response_command, response_bytes) =
            process_host_frame(CdcCommand::PullVault, &encoded_pull, &mut ctx).unwrap();
        assert_eq!(response_command, CdcCommand::PushOps);
        let frame: DeviceResponse = serde_cbor::from_slice(&response_bytes).unwrap();
        let (sequence, checksum) = match frame {
            DeviceResponse::JournalFrame(frame) => (frame.sequence, frame.checksum),
            other => panic!("unexpected response: {other:?}"),
        };

        let ack = HostRequest::Ack(AckRequest {
            protocol_version: PROTOCOL_VERSION,
            last_frame_sequence: sequence,
            journal_checksum: checksum,
        });
        let encoded_ack = serde_cbor::to_vec(&ack).unwrap();
        let (ack_command, ack_response) =
            process_host_frame(CdcCommand::Ack, &encoded_ack, &mut ctx).unwrap();
        assert_eq!(ack_command, CdcCommand::Ack);
        let decoded: DeviceResponse = serde_cbor::from_slice(&ack_response).unwrap();

        match decoded {
            DeviceResponse::Ack(message) => {
                assert_eq!(message.protocol_version, PROTOCOL_VERSION);
                assert!(message.message.contains(&sequence.to_string()));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn unsupported_protocol_is_rejected() {
        let mut ctx = SyncContext::new();
        let request = HostRequest::PullVault(PullVaultRequest {
            protocol_version: PROTOCOL_VERSION + 1,
            host_buffer_size: 1,
            max_chunk_size: 1,
            known_generation: None,
        });
        let encoded = serde_cbor::to_vec(&request).unwrap();
        let error = process_host_frame(CdcCommand::PullVault, &encoded, &mut ctx)
            .expect_err("expected rejection");
        assert!(matches!(error, ProtocolError::UnsupportedProtocol(_)));
    }

    #[test]
    fn mismatched_command_is_rejected() {
        let mut ctx = SyncContext::new();
        let request = HostRequest::PullVault(PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: 1,
            max_chunk_size: 1,
            known_generation: None,
        });
        let encoded = serde_cbor::to_vec(&request).unwrap();
        let error = process_host_frame(CdcCommand::Ack, &encoded, &mut ctx)
            .expect_err("expected command mismatch");
        assert_eq!(error, ProtocolError::InvalidCommand);
    }

    #[test]
    fn checksum_validation_detects_corruption() {
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
        let mut ctx = SyncContext::new();
        let request = HostRequest::Hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            client_name: "cli".into(),
            client_version: "0.1.0".into(),
        });

        let encoded = serde_cbor::to_vec(&request).unwrap();
        let (command, response_bytes) =
            process_host_frame(CdcCommand::Hello, &encoded, &mut ctx).unwrap();
        assert_eq!(command, CdcCommand::Hello);
        let response: DeviceResponse = serde_cbor::from_slice(&response_bytes).unwrap();

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
        let mut ctx = SyncContext::new();
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
        let encoded = serde_cbor::to_vec(&request).unwrap();
        let (command, response_bytes) =
            process_host_frame(CdcCommand::Status, &encoded, &mut ctx).unwrap();
        assert_eq!(command, CdcCommand::Status);
        let response: DeviceResponse = serde_cbor::from_slice(&response_bytes).unwrap();

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
        let mut ctx = SyncContext::new();
        let set_request = HostRequest::SetTime(SetTimeRequest {
            protocol_version: PROTOCOL_VERSION,
            epoch_millis: 9_876,
        });
        let encoded_set = serde_cbor::to_vec(&set_request).unwrap();
        let (command, response_bytes) =
            process_host_frame(CdcCommand::SetTime, &encoded_set, &mut ctx).unwrap();
        assert_eq!(command, CdcCommand::Ack);
        let ack: DeviceResponse = serde_cbor::from_slice(&response_bytes).unwrap();
        match ack {
            DeviceResponse::Ack(message) => {
                assert!(message.message.contains("9876"));
            }
            other => panic!("unexpected response: {other:?}"),
        }

        let get_request = HostRequest::GetTime(GetTimeRequest {
            protocol_version: PROTOCOL_VERSION,
        });
        let encoded_get = serde_cbor::to_vec(&get_request).unwrap();
        let (command, response_bytes) =
            process_host_frame(CdcCommand::GetTime, &encoded_get, &mut ctx).unwrap();
        assert_eq!(command, CdcCommand::GetTime);
        let time_response: DeviceResponse = serde_cbor::from_slice(&response_bytes).unwrap();
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
        let mut ctx = SyncContext::new();
        ctx.vault_image.extend_from_slice(b"encrypted");
        ctx.recipients_manifest
            .extend_from_slice(b"{\"recipients\":[\"device\"]}");
        ctx.vault_generation = 2;

        let request = HostRequest::PullHead(PullHeadRequest {
            protocol_version: PROTOCOL_VERSION,
        });
        let encoded = serde_cbor::to_vec(&request).unwrap();
        let (command, response_bytes) =
            process_host_frame(CdcCommand::PullHead, &encoded, &mut ctx).unwrap();
        assert_eq!(command, CdcCommand::PullHead);
        let response: DeviceResponse = serde_cbor::from_slice(&response_bytes).unwrap();

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
        let encoded_record = serde_cbor::to_vec(&key_record).unwrap();

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

            let journal_bytes = serde_cbor::to_vec(&vec![JournalOperation::Add {
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

        let mut ctx = SyncContext::new();
        block_on(ctx.load_from_flash(&mut flash, range)).unwrap();

        assert_eq!(ctx.vault_image.as_slice(), b"vault-image");
        assert_eq!(ctx.recipients_manifest.as_slice(), b"recipients");
        assert_eq!(ctx.vault_generation, 7);
        assert_eq!(ctx.journal_ops.len(), 1);

        ctx.crypto.unlock_vault_key(pin).unwrap();
        let nonce = [0xAA; 12];
        let payload = b"record-data".to_vec();
        let ciphertext = ctx.crypto.encrypt_record(&nonce, &payload).unwrap();
        let roundtrip = ctx.crypto.decrypt_record(&nonce, &ciphertext).unwrap();
        assert_eq!(roundtrip, payload);
    }

    #[test]
    fn wrap_new_keys_and_wipe_clears_sensitive_state() {
        let mut ctx = SyncContext::new();
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
}
