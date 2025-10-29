#![cfg_attr(not(test), no_std)]
#![cfg_attr(all(not(test), target_arch = "xtensa"), no_main)]

extern crate alloc;

use alloc::{format, string::String, string::ToString, vec::Vec};
use core::cmp;

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

/// Placeholder for future cryptographic material associated with a sync session.
#[derive(Default)]
pub struct CryptoMaterial {
    vault_key: Zeroizing<Vec<u8>>,
    recipients_key: Zeroizing<Vec<u8>>,
}

impl CryptoMaterial {
    /// Reserve space for secrets that will be provisioned when the secure element is wired in.
    pub fn reserve(&mut self, vault_key_len: usize, recipients_key_len: usize) {
        self.vault_key.reserve(vault_key_len);
        self.recipients_key.reserve(recipients_key_len);
    }

    /// Clear any secrets that might still be resident in memory.
    pub fn wipe(&mut self) {
        self.vault_key.iter_mut().for_each(|byte| *byte = 0);
        self.vault_key.clear();

        self.recipients_key.iter_mut().for_each(|byte| *byte = 0);
        self.recipients_key.clear();
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

impl SyncContext {
    /// Construct a new synchronization context with pre-allocated buffers.
    pub fn new() -> Self {
        let mut crypto = CryptoMaterial::default();
        crypto.reserve(64, 64);

        Self {
            journal_ops: Vec::new(),
            pending_sequence: None,
            next_sequence: 1,
            vault_image: Zeroizing::new(Vec::with_capacity(VAULT_BUFFER_CAPACITY)),
            vault_offset: 0,
            recipients_manifest: Zeroizing::new(Vec::with_capacity(RECIPIENTS_BUFFER_CAPACITY)),
            crypto,
            session_id: 0,
            device_name: String::from("Cardputer Wallet"),
            firmware_version: String::from(env!("CARGO_PKG_VERSION")),
            vault_generation: 0,
            current_time_ms: 0,
        }
    }

    /// Populate the buffers with demo data until the secure storage backend is wired in.
    pub fn bootstrap_demo_state(&mut self) {
        if self.vault_image.is_empty() {
            self.vault_image.extend_from_slice(b"{\"status\":\"demo\"}");
        }
        if self.recipients_manifest.is_empty() {
            self.recipients_manifest
                .extend_from_slice(b"{\"recipients\":[]}");
        }
        if self.journal_ops.is_empty() {
            self.journal_ops.push(JournalOperation::Add {
                entry_id: String::from("demo-entry"),
            });
        }
        if self.vault_generation == 0 {
            self.vault_generation = 1;
        }
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
            ctx.bootstrap_demo_state();
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
        ctx.bootstrap_demo_state();
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

    #[test]
    fn pull_head_reports_hashes() {
        let mut ctx = SyncContext::new();
        ctx.bootstrap_demo_state();

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
}
