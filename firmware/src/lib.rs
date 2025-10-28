#![cfg_attr(not(test), no_std)]
#![cfg_attr(all(not(test), target_arch = "xtensa"), no_main)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};
use core::cmp;

use shared::cdc::{FrameCommand, FrameHeader};
use shared::schema::{
    AbortRequest, DeviceError, DeviceErrorCode, DeviceResponse, JournalFrame, JournalOperation,
    PullVaultRequest, PushAck, SyncCompletion, VaultChunk, PROTOCOL_VERSION,
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
    /// Frame header or checksum validation failed.
    InvalidFrame(String),
    /// Incoming CBOR payload could not be decoded.
    Decode(String),
    /// Outgoing CBOR payload could not be encoded.
    Encode(String),
    /// Host requested a protocol version that we do not understand.
    UnsupportedProtocol(u16),
    /// Host acknowledged a journal frame with mismatching metadata.
    InvalidAcknowledgement,
}

impl ProtocolError {
    fn as_device_error(&self) -> DeviceError {
        let (code, message) = match self {
            ProtocolError::FrameTooLarge(len) => (
                DeviceErrorCode::ResourceExhausted,
                format!("frame length {len} exceeds device buffer"),
            ),
            ProtocolError::Transport => (
                DeviceErrorCode::InternalFailure,
                "transport failure while using USB CDC".into(),
            ),
            ProtocolError::InvalidFrame(message) => (
                DeviceErrorCode::ChecksumMismatch,
                format!("invalid frame received: {message}"),
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
            ProtocolError::InvalidAcknowledgement => (
                DeviceErrorCode::ChecksumMismatch,
                "received acknowledgement that does not match the last frame".into(),
            ),
        };

        DeviceError {
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
        let chunk_size = cmp::min(
            cmp::min(max_chunk, FRAME_MAX_SIZE),
            self.vault_image.len().saturating_sub(self.vault_offset),
        );
        let slice_end = self.vault_offset + chunk_size;
        let payload = if chunk_size == 0 {
            Vec::new()
        } else {
            self.vault_image[self.vault_offset..slice_end].to_vec()
        };

        self.vault_offset = slice_end;
        let remaining = self.vault_image.len().saturating_sub(self.vault_offset) as u64;
        let checksum = accumulate_checksum(0, &payload);

        VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: self.next_sequence,
            total_size: self.vault_image.len() as u64,
            remaining_bytes: remaining,
            device_chunk_size: cmp::max(1, cmp::min(FRAME_MAX_SIZE, max_chunk)) as u32,
            data: payload,
            checksum,
            is_last: remaining == 0,
        }
    }
}

fn accumulate_checksum(mut seed: u32, payload: &[u8]) -> u32 {
    for byte in payload {
        seed = seed.wrapping_mul(16777619) ^ (*byte as u32);
    }
    seed
}

fn encode_response_frame(
    response: &DeviceResponse,
) -> Result<(FrameCommand, Vec<u8>), ProtocolError> {
    match response {
        DeviceResponse::JournalFrame(frame) => Ok((
            FrameCommand::DeviceJournalFrame,
            serde_cbor::to_vec(frame).map_err(|err| ProtocolError::Encode(err.to_string()))?,
        )),
        DeviceResponse::VaultChunk(chunk) => Ok((
            FrameCommand::DeviceVaultChunk,
            serde_cbor::to_vec(chunk).map_err(|err| ProtocolError::Encode(err.to_string()))?,
        )),
        DeviceResponse::Completed(summary) => Ok((
            FrameCommand::DeviceCompleted,
            serde_cbor::to_vec(summary).map_err(|err| ProtocolError::Encode(err.to_string()))?,
        )),
        DeviceResponse::Error(error) => Ok((
            FrameCommand::DeviceError,
            serde_cbor::to_vec(error).map_err(|err| ProtocolError::Encode(err.to_string()))?,
        )),
    }
}

/// Decode a host frame, dispatch to the appropriate handler and encode the response.
pub fn process_host_frame(
    command: FrameCommand,
    payload: &[u8],
    ctx: &mut SyncContext,
) -> Result<DeviceResponse, ProtocolError> {
    match command {
        FrameCommand::HostPullVault => {
            let pull: PullVaultRequest = serde_cbor::from_slice(payload)
                .map_err(|err| ProtocolError::Decode(err.to_string()))?;
            handle_pull(&pull, ctx)
        }
        FrameCommand::HostAckPush => {
            let ack: PushAck = serde_cbor::from_slice(payload)
                .map_err(|err| ProtocolError::Decode(err.to_string()))?;
            handle_push(&ack, ctx)
        }
        FrameCommand::HostAbort => {
            let abort: AbortRequest = serde_cbor::from_slice(payload)
                .map_err(|err| ProtocolError::Decode(err.to_string()))?;
            Ok(handle_abort(&abort, ctx))
        }
        other => Err(ProtocolError::InvalidFrame(format!(
            "unsupported host command {other:?}"
        ))),
    }
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

fn handle_push(ack: &PushAck, ctx: &mut SyncContext) -> Result<DeviceResponse, ProtocolError> {
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
            Ok(DeviceResponse::Completed(SyncCompletion {
                protocol_version: PROTOCOL_VERSION,
                frames_sent: sequence,
                stream_checksum: checksum,
            }))
        }
        _ => Err(ProtocolError::InvalidAcknowledgement),
    }
}

fn handle_abort(_abort: &AbortRequest, ctx: &mut SyncContext) -> DeviceResponse {
    ctx.wipe_sensitive();
    DeviceResponse::Completed(SyncCompletion {
        protocol_version: PROTOCOL_VERSION,
        frames_sent: 0,
        stream_checksum: 0,
    })
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
                Ok((command, payload)) => match process_host_frame(command, &payload, &mut ctx) {
                    Ok(response) => send_response(&mut serial, &response),
                    Err(err) => {
                        let response = DeviceResponse::Error(err.as_device_error());
                        send_response(&mut serial, &response);
                    }
                },
                Err(err) => {
                    let response = DeviceResponse::Error(err.as_device_error());
                    send_response(&mut serial, &response);
                }
            }
        }
    }

    async fn read_frame(
        serial: &mut UsbSerialJtag<'static, Blocking>,
    ) -> Result<(FrameCommand, Vec<u8>), ProtocolError> {
        let mut header_bytes = [0u8; FrameHeader::ENCODED_LEN];
        for byte in &mut header_bytes {
            *byte = read_byte(serial).await?;
        }
        let header = FrameHeader::decode(header_bytes)
            .map_err(|err| ProtocolError::InvalidFrame(err.to_string()))?;

        if header.payload_length as usize > FRAME_MAX_SIZE {
            return Err(ProtocolError::FrameTooLarge(header.payload_length as usize));
        }

        let mut buffer = Vec::with_capacity(header.payload_length as usize);
        for _ in 0..header.payload_length {
            buffer.push(read_byte(serial).await?);
        }

        let mut checksum_bytes = [0u8; 4];
        for byte in &mut checksum_bytes {
            *byte = read_byte(serial).await?;
        }
        let expected = u32::from_le_bytes(checksum_bytes);
        let actual = header.checksum(&buffer);
        if expected != actual {
            return Err(ProtocolError::InvalidFrame(format!(
                "checksum mismatch (expected 0x{expected:08X}, calculated 0x{actual:08X})"
            )));
        }

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
        command: FrameCommand,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        if payload.len() > FRAME_MAX_SIZE {
            return Err(ProtocolError::FrameTooLarge(payload.len()));
        }
        let header = FrameHeader::new(command, payload.len() as u32);
        let header_bytes = header.encode();
        serial
            .write(&header_bytes)
            .map_err(|_| ProtocolError::Transport)?;
        if !payload.is_empty() {
            serial
                .write(payload)
                .map_err(|_| ProtocolError::Transport)?;
        }
        let checksum = header.checksum(payload);
        serial
            .write(&checksum.to_le_bytes())
            .map_err(|_| ProtocolError::Transport)?;
        serial.flush_tx().map_err(|_| ProtocolError::Transport)
    }

    fn send_response(serial: &mut UsbSerialJtag<'static, Blocking>, response: &DeviceResponse) {
        match encode_response_frame(response) {
            Ok((command, payload)) => {
                let _ = write_frame(serial, command, &payload);
            }
            Err(err) => {
                let fatal = err.as_device_error();
                let fallback = DeviceResponse::Error(fatal);
                let payload = serde_cbor::to_vec(&fallback).unwrap_or_default();
                let _ = write_frame(serial, FrameCommand::DeviceError, &payload);
            }
        }
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

        let request = PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: 64 * 1024,
            max_chunk_size: 1024,
            known_generation: None,
        };

        let payload = serde_cbor::to_vec(&request).expect("encode request");
        let response = process_host_frame(FrameCommand::HostPullVault, &payload, &mut ctx)
            .expect("process pull");

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

        let pull_request = PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: 64 * 1024,
            max_chunk_size: 1024,
            known_generation: None,
        };
        let encoded_pull = serde_cbor::to_vec(&pull_request).unwrap();
        let frame =
            process_host_frame(FrameCommand::HostPullVault, &encoded_pull, &mut ctx).unwrap();
        let (sequence, checksum) = match frame {
            DeviceResponse::JournalFrame(frame) => (frame.sequence, frame.checksum),
            other => panic!("unexpected response: {other:?}"),
        };

        let ack = PushAck {
            protocol_version: PROTOCOL_VERSION,
            last_frame_sequence: sequence,
            journal_checksum: checksum,
        };
        let encoded_ack = serde_cbor::to_vec(&ack).unwrap();
        let decoded =
            process_host_frame(FrameCommand::HostAckPush, &encoded_ack, &mut ctx).unwrap();

        match decoded {
            DeviceResponse::Completed(status) => {
                assert_eq!(status.frames_sent, sequence);
                assert_eq!(status.stream_checksum, checksum);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn device_rejects_unexpected_command() {
        let mut ctx = SyncContext::new();
        let err = process_host_frame(FrameCommand::DeviceCompleted, &[], &mut ctx)
            .expect_err("unexpected command should fail");
        match err {
            ProtocolError::InvalidFrame(message) => {
                assert!(message.contains("unsupported host command"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn encode_response_frame_matches_command() {
        let response = DeviceResponse::Completed(SyncCompletion {
            protocol_version: PROTOCOL_VERSION,
            frames_sent: 2,
            stream_checksum: 0x1234_5678,
        });

        let (command, payload) = encode_response_frame(&response).expect("encode response");
        assert_eq!(command, FrameCommand::DeviceCompleted);

        let decoded: SyncCompletion = serde_cbor::from_slice(&payload).expect("decode");
        assert_eq!(decoded.frames_sent, 2);
        assert_eq!(decoded.stream_checksum, 0x1234_5678);
    }

    #[test]
    fn unsupported_protocol_is_rejected() {
        let mut ctx = SyncContext::new();
        let request = PullVaultRequest {
            protocol_version: PROTOCOL_VERSION + 1,
            host_buffer_size: 1,
            max_chunk_size: 1,
            known_generation: None,
        };
        let payload = serde_cbor::to_vec(&request).unwrap();
        let error = process_host_frame(FrameCommand::HostPullVault, &payload, &mut ctx)
            .expect_err("expected rejection");
        assert!(matches!(error, ProtocolError::UnsupportedProtocol(_)));
    }
}
