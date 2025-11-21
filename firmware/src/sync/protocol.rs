use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::cmp;

#[cfg(any(test, target_arch = "xtensa"))]
use crate::hid::core::actions::DeviceAction;
use shared::cdc::transport::{FrameTransportError, command_for_request, command_for_response};
use shared::cdc::{CdcCommand, FRAME_HEADER_SIZE, compute_crc32};
use shared::checksum::accumulate_checksum;
use shared::journal::JournalHasher;
use shared::schema::{
    AckRequest, AckResponse, DeviceErrorCode, DeviceResponse, GetTimeRequest, HelloRequest,
    HelloResponse, HostRequest, JournalFrame, NackResponse, PROTOCOL_VERSION, PullHeadRequest,
    PullHeadResponse, PullVaultRequest, PushOperationsFrame, PushVaultFrame, SetTimeRequest,
    StatusRequest, StatusResponse, TimeResponse, VaultArtifact, VaultChunk, decode_host_request,
    encode_device_response,
};
use shared::transfer::ArtifactLengths;

use super::{
    FRAME_MAX_SIZE, RECIPIENTS_BUFFER_CAPACITY, SIGNATURE_BUFFER_CAPACITY, SyncContext,
    VAULT_BUFFER_CAPACITY,
};

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
    pub fn as_nack(&self) -> NackResponse {
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

impl SyncContext {
    pub(crate) fn next_transfer_chunk(
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
            let (chunk, commit) = pending.into_chunk();
            let response = DeviceResponse::VaultChunk(chunk);
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
                let DeviceResponse::VaultChunk(chunk) = response else {
                    unreachable!("response must be a vault chunk");
                };
                if chunk_size == 0 && chunk.remaining_bytes > 0 {
                    return Err(ProtocolError::HostBufferTooSmall {
                        required: encoded_len + FRAME_HEADER_SIZE,
                        provided: host_buffer_size,
                    });
                }
                return Ok(self.transfer.commit_chunk(chunk, commit));
            }

            if chunk_size == 0 {
                let DeviceResponse::VaultChunk(chunk) = response else {
                    unreachable!("response must be a vault chunk");
                };
                if chunk.remaining_bytes > 0 || frame_budget < encoded_len {
                    return Err(ProtocolError::HostBufferTooSmall {
                        required: encoded_len + FRAME_HEADER_SIZE,
                        provided: host_buffer_size,
                    });
                }

                return Ok(self.transfer.commit_chunk(chunk, commit));
            }

            let DeviceResponse::VaultChunk(chunk) = response else {
                unreachable!("response must be a vault chunk");
            };
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

    pub(crate) fn reset_transfer_state(&mut self) {
        let lengths = ArtifactLengths {
            vault: self.vault_image.len(),
            recipients: self.recipients_manifest.len(),
            signature: self.signature.len(),
        };
        self.transfer.reset(lengths);
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
    crate::hid::core::actions::publish(DeviceAction::StartSession {
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
        current_time_ms: ctx.current_time_ms(),
    }))
}

fn handle_set_time(
    request: &SetTimeRequest,
    ctx: &mut SyncContext,
) -> Result<DeviceResponse, ProtocolError> {
    if request.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocol(request.protocol_version));
    }

    ctx.set_epoch_time_ms(request.epoch_millis);

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
        epoch_millis: ctx.current_time_ms(),
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

pub(super) fn handle_pull(
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
            "received operations frame ({} ops, last: {})",
            push.operations.len(),
            push.is_last
        ),
    }))
}

pub(super) fn handle_ack(
    ack: &AckRequest,
    ctx: &mut SyncContext,
) -> Result<DeviceResponse, ProtocolError> {
    if ack.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocol(ack.protocol_version));
    }

    let Some(state) = ctx.frame_tracker.state() else {
        return Err(ProtocolError::InvalidAcknowledgement);
    };

    if state.sequence != ack.last_frame_sequence || state.checksum != ack.journal_checksum {
        return Err(ProtocolError::InvalidAcknowledgement);
    }

    ctx.frame_tracker.clear();

    #[cfg(any(test, target_arch = "xtensa"))]
    crate::hid::core::actions::publish(DeviceAction::EndSession);

    Ok(DeviceResponse::Ack(AckResponse {
        protocol_version: PROTOCOL_VERSION,
        message: format!("acknowledged frame {}", ack.last_frame_sequence),
    }))
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
