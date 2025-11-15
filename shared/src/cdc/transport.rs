use crate::cdc::{CdcCommand, FRAME_HEADER_SIZE, FrameHeader, FrameHeaderError, compute_crc32};
use crate::schema::{DeviceResponse, HostRequest};
use core::{cmp, fmt};

/// Errors produced by the shared CDC transport helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameTransportError {
    /// Payload length exceeds the configured limit.
    PayloadTooLarge { actual: usize, limit: usize },
    /// Header advertised a different version than expected.
    UnsupportedVersion { expected: u16, found: u16 },
    /// Header and payload lengths do not match.
    LengthMismatch { declared: usize, actual: usize },
    /// CRC32 verification failed.
    ChecksumMismatch { expected: u32, actual: u32 },
    /// Header decoding failed before payload validation.
    Header(FrameHeaderError),
}

impl fmt::Display for FrameTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameTransportError::PayloadTooLarge { actual, limit } => {
                write!(f, "frame payload {actual} exceeds limit {limit}")
            }
            FrameTransportError::UnsupportedVersion { expected, found } => {
                write!(f, "expected protocol version {expected}, got {found}")
            }
            FrameTransportError::LengthMismatch { declared, actual } => {
                write!(
                    f,
                    "header declared length {declared} but payload was {actual}"
                )
            }
            FrameTransportError::ChecksumMismatch { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch (expected 0x{expected:08X}, calculated 0x{actual:08X})"
                )
            }
            FrameTransportError::Header(err) => write!(f, "{err}"),
        }
    }
}

impl From<FrameHeaderError> for FrameTransportError {
    fn from(value: FrameHeaderError) -> Self {
        FrameTransportError::Header(value)
    }
}

/// Encode the CDC frame header for the provided payload.
pub fn encode_frame(
    version: u16,
    command: CdcCommand,
    payload: &[u8],
    max_payload: usize,
) -> Result<[u8; FRAME_HEADER_SIZE], FrameTransportError> {
    let limit = cmp::min(max_payload, u32::MAX as usize);
    if payload.len() > limit {
        return Err(FrameTransportError::PayloadTooLarge {
            actual: payload.len(),
            limit,
        });
    }

    let checksum = compute_crc32(payload);
    let header = FrameHeader::new(version, command, payload.len() as u32, checksum);
    Ok(header.to_bytes())
}

/// Decode and validate the CDC frame header using the expected version and payload limit.
pub fn decode_frame_header(
    expected_version: u16,
    max_payload: usize,
    header_bytes: [u8; FRAME_HEADER_SIZE],
) -> Result<FrameHeader, FrameTransportError> {
    let header = FrameHeader::from_bytes(header_bytes)?;

    if header.version != expected_version {
        return Err(FrameTransportError::UnsupportedVersion {
            expected: expected_version,
            found: header.version,
        });
    }

    if header.length as usize > max_payload {
        return Err(FrameTransportError::PayloadTooLarge {
            actual: header.length as usize,
            limit: max_payload,
        });
    }

    Ok(header)
}

/// Validate the payload against the header metadata.
pub fn decode_frame(header: &FrameHeader, payload: &[u8]) -> Result<(), FrameTransportError> {
    let declared = header.length as usize;
    if declared != payload.len() {
        return Err(FrameTransportError::LengthMismatch {
            declared,
            actual: payload.len(),
        });
    }

    let expected = header.checksum;
    let actual = compute_crc32(payload);
    if expected != actual {
        return Err(FrameTransportError::ChecksumMismatch { expected, actual });
    }

    Ok(())
}

/// Resolve the CDC command associated with a host request.
pub fn command_for_request(request: &HostRequest) -> CdcCommand {
    match request {
        HostRequest::Hello(_) => CdcCommand::Hello,
        HostRequest::Status(_) => CdcCommand::Status,
        HostRequest::SetTime(_) => CdcCommand::SetTime,
        HostRequest::GetTime(_) => CdcCommand::GetTime,
        HostRequest::PullHead(_) => CdcCommand::PullHead,
        HostRequest::PullVault(_) => CdcCommand::PullVault,
        HostRequest::PushVault(_) => CdcCommand::PushVault,
        HostRequest::PushOps(_) => CdcCommand::PushOps,
        HostRequest::Ack(_) => CdcCommand::Ack,
    }
}

/// Resolve the CDC command associated with a device response.
pub fn command_for_response(response: &DeviceResponse) -> CdcCommand {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{PullHeadRequest, VaultArtifact, VaultChunk};
    use alloc::vec;

    #[test]
    fn encode_rejects_large_payload() {
        let payload = vec![0u8; 8];
        let err = encode_frame(1, CdcCommand::Hello, &payload, 4).expect_err("expected error");
        assert!(matches!(
            err,
            FrameTransportError::PayloadTooLarge {
                actual: 8,
                limit: 4
            }
        ));
    }

    #[test]
    fn decode_detects_checksum_mismatch() {
        let header = FrameHeader::new(1, CdcCommand::Status, 2, 0x12345678);
        let payload = vec![1u8, 2];
        let err = decode_frame(&header, &payload).expect_err("expected checksum error");
        assert!(matches!(err, FrameTransportError::ChecksumMismatch { .. }));
    }

    #[test]
    fn command_tables_match_variants() {
        let head = HostRequest::PullHead(PullHeadRequest {
            protocol_version: 1,
        });
        assert_eq!(command_for_request(&head), CdcCommand::PullHead);

        let vault = DeviceResponse::VaultChunk(VaultChunk {
            protocol_version: 1,
            sequence: 1,
            total_size: 0,
            remaining_bytes: 0,
            device_chunk_size: 0,
            data: vec![],
            checksum: 0,
            is_last: true,
            artifact: VaultArtifact::Vault,
        });
        assert_eq!(command_for_response(&vault), CdcCommand::PullVault);
    }
}
