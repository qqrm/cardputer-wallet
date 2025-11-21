use alloc::vec::Vec;

use crate::cdc::compute_crc32;
use crate::checksum::accumulate_checksum;
use crate::schema::{VaultArtifact, VaultChunk};

use super::artifact_stream::ArtifactManifest;

#[derive(Debug, Clone, PartialEq)]
pub enum TransferError {
    ChecksumMismatch { expected: u32, calculated: u32 },
    MetadataMismatch(&'static str),
    OutOfOrder(VaultArtifact),
    UnexpectedArtifact(VaultArtifact),
    MissingArtifact(VaultArtifact),
}

impl core::fmt::Display for TransferError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransferError::ChecksumMismatch {
                expected,
                calculated,
            } => {
                write!(
                    f,
                    "chunk checksum 0x{calculated:08X} did not match expected 0x{expected:08X}"
                )
            }
            TransferError::MetadataMismatch(field) => {
                write!(f, "chunk metadata mismatch for {field}")
            }
            TransferError::OutOfOrder(artifact) => {
                write!(
                    f,
                    "received {artifact:?} chunk before finishing previous artifact"
                )
            }
            TransferError::UnexpectedArtifact(artifact) => {
                write!(f, "device sent unexpected {artifact:?} artifact")
            }
            TransferError::MissingArtifact(artifact) => {
                write!(f, "device omitted required {artifact:?} artifact")
            }
        }
    }
}

pub(crate) fn validate_and_ingest_chunk(
    buffer: &mut Vec<u8>,
    chunk: &VaultChunk,
) -> Result<(), TransferError> {
    let calculated = accumulate_checksum(0, &chunk.data);
    if calculated != chunk.checksum {
        return Err(TransferError::ChecksumMismatch {
            expected: chunk.checksum,
            calculated,
        });
    }

    let consumed = buffer.len() as u64;
    if chunk.total_size < consumed {
        return Err(TransferError::MetadataMismatch("total_size"));
    }
    let expected_remaining = chunk
        .total_size
        .saturating_sub(consumed + chunk.data.len() as u64);
    if expected_remaining != chunk.remaining_bytes {
        return Err(TransferError::MetadataMismatch("remaining_bytes"));
    }
    if (expected_remaining == 0) != chunk.is_last {
        return Err(TransferError::MetadataMismatch("is_last"));
    }

    buffer.extend_from_slice(&chunk.data);
    if chunk.is_last && buffer.len() as u64 != chunk.total_size {
        return Err(TransferError::MetadataMismatch("total_size"));
    }

    Ok(())
}

pub(crate) fn verify_hash(
    manifest: &ArtifactManifest,
    artifact: VaultArtifact,
    data: &[u8],
) -> Result<(), TransferError> {
    let expected = manifest.hash(artifact);

    let Some(expected_hash) = expected else {
        return Ok(());
    };

    if data.is_empty() {
        return Err(TransferError::MissingArtifact(artifact));
    }

    let checksum = compute_crc32(data);
    if expected_hash[..4] != checksum.to_le_bytes() {
        return Err(TransferError::MetadataMismatch("hash"));
    }

    Ok(())
}
