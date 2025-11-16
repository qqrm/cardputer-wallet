use alloc::vec::Vec;
use core::cmp;

use crate::cdc::compute_crc32;
use crate::checksum::accumulate_checksum;
use crate::schema::{PROTOCOL_VERSION, VaultArtifact, VaultChunk};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactLengths {
    pub vault: usize,
    pub recipients: usize,
    pub signature: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferStage {
    Vault,
    Recipients,
    Signature,
    Complete,
}

impl TransferStage {
    fn first_with_lengths(lengths: ArtifactLengths) -> Self {
        if lengths.vault > 0 {
            TransferStage::Vault
        } else if lengths.recipients > 0 {
            TransferStage::Recipients
        } else if lengths.signature > 0 {
            TransferStage::Signature
        } else {
            TransferStage::Complete
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArtifactStream {
    vault_offset: usize,
    recipients_offset: usize,
    signature_offset: usize,
    stage: TransferStage,
    last_artifact: VaultArtifact,
}

impl ArtifactStream {
    pub const fn new() -> Self {
        Self {
            vault_offset: 0,
            recipients_offset: 0,
            signature_offset: 0,
            stage: TransferStage::Complete,
            last_artifact: VaultArtifact::Vault,
        }
    }

    pub fn reset(&mut self, lengths: ArtifactLengths) {
        self.vault_offset = 0;
        self.recipients_offset = 0;
        self.signature_offset = 0;
        self.stage = TransferStage::first_with_lengths(lengths);
        self.last_artifact = match self.stage {
            TransferStage::Vault => VaultArtifact::Vault,
            TransferStage::Recipients => VaultArtifact::Recipients,
            TransferStage::Signature => VaultArtifact::Signature,
            TransferStage::Complete => VaultArtifact::Vault,
        };
    }

    pub fn prepare_chunk<'a, F>(
        &'a self,
        sequence: u32,
        payload_limit: usize,
        device_chunk_size: u32,
        mut view: F,
    ) -> PendingChunk
    where
        F: FnMut(VaultArtifact) -> &'a [u8],
    {
        let artifact = match self.stage {
            TransferStage::Vault => VaultArtifact::Vault,
            TransferStage::Recipients => VaultArtifact::Recipients,
            TransferStage::Signature => VaultArtifact::Signature,
            TransferStage::Complete => self.last_artifact,
        };

        let buffer = view(artifact);
        let offset = match artifact {
            VaultArtifact::Vault => self.vault_offset,
            VaultArtifact::Recipients => self.recipients_offset,
            VaultArtifact::Signature => self.signature_offset,
        };

        let available = buffer.len().saturating_sub(offset);
        let chunk_size = cmp::min(payload_limit, available);
        let slice_end = offset + chunk_size;
        let payload = if chunk_size == 0 {
            Vec::new()
        } else {
            buffer[offset..slice_end].to_vec()
        };
        let remaining = buffer.len().saturating_sub(slice_end) as u64;
        let checksum = accumulate_checksum(0, &payload);
        let chunk = VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence,
            total_size: buffer.len() as u64,
            remaining_bytes: remaining,
            device_chunk_size,
            data: payload,
            checksum,
            is_last: remaining == 0,
            artifact,
        };

        let has_recipients = !view(VaultArtifact::Recipients).is_empty();
        let has_signature = !view(VaultArtifact::Signature).is_empty();

        PendingChunk {
            chunk,
            artifact,
            slice_end,
            has_recipients,
            has_signature,
        }
    }

    pub fn commit_chunk(&mut self, pending: PendingChunk) -> VaultChunk {
        match pending.artifact {
            VaultArtifact::Vault => {
                self.vault_offset = pending.slice_end;
            }
            VaultArtifact::Recipients => {
                self.recipients_offset = pending.slice_end;
            }
            VaultArtifact::Signature => {
                self.signature_offset = pending.slice_end;
            }
        }

        self.last_artifact = pending.artifact;
        let chunk = pending.chunk;

        if chunk.is_last {
            self.stage = match pending.artifact {
                VaultArtifact::Vault => {
                    if pending.has_recipients {
                        TransferStage::Recipients
                    } else if pending.has_signature {
                        TransferStage::Signature
                    } else {
                        TransferStage::Complete
                    }
                }
                VaultArtifact::Recipients => {
                    if pending.has_signature {
                        TransferStage::Signature
                    } else {
                        TransferStage::Complete
                    }
                }
                VaultArtifact::Signature => TransferStage::Complete,
            };
        } else {
            self.stage = match pending.artifact {
                VaultArtifact::Vault => TransferStage::Vault,
                VaultArtifact::Recipients => TransferStage::Recipients,
                VaultArtifact::Signature => TransferStage::Signature,
            };
        }

        chunk
    }
}

impl Default for ArtifactStream {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PendingChunk {
    chunk: VaultChunk,
    artifact: VaultArtifact,
    slice_end: usize,
    has_recipients: bool,
    has_signature: bool,
}

impl PendingChunk {
    pub fn chunk(&self) -> &VaultChunk {
        &self.chunk
    }

    pub fn into_chunk(self) -> VaultChunk {
        self.chunk
    }
}

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

pub struct ArtifactCollector {
    vault: Vec<u8>,
    recipients: Vec<u8>,
    signature: Vec<u8>,
    vault_hash: Option<[u8; 32]>,
    recipients_hash: Option<[u8; 32]>,
    signature_hash: Option<[u8; 32]>,
    recipients_expected: bool,
    signature_expected: bool,
    recipients_seen: bool,
    signature_seen: bool,
    stage: TransferStage,
}

impl ArtifactCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_recipients_expected(&mut self, expected: bool) {
        self.recipients_expected = expected;
    }

    pub fn set_signature_expected(&mut self, expected: bool) {
        self.signature_expected = expected;
    }

    pub fn set_expected_hash(&mut self, artifact: VaultArtifact, hash: [u8; 32]) {
        let hash_option = if hash != [0u8; 32] { Some(hash) } else { None };

        match artifact {
            VaultArtifact::Vault => {
                self.vault_hash = hash_option;
            }
            VaultArtifact::Recipients => {
                self.recipients_hash = hash_option;
                self.recipients_expected = hash_option.is_some();
            }
            VaultArtifact::Signature => {
                self.signature_hash = hash_option;
                self.signature_expected = hash_option.is_some();
            }
        }
    }

    pub fn record_chunk(&mut self, chunk: &VaultChunk) -> Result<bool, TransferError> {
        match chunk.artifact {
            VaultArtifact::Vault => {
                if !matches!(self.stage, TransferStage::Vault | TransferStage::Complete) {
                    return Err(TransferError::OutOfOrder(VaultArtifact::Vault));
                }
                self.stage = TransferStage::Vault;
                Self::ingest_chunk(&mut self.vault, chunk)?;
                if chunk.is_last {
                    self.verify_hash(VaultArtifact::Vault)?;
                    self.stage = if self.recipients_expected {
                        TransferStage::Recipients
                    } else if self.signature_expected {
                        TransferStage::Signature
                    } else {
                        TransferStage::Complete
                    };
                }
            }
            VaultArtifact::Recipients => {
                if !self.recipients_expected {
                    return Err(TransferError::UnexpectedArtifact(VaultArtifact::Recipients));
                }
                if !matches!(
                    self.stage,
                    TransferStage::Recipients | TransferStage::Complete
                ) {
                    return Err(TransferError::OutOfOrder(VaultArtifact::Recipients));
                }
                self.stage = TransferStage::Recipients;
                if chunk.sequence == 1 {
                    self.recipients.clear();
                }
                Self::ingest_chunk(&mut self.recipients, chunk)?;
                self.recipients_seen = true;
                if chunk.is_last {
                    self.verify_hash(VaultArtifact::Recipients)?;
                    self.stage = if self.signature_expected {
                        TransferStage::Signature
                    } else {
                        TransferStage::Complete
                    };
                }
            }
            VaultArtifact::Signature => {
                if !self.signature_expected {
                    return Err(TransferError::UnexpectedArtifact(VaultArtifact::Signature));
                }
                if !matches!(
                    self.stage,
                    TransferStage::Signature | TransferStage::Complete
                ) {
                    return Err(TransferError::OutOfOrder(VaultArtifact::Signature));
                }
                self.stage = TransferStage::Signature;
                if chunk.sequence == 1 {
                    self.signature.clear();
                }
                Self::ingest_chunk(&mut self.signature, chunk)?;
                self.signature_seen = true;
                if chunk.is_last {
                    self.verify_hash(VaultArtifact::Signature)?;
                    self.stage = TransferStage::Complete;
                }
            }
        }

        let transfer_complete = matches!(self.stage, TransferStage::Complete) && chunk.is_last;
        Ok(!transfer_complete)
    }

    pub fn vault_bytes(&self) -> &[u8] {
        &self.vault
    }

    pub fn recipients_bytes(&self) -> Option<&[u8]> {
        self.recipients_seen.then_some(self.recipients.as_slice())
    }

    pub fn signature_bytes(&self) -> Option<&[u8]> {
        self.signature_seen.then_some(self.signature.as_slice())
    }

    pub fn recipients_expected(&self) -> bool {
        self.recipients_expected
    }

    pub fn recipients_seen(&self) -> bool {
        self.recipients_seen
    }

    pub fn signature_expected(&self) -> bool {
        self.signature_expected
    }

    pub fn signature_seen(&self) -> bool {
        self.signature_seen
    }

    fn ingest_chunk(buffer: &mut Vec<u8>, chunk: &VaultChunk) -> Result<(), TransferError> {
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

    fn verify_hash(&self, artifact: VaultArtifact) -> Result<(), TransferError> {
        let expected = match artifact {
            VaultArtifact::Vault => self.vault_hash,
            VaultArtifact::Recipients => self.recipients_hash,
            VaultArtifact::Signature => self.signature_hash,
        };

        let Some(expected_hash) = expected else {
            return Ok(());
        };

        let data = match artifact {
            VaultArtifact::Vault => &self.vault,
            VaultArtifact::Recipients => &self.recipients,
            VaultArtifact::Signature => &self.signature,
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
}

impl Default for ArtifactCollector {
    fn default() -> Self {
        Self {
            vault: Vec::new(),
            recipients: Vec::new(),
            signature: Vec::new(),
            vault_hash: None,
            recipients_hash: None,
            signature_hash: None,
            recipients_expected: false,
            signature_expected: false,
            recipients_seen: false,
            signature_seen: false,
            stage: TransferStage::Vault,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_chunk(
        artifact: VaultArtifact,
        data: &[u8],
        sequence: u32,
        is_last: bool,
    ) -> VaultChunk {
        let total = if is_last {
            data.len() as u64
        } else {
            data.len() as u64 + 1
        };
        let remaining = total.saturating_sub(data.len() as u64);
        VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence,
            total_size: total,
            remaining_bytes: remaining,
            device_chunk_size: data.len() as u32,
            data: data.to_vec(),
            checksum: accumulate_checksum(0, data),
            is_last,
            artifact,
        }
    }

    #[test]
    fn collector_detects_out_of_order_chunks() {
        let mut collector = ArtifactCollector::new();
        collector.set_expected_hash(VaultArtifact::Recipients, [1; 32]);
        let chunk = make_chunk(VaultArtifact::Recipients, b"recips", 1, true);
        let err = collector
            .record_chunk(&chunk)
            .expect_err("expected failure");
        assert!(matches!(
            err,
            TransferError::OutOfOrder(VaultArtifact::Recipients)
        ));
    }

    #[test]
    fn collector_detects_checksum_error() {
        let mut collector = ArtifactCollector::new();
        let mut chunk = make_chunk(VaultArtifact::Vault, b"vault", 1, false);
        chunk.checksum ^= 0xFFFF;
        let err = collector
            .record_chunk(&chunk)
            .expect_err("expected checksum");
        assert!(matches!(err, TransferError::ChecksumMismatch { .. }));
    }

    #[test]
    fn collector_detects_metadata_mismatch() {
        let mut collector = ArtifactCollector::new();
        let mut chunk = make_chunk(VaultArtifact::Vault, b"vault", 1, true);
        chunk.remaining_bytes = 5;
        let err = collector
            .record_chunk(&chunk)
            .expect_err("expected metadata error");
        assert!(matches!(
            err,
            TransferError::MetadataMismatch("remaining_bytes")
        ));
    }
}
