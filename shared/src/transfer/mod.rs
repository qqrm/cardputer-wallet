use alloc::borrow::Cow;
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
struct ArtifactSpec {
    expected: bool,
    hash: Option<[u8; 32]>,
}

impl ArtifactSpec {
    const fn new(expected: bool) -> Self {
        Self {
            expected,
            hash: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactManifest {
    vault: ArtifactSpec,
    recipients: ArtifactSpec,
    signature: ArtifactSpec,
}

impl ArtifactManifest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_lengths(lengths: ArtifactLengths) -> Self {
        let mut manifest = ArtifactManifest {
            vault: ArtifactSpec::new(lengths.vault > 0),
            ..ArtifactManifest::new()
        };
        manifest.set_expected(VaultArtifact::Recipients, lengths.recipients > 0);
        manifest.set_expected(VaultArtifact::Signature, lengths.signature > 0);
        manifest
    }

    pub fn set_expected(&mut self, artifact: VaultArtifact, expected: bool) {
        if matches!(artifact, VaultArtifact::Vault) {
            return;
        }

        self.spec_mut(artifact).expected = expected;
    }

    pub fn set_hash(&mut self, artifact: VaultArtifact, hash: [u8; 32]) {
        let spec = self.spec_mut(artifact);
        spec.hash = (hash != [0u8; 32]).then_some(hash);
        if matches!(artifact, VaultArtifact::Vault) {
            return;
        }

        spec.expected |= spec.hash.is_some();
    }

    pub fn hash(&self, artifact: VaultArtifact) -> Option<[u8; 32]> {
        self.spec(artifact).hash
    }

    pub fn expected(&self, artifact: VaultArtifact) -> bool {
        self.spec(artifact).expected
    }

    fn spec(&self, artifact: VaultArtifact) -> &ArtifactSpec {
        match artifact {
            VaultArtifact::Vault => &self.vault,
            VaultArtifact::Recipients => &self.recipients,
            VaultArtifact::Signature => &self.signature,
        }
    }

    fn spec_mut(&mut self, artifact: VaultArtifact) -> &mut ArtifactSpec {
        match artifact {
            VaultArtifact::Vault => &mut self.vault,
            VaultArtifact::Recipients => &mut self.recipients,
            VaultArtifact::Signature => &mut self.signature,
        }
    }

    fn sequence(&self) -> impl Iterator<Item = VaultArtifact> + '_ {
        [
            VaultArtifact::Vault,
            VaultArtifact::Recipients,
            VaultArtifact::Signature,
        ]
        .into_iter()
        .filter(|artifact| self.expected(*artifact))
    }

    fn first(&self) -> Option<VaultArtifact> {
        self.sequence().next()
    }

    fn next_after(&self, artifact: VaultArtifact) -> Option<VaultArtifact> {
        let mut iter = self.sequence();
        while let Some(current) = iter.next() {
            if current == artifact {
                return iter.next();
            }
        }

        None
    }
}

impl Default for ArtifactManifest {
    fn default() -> Self {
        Self {
            vault: ArtifactSpec::new(true),
            recipients: ArtifactSpec::new(false),
            signature: ArtifactSpec::new(false),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum TransferState {
    Waiting(VaultArtifact),
    Completed,
}

impl TransferState {
    fn new(manifest: &ArtifactManifest) -> Self {
        manifest
            .first()
            .map(TransferState::Waiting)
            .unwrap_or(TransferState::Completed)
    }

    fn artifact_or_default(&self, last_artifact: VaultArtifact) -> VaultArtifact {
        match self {
            TransferState::Waiting(artifact) => *artifact,
            TransferState::Completed => last_artifact,
        }
    }

    fn ensure_expected(
        &self,
        manifest: &ArtifactManifest,
        artifact: VaultArtifact,
    ) -> Result<(), TransferError> {
        match self {
            TransferState::Waiting(expected) if *expected == artifact => Ok(()),
            TransferState::Waiting(_) if manifest.expected(artifact) => {
                Err(TransferError::OutOfOrder(artifact))
            }
            TransferState::Waiting(_) => Err(TransferError::UnexpectedArtifact(artifact)),
            TransferState::Completed => Err(TransferError::UnexpectedArtifact(artifact)),
        }
    }

    fn advance(
        self,
        manifest: &ArtifactManifest,
        artifact: VaultArtifact,
        chunk_complete: bool,
    ) -> Self {
        if !chunk_complete {
            return TransferState::Waiting(artifact);
        }

        manifest
            .next_after(artifact)
            .map(TransferState::Waiting)
            .unwrap_or(TransferState::Completed)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ArtifactOffsets {
    vault: usize,
    recipients: usize,
    signature: usize,
}

impl ArtifactOffsets {
    fn offset(&self, artifact: VaultArtifact) -> usize {
        match artifact {
            VaultArtifact::Vault => self.vault,
            VaultArtifact::Recipients => self.recipients,
            VaultArtifact::Signature => self.signature,
        }
    }

    fn update(&mut self, artifact: VaultArtifact, next_offset: usize) {
        match artifact {
            VaultArtifact::Vault => self.vault = next_offset,
            VaultArtifact::Recipients => self.recipients = next_offset,
            VaultArtifact::Signature => self.signature = next_offset,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArtifactStream {
    offsets: ArtifactOffsets,
    manifest: ArtifactManifest,
    state: TransferState,
    last_artifact: VaultArtifact,
}

impl ArtifactStream {
    pub const fn new() -> Self {
        Self {
            offsets: ArtifactOffsets {
                vault: 0,
                recipients: 0,
                signature: 0,
            },
            manifest: ArtifactManifest {
                vault: ArtifactSpec {
                    expected: true,
                    hash: None,
                },
                recipients: ArtifactSpec {
                    expected: false,
                    hash: None,
                },
                signature: ArtifactSpec {
                    expected: false,
                    hash: None,
                },
            },
            state: TransferState::Completed,
            last_artifact: VaultArtifact::Vault,
        }
    }

    pub fn reset(&mut self, lengths: ArtifactLengths) {
        self.offsets = ArtifactOffsets::default();
        self.manifest = ArtifactManifest::from_lengths(lengths);
        self.state = TransferState::new(&self.manifest);
        self.last_artifact = self.manifest.first().unwrap_or(VaultArtifact::Vault);
    }

    pub fn prepare_chunk<'a, F>(
        &'a self,
        sequence: u32,
        payload_limit: usize,
        device_chunk_size: u32,
        mut view: F,
    ) -> PendingChunk<'a>
    where
        F: FnMut(VaultArtifact) -> &'a [u8],
    {
        let artifact = self.state.artifact_or_default(self.last_artifact);

        let buffer = view(artifact);
        let offset = self.offsets.offset(artifact);

        let available = buffer.len().saturating_sub(offset);
        let chunk_size = cmp::min(payload_limit, available);
        let slice_end = offset + chunk_size;
        let payload = Cow::Borrowed(if chunk_size == 0 {
            &[] as &[u8]
        } else {
            &buffer[offset..slice_end]
        });
        let remaining = buffer.len().saturating_sub(slice_end) as u64;
        let checksum = accumulate_checksum(0, payload.as_ref());
        let is_last = remaining == 0;

        PendingChunk {
            payload,
            sequence,
            total_size: buffer.len() as u64,
            remaining_bytes: remaining,
            device_chunk_size,
            checksum,
            is_last,
            artifact,
            slice_end,
        }
    }

    pub fn commit_chunk(&mut self, chunk: VaultChunk, commit: PendingCommit) -> VaultChunk {
        self.offsets.update(commit.artifact, commit.slice_end);

        self.last_artifact = commit.artifact;
        self.state = self
            .state
            .advance(&self.manifest, commit.artifact, commit.is_last);

        chunk
    }
}

impl Default for ArtifactStream {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PendingChunk<'a> {
    payload: Cow<'a, [u8]>,
    sequence: u32,
    total_size: u64,
    remaining_bytes: u64,
    device_chunk_size: u32,
    checksum: u32,
    is_last: bool,
    artifact: VaultArtifact,
    slice_end: usize,
}

impl<'a> PendingChunk<'a> {
    pub fn artifact(&self) -> VaultArtifact {
        self.artifact
    }

    pub fn payload(&self) -> &[u8] {
        self.payload.as_ref()
    }

    pub fn into_chunk(self) -> (VaultChunk, PendingCommit) {
        let chunk = VaultChunk {
            protocol_version: PROTOCOL_VERSION,
            sequence: self.sequence,
            total_size: self.total_size,
            remaining_bytes: self.remaining_bytes,
            device_chunk_size: self.device_chunk_size,
            data: self.payload.into_owned(),
            checksum: self.checksum,
            is_last: self.is_last,
            artifact: self.artifact,
        };

        let commit = PendingCommit {
            artifact: self.artifact,
            slice_end: self.slice_end,
            is_last: self.is_last,
        };

        (chunk, commit)
    }
}

pub struct PendingCommit {
    artifact: VaultArtifact,
    slice_end: usize,
    is_last: bool,
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
    manifest: ArtifactManifest,
    state: TransferState,
    vault: Vec<u8>,
    recipients: Vec<u8>,
    signature: Vec<u8>,
    recipients_seen: bool,
    signature_seen: bool,
}

impl ArtifactCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_manifest(manifest: ArtifactManifest) -> Self {
        let state = TransferState::new(&manifest);
        Self {
            manifest,
            state,
            vault: Vec::new(),
            recipients: Vec::new(),
            signature: Vec::new(),
            recipients_seen: false,
            signature_seen: false,
        }
    }

    pub fn set_recipients_expected(&mut self, expected: bool) {
        self.manifest
            .set_expected(VaultArtifact::Recipients, expected);
    }

    pub fn set_signature_expected(&mut self, expected: bool) {
        self.manifest
            .set_expected(VaultArtifact::Signature, expected);
    }

    pub fn set_expected_hash(&mut self, artifact: VaultArtifact, hash: [u8; 32]) {
        self.manifest.set_hash(artifact, hash);
    }

    pub fn record_chunk(&mut self, chunk: &VaultChunk) -> Result<bool, TransferError> {
        self.state.ensure_expected(&self.manifest, chunk.artifact)?;

        match chunk.artifact {
            VaultArtifact::Vault => {
                Self::ingest_chunk(&mut self.vault, chunk)?;
                if chunk.is_last {
                    self.verify_hash(VaultArtifact::Vault)?;
                }
            }
            VaultArtifact::Recipients => {
                if chunk.sequence == 1 {
                    self.recipients.clear();
                }
                Self::ingest_chunk(&mut self.recipients, chunk)?;
                self.recipients_seen = true;
                if chunk.is_last {
                    self.verify_hash(VaultArtifact::Recipients)?;
                }
            }
            VaultArtifact::Signature => {
                if chunk.sequence == 1 {
                    self.signature.clear();
                }
                Self::ingest_chunk(&mut self.signature, chunk)?;
                self.signature_seen = true;
                if chunk.is_last {
                    self.verify_hash(VaultArtifact::Signature)?;
                }
            }
        }

        self.state = self
            .state
            .advance(&self.manifest, chunk.artifact, chunk.is_last);

        Ok(!matches!(self.state, TransferState::Completed))
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
        self.manifest.expected(VaultArtifact::Recipients)
    }

    pub fn recipients_seen(&self) -> bool {
        self.recipients_seen
    }

    pub fn signature_expected(&self) -> bool {
        self.manifest.expected(VaultArtifact::Signature)
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
        let expected = self.manifest.hash(artifact);

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
        Self::with_manifest(ArtifactManifest::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_chunk_borrows_empty_payload() {
        let mut stream = ArtifactStream::new();
        stream.reset(ArtifactLengths {
            vault: 3,
            recipients: 0,
            signature: 0,
        });

        let payload = b"abc";
        let pending = stream.prepare_chunk(1, 0, 8, |_| payload);

        assert!(matches!(&pending.payload, Cow::Borrowed(_)));
        assert_eq!(pending.artifact(), VaultArtifact::Vault);
        assert_eq!(pending.payload(), &[]);

        let (chunk, commit) = pending.into_chunk();
        assert_eq!(chunk.total_size, payload.len() as u64);
        assert_eq!(chunk.remaining_bytes, payload.len() as u64);
        assert!(!chunk.is_last);
        assert!(chunk.data.is_empty());

        let chunk = stream.commit_chunk(chunk, commit);
        assert!(chunk.data.is_empty());
    }

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

    #[test]
    fn collector_rejects_unexpected_artifact() {
        let mut collector = ArtifactCollector::new();
        let chunk = make_chunk(VaultArtifact::Recipients, b"recips", 1, true);
        let err = collector
            .record_chunk(&chunk)
            .expect_err("should reject unexpected recipients chunk");
        assert!(matches!(
            err,
            TransferError::UnexpectedArtifact(VaultArtifact::Recipients)
        ));
    }

    #[test]
    fn collector_rejects_skipped_recipients() {
        let mut collector = ArtifactCollector::new();
        collector.set_recipients_expected(true);
        collector.set_signature_expected(true);

        let vault_chunk = make_chunk(VaultArtifact::Vault, b"vault", 1, true);
        assert!(
            collector
                .record_chunk(&vault_chunk)
                .expect("should record vault chunk")
        );

        let signature_chunk = make_chunk(VaultArtifact::Signature, b"sig", 1, true);
        let err = collector
            .record_chunk(&signature_chunk)
            .expect_err("should require recipients before signature");
        assert!(matches!(
            err,
            TransferError::OutOfOrder(VaultArtifact::Signature)
        ));
    }

    #[test]
    fn collector_reports_missing_expected_artifact() {
        let mut collector = ArtifactCollector::new();
        collector.set_signature_expected(true);
        collector.set_expected_hash(VaultArtifact::Signature, [1; 32]);

        let vault_chunk = make_chunk(VaultArtifact::Vault, b"vault", 1, true);
        assert!(
            collector
                .record_chunk(&vault_chunk)
                .expect("should record vault chunk")
        );

        let signature_chunk = make_chunk(VaultArtifact::Signature, b"", 1, true);
        let err = collector
            .record_chunk(&signature_chunk)
            .expect_err("should require signature payload");
        assert!(matches!(
            err,
            TransferError::MissingArtifact(VaultArtifact::Signature)
        ));
    }

    #[test]
    fn collector_rejects_additional_chunks_after_completion() {
        let mut collector = ArtifactCollector::new();
        let vault_chunk = make_chunk(VaultArtifact::Vault, b"vault", 1, true);
        assert!(
            !collector
                .record_chunk(&vault_chunk)
                .expect("should finish after vault")
        );

        let extra_chunk = make_chunk(VaultArtifact::Vault, b"v", 1, true);
        let err = collector
            .record_chunk(&extra_chunk)
            .expect_err("should reject trailing chunk");
        assert!(matches!(
            err,
            TransferError::UnexpectedArtifact(VaultArtifact::Vault)
        ));
    }
}
