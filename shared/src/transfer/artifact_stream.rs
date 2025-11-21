use alloc::borrow::Cow;
use core::cmp;

use crate::checksum::accumulate_checksum;
use crate::schema::{PROTOCOL_VERSION, VaultArtifact, VaultChunk};

use super::checks::TransferError;

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

    pub(crate) fn first(&self) -> Option<VaultArtifact> {
        self.sequence().next()
    }

    pub(crate) fn next_after(&self, artifact: VaultArtifact) -> Option<VaultArtifact> {
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
pub(crate) enum TransferState {
    Waiting(VaultArtifact),
    Completed,
}

impl TransferState {
    pub(crate) fn new(manifest: &ArtifactManifest) -> Self {
        manifest
            .first()
            .map(TransferState::Waiting)
            .unwrap_or(TransferState::Completed)
    }

    pub(crate) fn artifact_or_default(&self, last_artifact: VaultArtifact) -> VaultArtifact {
        match self {
            TransferState::Waiting(artifact) => *artifact,
            TransferState::Completed => last_artifact,
        }
    }

    pub(crate) fn ensure_expected(
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

    pub(crate) fn advance(
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
pub(crate) struct ArtifactOffsets {
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

#[derive(Debug)]
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

#[derive(Debug, Clone, Copy)]
pub struct PendingCommit {
    pub(crate) artifact: VaultArtifact,
    pub(crate) slice_end: usize,
    pub(crate) is_last: bool,
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
}
