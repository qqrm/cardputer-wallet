use alloc::vec::Vec;

use crate::schema::{VaultArtifact, VaultChunk};

use super::artifact_stream::{ArtifactManifest, TransferState};
use super::checks::{TransferError, validate_and_ingest_chunk, verify_hash};

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
                validate_and_ingest_chunk(&mut self.vault, chunk)?;
                if chunk.is_last {
                    verify_hash(&self.manifest, VaultArtifact::Vault, &self.vault)?;
                }
            }
            VaultArtifact::Recipients => {
                if chunk.sequence == 1 {
                    self.recipients.clear();
                }
                validate_and_ingest_chunk(&mut self.recipients, chunk)?;
                self.recipients_seen = true;
                if chunk.is_last {
                    verify_hash(&self.manifest, VaultArtifact::Recipients, &self.recipients)?;
                }
            }
            VaultArtifact::Signature => {
                if chunk.sequence == 1 {
                    self.signature.clear();
                }
                validate_and_ingest_chunk(&mut self.signature, chunk)?;
                self.signature_seen = true;
                if chunk.is_last {
                    verify_hash(&self.manifest, VaultArtifact::Signature, &self.signature)?;
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
}

impl Default for ArtifactCollector {
    fn default() -> Self {
        Self::with_manifest(ArtifactManifest::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::accumulate_checksum;
    use crate::schema::PROTOCOL_VERSION;

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
