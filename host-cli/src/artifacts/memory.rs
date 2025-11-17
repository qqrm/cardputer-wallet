use shared::error::SharedError;
use shared::schema::{JournalFrame, VaultArtifact, VaultChunk};
use shared::transfer::ArtifactCollector;

use super::TransferArtifactStore;

/// Minimal in-memory artifact store used for unit tests.
#[derive(Default)]
pub struct MemoryArtifactStore {
    collector: ArtifactCollector,
    pub logs: Vec<String>,
    pub journal_entries: Vec<String>,
}

impl MemoryArtifactStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TransferArtifactStore for MemoryArtifactStore {
    fn set_expected_hash(&mut self, artifact: VaultArtifact, hash: [u8; 32]) {
        self.collector.set_expected_hash(artifact, hash);
    }

    fn set_recipients_expected(&mut self, expected: bool) {
        self.collector.set_recipients_expected(expected);
    }

    fn set_signature_expected(&mut self, expected: bool) {
        self.collector.set_signature_expected(expected);
    }

    fn record_vault_chunk(&mut self, chunk: &VaultChunk) -> Result<bool, SharedError> {
        self.collector
            .record_chunk(chunk)
            .map_err(|err| SharedError::Transport(format!("failed to record vault chunk: {err}")))
    }

    fn record_journal_frame(&mut self, frame: &JournalFrame) {
        let summary = format!(
            "journal frame #{sequence} with {operations} operations and {remaining} pending",
            sequence = frame.sequence,
            operations = frame.operations.len(),
            remaining = frame.remaining_operations,
        );
        self.journal_entries.push(summary);
    }

    fn record_log(&mut self, context: &str) {
        self.logs.push(context.to_owned());
    }

    fn vault_bytes(&self) -> &[u8] {
        self.collector.vault_bytes()
    }

    fn recipients_bytes(&self) -> Option<&[u8]> {
        self.collector.recipients_bytes()
    }

    fn signature_bytes(&self) -> Option<&[u8]> {
        self.collector.signature_bytes()
    }

    fn signature_expected(&self) -> bool {
        self.collector.signature_expected()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::checksum::accumulate_checksum;
    use shared::schema::{JournalFrame, VaultChunk};

    #[test]
    fn stores_vault_and_recipients() {
        let mut store = MemoryArtifactStore::new();
        store.set_recipients_expected(true);
        store.set_signature_expected(true);

        let mut chunk = VaultChunk {
            protocol_version: 1,
            sequence: 1,
            total_size: 5,
            remaining_bytes: 0,
            device_chunk_size: 5,
            data: b"vault".to_vec(),
            checksum: accumulate_checksum(0, b"vault"),
            is_last: true,
            artifact: VaultArtifact::Vault,
        };
        assert!(
            store
                .record_vault_chunk(&chunk)
                .expect("record vault chunk")
        );

        chunk = VaultChunk {
            protocol_version: 1,
            sequence: 1,
            total_size: 10,
            remaining_bytes: 0,
            device_chunk_size: 10,
            data: b"recipients".to_vec(),
            checksum: accumulate_checksum(0, b"recipients"),
            is_last: true,
            artifact: VaultArtifact::Recipients,
        };
        assert!(
            store
                .record_vault_chunk(&chunk)
                .expect("record recipients chunk")
        );

        chunk = VaultChunk {
            protocol_version: 1,
            sequence: 1,
            total_size: 9,
            remaining_bytes: 0,
            device_chunk_size: 9,
            data: b"signature".to_vec(),
            checksum: accumulate_checksum(0, b"signature"),
            is_last: true,
            artifact: VaultArtifact::Signature,
        };
        assert!(
            !store
                .record_vault_chunk(&chunk)
                .expect("record signature chunk")
        );

        assert_eq!(store.vault_bytes(), b"vault");
        assert_eq!(store.recipients_bytes(), Some(b"recipients".as_ref()));
        assert_eq!(store.signature_bytes(), Some(b"signature".as_ref()));
    }

    #[test]
    fn logs_journal_frames() {
        let mut store = MemoryArtifactStore::new();
        let frame = JournalFrame {
            protocol_version: 1,
            sequence: 2,
            checksum: 0,
            remaining_operations: 1,
            operations: vec![],
        };
        store.record_journal_frame(&frame);
        assert_eq!(store.journal_entries.len(), 1);
    }
}
