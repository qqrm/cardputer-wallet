use shared::error::SharedError;
use shared::schema::{JournalFrame, VaultArtifact, VaultChunk};

use super::ArtifactStore;

/// Minimal in-memory artifact store used for unit tests.
#[derive(Default)]
pub struct MemoryArtifactStore {
    vault: Vec<u8>,
    recipients: Vec<u8>,
    signature: Vec<u8>,
    recipients_expected: bool,
    recipients_seen: bool,
    signature_expected: bool,
    signature_seen: bool,
    pub logs: Vec<String>,
    pub journal_entries: Vec<String>,
}

impl MemoryArtifactStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactStore for MemoryArtifactStore {
    fn set_recipients_expected(&mut self, expected: bool) {
        self.recipients_expected = expected;
    }

    fn set_signature_expected(&mut self, expected: bool) {
        self.signature_expected = expected;
    }

    fn record_vault_chunk(&mut self, chunk: &VaultChunk) -> Result<bool, SharedError> {
        match chunk.artifact {
            VaultArtifact::Vault => {
                self.vault.extend_from_slice(&chunk.data);
                if chunk.is_last {
                    if self.recipients_expected && !self.recipients_seen {
                        return Ok(true);
                    }
                    if self.signature_expected && !self.signature_seen {
                        return Ok(true);
                    }
                    return Ok(false);
                }
                Ok(true)
            }
            VaultArtifact::Recipients => {
                if chunk.sequence == 1 {
                    self.recipients.clear();
                }
                self.recipients_seen = true;
                self.recipients.extend_from_slice(&chunk.data);
                if chunk.is_last {
                    if self.signature_expected && !self.signature_seen {
                        return Ok(true);
                    }
                    return Ok(false);
                }
                Ok(true)
            }
            VaultArtifact::Signature => {
                if chunk.sequence == 1 {
                    self.signature.clear();
                }
                self.signature_seen = true;
                self.signature.extend_from_slice(&chunk.data);
                Ok(!chunk.is_last)
            }
        }
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
        &self.vault
    }

    fn recipients_bytes(&self) -> Option<&[u8]> {
        self.recipients_seen.then_some(self.recipients.as_slice())
    }

    fn signature_bytes(&self) -> Option<&[u8]> {
        self.signature_seen.then_some(self.signature.as_slice())
    }

    fn recipients_expected(&self) -> bool {
        self.recipients_expected
    }

    fn recipients_seen(&self) -> bool {
        self.recipients_seen
    }

    fn signature_expected(&self) -> bool {
        self.signature_expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            checksum: 0,
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
            checksum: 0,
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
            checksum: 0,
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
