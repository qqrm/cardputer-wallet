use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use shared::error::SharedError;
use shared::journal::FrameState;
use shared::schema::{JournalFrame, VaultArtifact, VaultChunk};
use shared::transfer::ArtifactCollector;

use crate::constants::SYNC_STATE_FILE;

#[cfg(test)]
pub mod memory;

/// Trait describing storage backends used while pulling vault artifacts from the device.
pub trait ArtifactStore {
    /// Configure the expected hash for a given artifact.
    fn set_expected_hash(&mut self, artifact: VaultArtifact, hash: [u8; 32]);

    /// Configure whether recipients data should be collected during the transfer.
    fn set_recipients_expected(&mut self, expected: bool);

    /// Configure whether a vault signature is expected as part of the transfer.
    fn set_signature_expected(&mut self, expected: bool);

    /// Record an incoming vault chunk. Returns `true` when additional chunks are required.
    fn record_vault_chunk(&mut self, chunk: &VaultChunk) -> Result<bool, SharedError>;

    /// Record an incoming journal frame for later inspection.
    fn record_journal_frame(&mut self, frame: &JournalFrame);

    /// Record an informational log entry about the pull lifecycle.
    fn record_log(&mut self, context: &str);

    /// Access the collected vault bytes.
    fn vault_bytes(&self) -> &[u8];

    /// Access the collected recipients manifest if present.
    fn recipients_bytes(&self) -> Option<&[u8]>;

    /// Access the collected signature, if one was transferred.
    fn signature_bytes(&self) -> Option<&[u8]>;

    /// Track whether a signature should be present in the transfer.
    fn signature_expected(&self) -> bool;
}

#[derive(Default)]
pub struct PullArtifacts {
    collector: ArtifactCollector,
    pub(crate) log_context: Vec<String>,
}

impl PullArtifacts {
    pub fn recipients_expected(&self) -> bool {
        self.collector.recipients_expected()
    }

    pub fn recipients_received(&self) -> bool {
        self.collector.recipients_seen()
    }
}

impl ArtifactStore for PullArtifacts {
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
        self.log_context.push(summary);
    }

    fn record_log(&mut self, context: &str) {
        self.log_context.push(context.into());
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

pub(crate) fn io_error(context: &str, path: &Path, err: io::Error) -> SharedError {
    SharedError::Transport(format!("{context} at '{}': {err}", path.display()))
}

pub fn persist_sync_state(repo_path: &Path, state: Option<FrameState>) -> Result<(), SharedError> {
    let path = sync_state_path(repo_path);
    match state {
        Some(state) => {
            let content = format!("{}\n", state);
            fs::write(&path, content).map_err(|err| {
                SharedError::Transport(format!(
                    "failed to write sync state to '{}': {err}",
                    path.display()
                ))
            })?
        }
        None => match fs::remove_file(&path) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(SharedError::Transport(format!(
                    "failed to clear sync state at '{}': {err}",
                    path.display()
                )));
            }
        },
    }

    Ok(())
}

pub fn load_sync_state(repo_path: &Path) -> Result<Option<FrameState>, SharedError> {
    let path = sync_state_path(repo_path);
    let content = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(SharedError::Transport(format!(
                "failed to read sync state from '{}': {err}",
                path.display()
            )));
        }
    };

    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(SharedError::Transport(format!(
            "invalid sync state in '{}': empty content",
            path.display()
        )));
    }

    let state = trimmed.parse::<FrameState>().map_err(|err| {
        SharedError::Transport(format!("invalid sync state in '{}': {err}", path.display()))
    })?;

    Ok(Some(state))
}

fn sync_state_path(repo_path: &Path) -> PathBuf {
    repo_path.join(SYNC_STATE_FILE)
}
