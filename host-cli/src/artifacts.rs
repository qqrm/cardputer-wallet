use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use shared::error::SharedError;
use shared::journal::FrameState;
use shared::schema::{JournalFrame, VaultArtifact, VaultChunk};

use crate::constants::{RECIPIENTS_FILE, SIGNATURE_FILE, SYNC_STATE_FILE, VAULT_FILE};

pub mod memory;

/// Trait describing storage backends used while pulling vault artifacts from the device.
pub trait ArtifactStore {
    /// Configure whether recipients data should be collected during the transfer.
    fn set_recipients_expected(&mut self, expected: bool);

    /// Configure whether a vault signature is expected as part of the transfer.
    fn set_signature_expected(&mut self, expected: bool);

    /// Record an incoming vault chunk. Returns `true` when additional chunks are required.
    fn record_vault_chunk(&mut self, chunk: &VaultChunk) -> bool;

    /// Record an incoming journal frame for later inspection.
    fn record_journal_frame(&mut self, frame: &JournalFrame);

    /// Record an informational log entry about the pull lifecycle.
    fn record_log(&mut self, context: &str);

    /// Persist artifacts to the on-disk repository.
    fn persist(&self, repo: &Path) -> Result<(), SharedError>;

    /// Access the collected vault bytes.
    fn vault_bytes(&self) -> &[u8];

    /// Access the collected recipients manifest if present.
    fn recipients_bytes(&self) -> Option<&[u8]>;

    /// Access the collected signature, if one was transferred.
    fn signature_bytes(&self) -> Option<&[u8]>;

    /// Track whether a recipients manifest should be present in the transfer.
    fn recipients_expected(&self) -> bool;

    /// Track whether a recipients manifest has been observed in the transfer.
    fn recipients_seen(&self) -> bool;

    /// Track whether a signature should be present in the transfer.
    fn signature_expected(&self) -> bool;
}

#[derive(Default)]
pub struct PullArtifacts {
    pub(crate) vault: ArtifactBuffer,
    pub(crate) recipients: ArtifactBuffer,
    pub(crate) recipients_manifest: Option<Vec<u8>>,
    pub(crate) recipients_expected: bool,
    pub(crate) recipients_seen: bool,
    pub(crate) signature: ArtifactBuffer,
    pub(crate) signature_bytes: Option<Vec<u8>>,
    pub(crate) signature_expected: bool,
    pub(crate) signature_seen: bool,
    pub(crate) log_context: Vec<String>,
}

impl PullArtifacts {
    fn record_recipients_manifest(&mut self, data: &[u8]) {
        self.recipients_manifest = Some(data.to_vec());
    }
}

impl ArtifactStore for PullArtifacts {
    fn set_recipients_expected(&mut self, expected: bool) {
        self.recipients_expected = expected;
    }

    fn set_signature_expected(&mut self, expected: bool) {
        self.signature_expected = expected;
    }

    fn record_vault_chunk(&mut self, chunk: &VaultChunk) -> bool {
        match chunk.artifact {
            VaultArtifact::Vault => {
                self.vault.bytes.extend_from_slice(&chunk.data);
                self.vault
                    .metadata
                    .push(VaultChunkMetadata::from_chunk(chunk));
                if chunk.is_last {
                    if self.recipients_expected && !self.recipients_seen {
                        return true;
                    }
                    if self.signature_expected && !self.signature_seen {
                        return true;
                    }
                    return false;
                }
                true
            }
            VaultArtifact::Recipients => {
                if !self.recipients_seen || chunk.sequence == 1 {
                    self.recipients.bytes.clear();
                    self.recipients.metadata.clear();
                }
                self.recipients_seen = true;
                self.recipients.bytes.extend_from_slice(&chunk.data);
                self.recipients
                    .metadata
                    .push(VaultChunkMetadata::from_chunk(chunk));
                if chunk.is_last {
                    let data = self.recipients.bytes.clone();
                    self.record_recipients_manifest(&data);
                    if self.signature_expected && !self.signature_seen {
                        return true;
                    }
                    return false;
                }
                true
            }
            VaultArtifact::Signature => {
                if !self.signature_seen || chunk.sequence == 1 {
                    self.signature.bytes.clear();
                    self.signature.metadata.clear();
                }
                self.signature_seen = true;
                self.signature.bytes.extend_from_slice(&chunk.data);
                self.signature
                    .metadata
                    .push(VaultChunkMetadata::from_chunk(chunk));
                if chunk.is_last {
                    self.signature_bytes = Some(self.signature.bytes.clone());
                    return false;
                }
                true
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
        self.log_context.push(summary);
    }

    fn record_log(&mut self, context: &str) {
        self.log_context.push(context.into());
    }

    fn persist(&self, repo: &Path) -> Result<(), SharedError> {
        if self.vault.bytes.is_empty() && self.recipients_manifest.is_none() {
            return Ok(());
        }

        fs::create_dir_all(repo)
            .map_err(|err| io_error("create repository directory", repo, err))?;

        if !self.vault.bytes.is_empty() {
            let vault_path = repo.join(VAULT_FILE);
            if let Some(parent) = vault_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| io_error("prepare vault directory", parent, err))?;
            }
            fs::write(&vault_path, &self.vault.bytes)
                .map_err(|err| io_error("write vault artifact", &vault_path, err))?;
            println!("Saved vault artifact to '{}'.", vault_path.display());
        }

        if let Some(recipients) = &self.recipients_manifest {
            let recipients_path = repo.join(RECIPIENTS_FILE);
            if let Some(parent) = recipients_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| io_error("prepare recipients directory", parent, err))?;
            }
            fs::write(&recipients_path, recipients)
                .map_err(|err| io_error("write recipients artifact", &recipients_path, err))?;
            println!(
                "Saved recipients manifest to '{}'.",
                recipients_path.display()
            );
        }

        if let Some(signature) = &self.signature_bytes {
            let signature_path = repo.join(SIGNATURE_FILE);
            if let Some(parent) = signature_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| io_error("prepare signature directory", parent, err))?;
            }
            fs::write(&signature_path, signature)
                .map_err(|err| io_error("write signature artifact", &signature_path, err))?;
            println!("Saved vault signature to '{}'.", signature_path.display());
        }

        Ok(())
    }

    fn vault_bytes(&self) -> &[u8] {
        &self.vault.bytes
    }

    fn recipients_bytes(&self) -> Option<&[u8]> {
        self.recipients_seen
            .then_some(self.recipients.bytes.as_slice())
            .or_else(|| self.recipients_manifest.as_deref())
    }

    fn signature_bytes(&self) -> Option<&[u8]> {
        self.signature_bytes.as_deref().or_else(|| {
            self.signature_seen
                .then_some(self.signature.bytes.as_slice())
        })
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

#[derive(Default)]
pub(crate) struct ArtifactBuffer {
    pub(crate) bytes: Vec<u8>,
    pub(crate) metadata: Vec<VaultChunkMetadata>,
}

#[allow(dead_code)]
pub(crate) struct VaultChunkMetadata {
    protocol_version: u16,
    sequence: u32,
    total_size: u64,
    remaining_bytes: u64,
    device_chunk_size: u32,
    checksum: u32,
    is_last: bool,
}

impl VaultChunkMetadata {
    fn from_chunk(chunk: &VaultChunk) -> Self {
        Self {
            protocol_version: chunk.protocol_version,
            sequence: chunk.sequence,
            total_size: chunk.total_size,
            remaining_bytes: chunk.remaining_bytes,
            device_chunk_size: chunk.device_chunk_size,
            checksum: chunk.checksum,
            is_last: chunk.is_last,
        }
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
