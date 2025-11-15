use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use shared::error::SharedError;
use shared::journal::FrameState;
use shared::schema::{JournalFrame, VaultArtifact, VaultChunk};
use shared::transfer::ArtifactCollector;

use crate::constants::{RECIPIENTS_FILE, SIGNATURE_FILE, SYNC_STATE_FILE, VAULT_FILE};

#[derive(Default)]
pub struct PullArtifacts {
    collector: ArtifactCollector,
    pub(crate) log_context: Vec<String>,
}

impl PullArtifacts {
    pub fn set_expected_hash(&mut self, artifact: VaultArtifact, hash: [u8; 32]) {
        self.collector.set_expected_hash(artifact, hash);
    }

    pub fn record_vault_chunk(&mut self, chunk: &VaultChunk) -> Result<bool, SharedError> {
        self.collector
            .record_chunk(chunk)
            .map_err(|err| SharedError::Transport(err.to_string()))
    }

    pub fn record_journal_frame(&mut self, frame: &JournalFrame) {
        let summary = format!(
            "journal frame #{sequence} with {operations} operations and {remaining} pending",
            sequence = frame.sequence,
            operations = frame.operations.len(),
            remaining = frame.remaining_operations,
        );
        self.log_context.push(summary);
    }

    pub fn record_log(&mut self, context: impl Into<String>) {
        self.log_context.push(context.into());
    }

    pub fn persist(&self, repo: &Path) -> Result<(), SharedError> {
        if self.collector.vault_bytes().is_empty() && self.collector.recipients_bytes().is_none() {
            return Ok(());
        }

        fs::create_dir_all(repo)
            .map_err(|err| io_error("create repository directory", repo, err))?;

        let vault_bytes = self.collector.vault_bytes();
        if !vault_bytes.is_empty() {
            let vault_path = repo.join(VAULT_FILE);
            if let Some(parent) = vault_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| io_error("prepare vault directory", parent, err))?;
            }
            fs::write(&vault_path, vault_bytes)
                .map_err(|err| io_error("write vault artifact", &vault_path, err))?;
            println!("Saved vault artifact to '{}'.", vault_path.display());
        }

        if let Some(recipients) = self.collector.recipients_bytes() {
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

        if let Some(signature) = self.collector.signature_bytes() {
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

    pub fn vault_bytes(&self) -> &[u8] {
        self.collector.vault_bytes()
    }

    pub fn recipients_manifest(&self) -> Option<&[u8]> {
        self.collector.recipients_bytes()
    }

    pub fn signature_bytes(&self) -> Option<&[u8]> {
        self.collector.signature_bytes()
    }

    pub fn signature_expected(&self) -> bool {
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
