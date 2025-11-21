use std::fs;
use std::path::Path;

use ed25519_dalek::Signer;
use rand_core::{CryptoRng, OsRng, RngCore};
use serde_cbor::{from_slice as cbor_from_slice, to_vec as cbor_to_vec};
use shared::checksum::accumulate_checksum;
use shared::error::SharedError;
use shared::schema::{HostRequest, PROTOCOL_VERSION, PushVaultFrame, VaultArtifact};
use shared::vault::{
    EntryUpdate, JournalOperation as VaultJournalOperation, PageCipher, VaultEntry,
};

use crate::commands::host_config::{HostConfig, VaultSnapshot};
use crate::commands::signature::compute_signature_message;
use crate::commands::{DeviceTransport, RepoArtifactStore};
use crate::constants::{
    CONFIG_FILE, MAX_CHUNK_SIZE, RECIPIENTS_FILE, SIGNATURE_FILE, SIGNATURE_SIZE, VAULT_AAD,
    VAULT_FILE, VAULT_NONCE_SIZE,
};
use crate::transport::{CliResponseAdapter, RecordingResponseAdapter, send_host_request};

use super::frames::expect_ack;

pub(crate) fn push_vault_artifacts<T, S>(transport: &mut T, store: &S) -> Result<(), SharedError>
where
    T: DeviceTransport + ?Sized,
    S: RepoArtifactStore + ?Sized,
{
    let descriptors = [
        (VaultArtifact::Vault, "vault image"),
        (VaultArtifact::Recipients, "recipients manifest"),
        (VaultArtifact::Signature, "vault signature"),
    ];

    let mut cli_adapter = CliResponseAdapter;
    let mut recording_adapter = RecordingResponseAdapter::new(None, None);

    let mut sequence = 1u32;

    for (artifact, label) in descriptors.into_iter() {
        let Some(data) = store.load(artifact)? else {
            continue;
        };

        if matches!(artifact, VaultArtifact::Signature) && data.len() != SIGNATURE_SIZE {
            return Err(SharedError::Transport(format!(
                "signature artifact must be exactly {} bytes (found {})",
                SIGNATURE_SIZE,
                data.len()
            )));
        }

        println!(
            "Sending {label} ({} byte{}).",
            data.len(),
            if data.len() == 1 { "" } else { "s" }
        );

        let total_size = data.len() as u64;
        let chunk_size = MAX_CHUNK_SIZE as usize;
        let mut offset = 0usize;
        let mut first = true;

        while offset < data.len() || (first && data.is_empty()) {
            first = false;
            let end = (offset + chunk_size).min(data.len());
            let chunk = data[offset..end].to_vec();
            let remaining = total_size.saturating_sub(end as u64);
            offset = end;
            let checksum = accumulate_checksum(0, &chunk);

            let frame = PushVaultFrame {
                protocol_version: PROTOCOL_VERSION,
                sequence,
                artifact,
                total_size,
                remaining_bytes: remaining,
                data: chunk,
                checksum,
                is_last: remaining == 0,
            };
            sequence = sequence.saturating_add(1);

            let request = HostRequest::PushVault(frame);
            send_host_request(transport, &request)?;
            expect_ack(
                transport,
                &mut cli_adapter,
                &mut recording_adapter,
                &format!("pushing {label}"),
            )?;

            if remaining == 0 {
                break;
            }
        }
    }

    Ok(())
}

pub(crate) fn apply_operations_to_repo(
    repo: &Path,
    config: &HostConfig,
    operations: &[VaultJournalOperation],
) -> Result<(), SharedError> {
    if operations.is_empty() {
        return Ok(());
    }

    let vault_key = config
        .vault_key()
        .ok_or_else(|| SharedError::Transport("vault key missing from credentials".into()))?;

    let vault_path = repo.join(VAULT_FILE);
    let encrypted = fs::read(&vault_path).map_err(|err| {
        SharedError::Transport(format!(
            "failed to read vault from '{}': {err}",
            vault_path.display()
        ))
    })?;

    let mut snapshot = decrypt_vault(&encrypted, &vault_key)?;
    apply_vault_operations(&mut snapshot, operations)?;

    let mut rng = OsRng;
    let encrypted_vault = encrypt_vault_with_rng(&snapshot, &vault_key, &mut rng)?;
    fs::write(&vault_path, &encrypted_vault).map_err(|err| {
        SharedError::Transport(format!(
            "failed to write updated vault to '{}': {err}",
            vault_path.display()
        ))
    })?;

    let recipients_path = repo.join(RECIPIENTS_FILE);
    let recipients = if recipients_path.exists() {
        Some(fs::read(&recipients_path).map_err(|err| {
            SharedError::Transport(format!(
                "failed to read recipients manifest from '{}': {err}",
                recipients_path.display()
            ))
        })?)
    } else {
        None
    };

    let config_path = repo.join(CONFIG_FILE);
    let config_bytes = if config_path.exists() {
        Some(fs::read(&config_path).map_err(|err| {
            SharedError::Transport(format!(
                "failed to read config.json from '{}': {err}",
                config_path.display()
            ))
        })?)
    } else {
        None
    };

    let signing_key = config
        .signing_key()?
        .ok_or_else(|| SharedError::Transport("signing key missing from credentials".into()))?;

    let message = compute_signature_message(
        &encrypted_vault,
        recipients.as_deref(),
        config_bytes.as_deref(),
    );
    let signature = signing_key.sign(&message);

    let signature_path = repo.join(SIGNATURE_FILE);
    fs::write(signature_path, signature.to_bytes())
        .map_err(|err| SharedError::Transport(format!("failed to write vault signature: {err}")))?;

    Ok(())
}

fn apply_vault_operations(
    snapshot: &mut VaultSnapshot,
    operations: &[VaultJournalOperation],
) -> Result<(), SharedError> {
    for operation in operations {
        match operation {
            VaultJournalOperation::Add { entry } => {
                snapshot.entries.retain(|existing| existing.id != entry.id);
                snapshot.entries.push(entry.clone());
            }
            VaultJournalOperation::Update { id, changes } => {
                let entry = snapshot
                    .entries
                    .iter_mut()
                    .find(|item| &item.id == id)
                    .ok_or_else(|| {
                        SharedError::Transport(format!("cannot update unknown entry {}", id))
                    })?;
                apply_entry_update(entry, changes);
            }
            VaultJournalOperation::Delete { id } => {
                let before = snapshot.entries.len();
                snapshot.entries.retain(|entry| &entry.id != id);
                if snapshot.entries.len() == before {
                    return Err(SharedError::Transport(format!(
                        "cannot delete unknown entry {}",
                        id
                    )));
                }
            }
        }
    }

    Ok(())
}

fn apply_entry_update(entry: &mut VaultEntry, update: &EntryUpdate) {
    if let Some(value) = &update.title {
        entry.title = value.clone();
    }

    if let Some(value) = &update.service {
        entry.service = value.clone();
    }

    if let Some(value) = &update.domains {
        entry.domains = value.clone();
    }

    if let Some(value) = &update.username {
        entry.username = value.clone();
    }

    if let Some(value) = &update.password {
        entry.password = value.clone();
    }

    if let Some(value) = &update.totp {
        entry.totp = Some(value.clone());
    }

    if let Some(value) = &update.tags {
        entry.tags = value.clone();
    }

    if let Some(value) = &update.r#macro {
        entry.r#macro = Some(value.clone());
    }

    if let Some(value) = &update.updated_at {
        entry.updated_at = value.clone();
    }

    if let Some(value) = &update.used_at {
        entry.used_at = value.clone();
    }
}

pub(crate) fn decrypt_vault(data: &[u8], key: &[u8; 32]) -> Result<VaultSnapshot, SharedError> {
    if data.len() < VAULT_NONCE_SIZE {
        return Err(SharedError::Transport(
            "vault payload too small to contain nonce".into(),
        ));
    }

    let (nonce_bytes, ciphertext) = data.split_at(VAULT_NONCE_SIZE);
    let nonce: [u8; VAULT_NONCE_SIZE] = nonce_bytes
        .try_into()
        .expect("nonce slice has fixed length");

    let cipher = PageCipher::chacha20_poly1305(*key);
    let plaintext = cipher
        .decrypt(&nonce, VAULT_AAD, ciphertext)
        .map_err(|err| SharedError::Transport(format!("failed to decrypt vault: {err}")))?;

    cbor_from_slice(&plaintext)
        .map_err(|err| SharedError::Transport(format!("invalid vault format: {err}")))
}

pub(crate) fn encrypt_vault_with_rng<R>(
    snapshot: &VaultSnapshot,
    key: &[u8; 32],
    rng: &mut R,
) -> Result<Vec<u8>, SharedError>
where
    R: RngCore + CryptoRng,
{
    let plaintext = cbor_to_vec(snapshot)
        .map_err(|err| SharedError::Transport(format!("failed to encode vault snapshot: {err}")))?;
    let cipher = PageCipher::chacha20_poly1305(*key);
    let mut nonce = [0u8; VAULT_NONCE_SIZE];
    rng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(&nonce, VAULT_AAD, &plaintext)
        .map_err(|err| SharedError::Transport(format!("failed to encrypt vault: {err}")))?;

    let mut buffer = Vec::with_capacity(VAULT_NONCE_SIZE + ciphertext.len());
    buffer.extend_from_slice(&nonce);
    buffer.extend_from_slice(&ciphertext);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::schema::{AckResponse, DeviceResponse, PROTOCOL_VERSION, VaultArtifact};

    use crate::test_support::{InMemoryArtifactStore, MockPort, encode_response};

    #[test]
    fn push_vault_artifacts_respects_acknowledgements() {
        let ack = encode_response(DeviceResponse::Ack(AckResponse {
            protocol_version: PROTOCOL_VERSION,
            message: "ok".into(),
        }));

        let mut transport = MockPort::new(ack);
        let mut store = InMemoryArtifactStore::default();
        store.set(VaultArtifact::Vault, vec![0x01]);

        push_vault_artifacts(&mut transport, &store).expect("push artifacts");
    }
}
