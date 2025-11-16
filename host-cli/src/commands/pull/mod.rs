use std::fs;
use std::path::Path;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use shared::error::SharedError;
use shared::journal::FrameTracker;
use shared::schema::{
    DeviceResponse, HostRequest, PROTOCOL_VERSION, PullHeadRequest, PullVaultRequest, VaultArtifact,
};

use crate::RepoArgs;
use crate::artifacts::{ArtifactStore as DeviceArtifactStore, PullArtifacts, persist_sync_state};
use crate::commands::host_config::HostConfig;
use crate::commands::signature::compute_signature_message;
use crate::commands::{ArtifactStore as RepoArtifactStore, DeviceTransport, print_repo_banner};
use crate::constants::{CONFIG_FILE, HOST_BUFFER_SIZE, MAX_CHUNK_SIZE, SIGNATURE_SIZE};
use crate::transport::{handle_device_response, print_head};

pub fn run<T, S>(transport: &mut T, store: &mut S, args: &RepoArgs) -> Result<(), SharedError>
where
    T: DeviceTransport + ?Sized,
    S: RepoArtifactStore + ?Sized,
{
    print_repo_banner(args);

    let config = HostConfig::load(&args.credentials)?;
    let verifying_key = load_verifying_key(&config, args.signing_pubkey.as_deref())?;

    let head_request = HostRequest::PullHead(PullHeadRequest {
        protocol_version: PROTOCOL_VERSION,
    });

    transport.send(&head_request)?;
    println!("Requested head metadata. Awaiting response…");

    let mut artifacts = PullArtifacts::default();
    let head_response = transport.receive()?;
    let DeviceResponse::Head(head) = head_response else {
        handle_device_response(head_response, None, Some(&mut artifacts))?;
        return Err(SharedError::Transport(
            "unexpected device response while fetching head metadata".into(),
        ));
    };

    print_head(&head);
    DeviceArtifactStore::record_log(&mut artifacts, "head response");
    let recipients_expected = head.recipients_hash != [0u8; 32];
    DeviceArtifactStore::set_recipients_expected(&mut artifacts, recipients_expected);
    let signature_expected = head.signature_hash != [0u8; 32];
    DeviceArtifactStore::set_signature_expected(&mut artifacts, signature_expected);

    let request = HostRequest::PullVault(PullVaultRequest {
        protocol_version: PROTOCOL_VERSION,
        host_buffer_size: HOST_BUFFER_SIZE,
        max_chunk_size: MAX_CHUNK_SIZE,
        known_generation: None,
    });

    transport.send(&request)?;
    println!("Request sent. Waiting for device responses…");

    let mut state_tracker = FrameTracker::default();
    let mut should_continue = true;

    while should_continue {
        let response = transport.receive()?;
        should_continue =
            handle_device_response(response, Some(&mut state_tracker), Some(&mut artifacts))?;
        if should_continue {
            transport.send(&request)?;
        }
    }

    ensure_expected_recipients(&artifacts)?;
    verify_pulled_signature(&artifacts, &args.repo, verifying_key.as_ref())?;
    persist_artifacts(store, &artifacts)?;
    persist_sync_state(&args.repo, state_tracker.state())
}

fn ensure_expected_recipients(artifacts: &impl DeviceArtifactStore) -> Result<(), SharedError> {
    if artifacts.recipients_expected() && !artifacts.recipients_seen() {
        return Err(SharedError::Transport(
            "recipients manifest missing from transfer".into(),
        ));
    }

    Ok(())
}

fn persist_artifacts<S>(
    store: &mut S,
    artifacts: &impl DeviceArtifactStore,
) -> Result<(), SharedError>
where
    S: RepoArtifactStore + ?Sized,
{
    if !artifacts.vault_bytes().is_empty() {
        store.persist(VaultArtifact::Vault, artifacts.vault_bytes())?;
    }

    if let Some(recipients) = artifacts.recipients_bytes() {
        store.persist(VaultArtifact::Recipients, recipients)?;
    }

    if let Some(signature) = artifacts.signature_bytes() {
        store.persist(VaultArtifact::Signature, signature)?;
    }

    Ok(())
}

fn load_verifying_key(
    config: &HostConfig,
    override_path: Option<&Path>,
) -> Result<Option<VerifyingKey>, SharedError> {
    if let Some(path) = override_path {
        let raw = fs::read_to_string(path).map_err(|err| {
            SharedError::Transport(format!(
                "failed to read verifying key from '{}': {err}",
                path.display()
            ))
        })?;
        let decoded =
            crate::commands::host_config::decode_key_bytes::<{ SIGNATURE_SIZE / 2 }>(raw.trim())?;
        return VerifyingKey::from_bytes(&decoded)
            .map(Some)
            .map_err(|err| SharedError::Transport(format!("invalid verifying key: {err}")));
    }

    config.verifying_key()
}

fn verify_pulled_signature(
    artifacts: &impl DeviceArtifactStore,
    repo: &Path,
    verifying_key: Option<&VerifyingKey>,
) -> Result<(), SharedError> {
    if artifacts.vault_bytes().is_empty() || !artifacts.signature_expected() {
        return Ok(());
    }

    let key = verifying_key.ok_or_else(|| {
        SharedError::Transport(
            "signature verification requested but verifying key is missing".into(),
        )
    })?;

    let signature_bytes = artifacts
        .signature_bytes()
        .ok_or_else(|| SharedError::Transport("vault signature missing from transfer".into()))?;

    let array: [u8; SIGNATURE_SIZE] = signature_bytes
        .try_into()
        .map_err(|_| SharedError::Transport("invalid vault signature length".into()))?;
    let signature = Signature::from_bytes(&array);

    let recipients = artifacts.recipients_bytes();

    let config_path = repo.join(CONFIG_FILE);
    let config_bytes = if config_path.exists() {
        Some(fs::read(&config_path).map_err(|err| {
            SharedError::Transport(format!(
                "failed to read config.json for signature verification: {err}"
            ))
        })?)
    } else {
        None
    };

    let message =
        compute_signature_message(artifacts.vault_bytes(), recipients, config_bytes.as_deref());

    key.verify(&message, &signature).map_err(|err| {
        SharedError::Transport(format!("vault signature verification failed: {err}"))
    })
}
