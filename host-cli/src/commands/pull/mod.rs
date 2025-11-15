use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use shared::error::SharedError;
use shared::journal::FrameTracker;
use shared::schema::{
    DeviceResponse, HostRequest, PROTOCOL_VERSION, PullHeadRequest, PullVaultRequest, VaultArtifact,
};

use crate::RepoArgs;
use crate::artifacts::{PullArtifacts, persist_sync_state};
use crate::commands::host_config::HostConfig;
use crate::commands::print_repo_banner;
use crate::commands::signature::compute_signature_message;
use crate::constants::{CONFIG_FILE, HOST_BUFFER_SIZE, MAX_CHUNK_SIZE, SIGNATURE_SIZE};
use crate::transport::{
    handle_device_response, print_head, read_device_response, send_host_request,
};

pub fn run<P>(port: &mut P, args: &RepoArgs) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    print_repo_banner(args);

    let config = HostConfig::load(&args.credentials)?;
    let verifying_key = load_verifying_key(&config, args.signing_pubkey.as_deref())?;

    let head_request = HostRequest::PullHead(PullHeadRequest {
        protocol_version: PROTOCOL_VERSION,
    });

    send_host_request(port, &head_request)?;
    println!("Requested head metadata. Awaiting response…");

    let mut artifacts = PullArtifacts::default();
    let head_response = read_device_response(port)?;
    let DeviceResponse::Head(head) = head_response else {
        handle_device_response(head_response, None, Some(&mut artifacts))?;
        return Err(SharedError::Transport(
            "unexpected device response while fetching head metadata".into(),
        ));
    };

    print_head(&head);
    artifacts.record_log("head response");
    artifacts.set_expected_hash(VaultArtifact::Vault, head.vault_hash);
    artifacts.set_expected_hash(VaultArtifact::Recipients, head.recipients_hash);
    artifacts.set_expected_hash(VaultArtifact::Signature, head.signature_hash);

    let request = HostRequest::PullVault(PullVaultRequest {
        protocol_version: PROTOCOL_VERSION,
        host_buffer_size: HOST_BUFFER_SIZE,
        max_chunk_size: MAX_CHUNK_SIZE,
        known_generation: None,
    });

    send_host_request(port, &request)?;
    println!("Request sent. Waiting for device responses…");

    let mut state_tracker = FrameTracker::default();
    let mut should_continue = true;

    while should_continue {
        let response = read_device_response(port)?;
        should_continue =
            handle_device_response(response, Some(&mut state_tracker), Some(&mut artifacts))?;
        if should_continue {
            send_host_request(port, &request)?;
        }
    }

    verify_pulled_signature(&artifacts, &args.repo, verifying_key.as_ref())?;
    artifacts.persist(&args.repo)?;
    persist_sync_state(&args.repo, state_tracker.state())
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
    artifacts: &PullArtifacts,
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

    let recipients = artifacts.recipients_manifest();

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
