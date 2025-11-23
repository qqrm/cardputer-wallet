use std::fs;
use std::path::Path;

use tempfile::TempDir;

use shared::schema::{
    DeviceResponse, PROTOCOL_VERSION, PullHeadResponse, VaultArtifact, VaultChunk,
};

use crate::RepoArgs;
use crate::constants::MAX_CHUNK_SIZE;
use crate::test_support::{
    chunk_checksum, encode_response, hash_with_crc, write_empty_credentials,
};

pub(super) struct PullTestContext {
    _temp: TempDir,
    args: RepoArgs,
}

impl PullTestContext {
    pub(super) fn new(repo_label: &str) -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join(repo_label).join("repo");
        fs::create_dir_all(&repo).expect("create repo directory");
        let credentials = temp.path().join("creds");
        write_empty_credentials(&credentials);

        Self {
            _temp: temp,
            args: RepoArgs {
                repo,
                credentials,
                signing_pubkey: None,
            },
        }
    }

    pub(super) fn args(&self) -> RepoArgs {
        self.args.clone()
    }

    pub(super) fn repo_path(&self) -> &Path {
        &self.args.repo
    }

    pub(super) fn credentials_path(&self) -> &Path {
        &self.args.credentials
    }
}

pub(super) fn head_response(
    vault_generation: u64,
    vault_payload: &[u8],
    recipients_payload: Option<&[u8]>,
    signature_payload: Option<&[u8]>,
    hash_seed: u8,
) -> PullHeadResponse {
    PullHeadResponse {
        protocol_version: PROTOCOL_VERSION,
        vault_generation,
        vault_hash: hash_with_crc(hash_seed, vault_payload),
        recipients_hash: recipients_payload
            .map(|payload| hash_with_crc(hash_seed ^ 0x55, payload))
            .unwrap_or([0u8; 32]),
        signature_hash: signature_payload
            .map(|payload| hash_with_crc(hash_seed ^ 0xAA, payload))
            .unwrap_or([0u8; 32]),
    }
}

pub(super) fn vault_chunk(
    sequence: u32,
    total_size: u64,
    remaining_bytes: u64,
    data: Vec<u8>,
    is_last: bool,
    artifact: VaultArtifact,
) -> VaultChunk {
    VaultChunk {
        protocol_version: PROTOCOL_VERSION,
        sequence,
        total_size,
        remaining_bytes,
        device_chunk_size: MAX_CHUNK_SIZE,
        data: data.clone(),
        checksum: chunk_checksum(&data),
        is_last,
        artifact,
    }
}

pub(super) fn encoded_responses(responses: &[DeviceResponse]) -> Vec<u8> {
    responses
        .iter()
        .flat_map(|response| encode_response(response.clone()))
        .collect()
}
