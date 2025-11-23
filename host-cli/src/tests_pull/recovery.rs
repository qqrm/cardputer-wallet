use crate::commands;
use crate::constants::VAULT_FILE;
use crate::test_support::{
    InMemoryArtifactStore, InMemoryDeviceTransport, MockPort, SIGNATURE_SIZE, TEST_SIGNING_SEED,
    sign_artifacts, write_credentials_with_keys,
};
use ed25519_dalek::SigningKey;
use shared::error::SharedError;
use shared::schema::{DeviceResponse, PROTOCOL_VERSION, VaultArtifact};

use super::fixtures::{PullTestContext, encoded_responses, head_response, vault_chunk};

#[test]
fn pull_errors_when_expected_recipients_missing() {
    let ctx = PullTestContext::new("missing-recipients");

    let vault_payload = vec![1, 2, 3, 4];
    let recipients_payload = vec![9, 8, 7, 6];
    let vault_len = vault_payload.len() as u64;
    let responses = vec![
        DeviceResponse::Head(head_response(
            1,
            &vault_payload,
            Some(&recipients_payload),
            None,
            0x21,
        )),
        DeviceResponse::VaultChunk(vault_chunk(
            1,
            vault_len,
            0,
            vault_payload,
            true,
            VaultArtifact::Vault,
        )),
        DeviceResponse::Ack(shared::schema::AckResponse {
            protocol_version: PROTOCOL_VERSION,
            message: "complete".into(),
        }),
    ];

    let mut transport = InMemoryDeviceTransport::new(responses);
    let mut store = InMemoryArtifactStore::default();

    let err = commands::pull::run(&mut transport, &mut store, &ctx.args())
        .expect_err("expected recipients failure");
    match err {
        SharedError::Transport(message) => {
            assert!(message.contains("recipients manifest missing"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn pull_errors_when_signature_expected_without_verifying_key() {
    let ctx = PullTestContext::new("missing-key");
    let signing = SigningKey::from_bytes(&TEST_SIGNING_SEED);
    let vault_payload = vec![1, 2, 3, 4];
    let signature = sign_artifacts(&signing, &vault_payload, None, None);

    let responses = encoded_responses(&[
        DeviceResponse::Head(head_response(
            4,
            &vault_payload,
            None,
            Some(&signature),
            0x55,
        )),
        DeviceResponse::VaultChunk(vault_chunk(
            1,
            vault_payload.len() as u64,
            0,
            vault_payload.clone(),
            true,
            VaultArtifact::Vault,
        )),
        DeviceResponse::VaultChunk(vault_chunk(
            2,
            SIGNATURE_SIZE as u64,
            0,
            signature.clone(),
            true,
            VaultArtifact::Signature,
        )),
    ]);

    let mut port = MockPort::new(responses);
    let mut store = commands::FilesystemArtifactStore::new(ctx.repo_path());
    let err =
        commands::pull::run(&mut port, &mut store, &ctx.args()).expect_err("pull should fail");

    match err {
        SharedError::Transport(message) => {
            assert!(message.contains("verifying key is missing"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    assert!(
        !ctx.repo_path().join(VAULT_FILE).exists(),
        "vault should not be persisted on failure",
    );
}

#[test]
fn pull_errors_when_signature_verification_fails() {
    let ctx = PullTestContext::new("bad-signature");

    let signing = write_credentials_with_keys(ctx.credentials_path(), false, false);
    let vault_payload = vec![4, 3, 2, 1];
    let mut signature = sign_artifacts(&signing, &vault_payload, None, None);
    signature[0] ^= 0xFF;

    let responses = encoded_responses(&[
        DeviceResponse::Head(head_response(
            9,
            &vault_payload,
            None,
            Some(&signature),
            0x66,
        )),
        DeviceResponse::VaultChunk(vault_chunk(
            1,
            vault_payload.len() as u64,
            0,
            vault_payload.clone(),
            true,
            VaultArtifact::Vault,
        )),
        DeviceResponse::VaultChunk(vault_chunk(
            2,
            SIGNATURE_SIZE as u64,
            0,
            signature.clone(),
            true,
            VaultArtifact::Signature,
        )),
    ]);

    let mut port = MockPort::new(responses);
    let mut store = commands::FilesystemArtifactStore::new(ctx.repo_path());
    let err =
        commands::pull::run(&mut port, &mut store, &ctx.args()).expect_err("pull should fail");

    match err {
        SharedError::Transport(message) => {
            assert!(message.contains("vault signature verification failed"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    assert!(
        !ctx.repo_path().join(VAULT_FILE).exists(),
        "vault should not be persisted on failure",
    );
}
