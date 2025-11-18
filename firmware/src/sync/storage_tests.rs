use super::*;
use crate::storage::initialize_context_from_flash;
use crate::sync::context::fresh_context;
use postcard::to_allocvec as postcard_to_allocvec;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sequential_storage::mock_flash::{MockFlashBase, WriteCountCheck};
use sequential_storage::{cache::NoCache, map};
use shared::schema::{
    DeviceResponse, HostRequest, PROTOCOL_VERSION, PullHeadRequest, decode_device_response,
    encode_host_request, encode_journal_operations,
};

#[test]
fn initial_context_loaded_before_request_handling() {
    type Flash = MockFlashBase<16, 4, 1024>;
    let mut flash = Flash::new(WriteCountCheck::Twice, None, false);
    let range = Flash::FULL_FLASH_RANGE;
    let mut cache = NoCache::new();
    let mut buffer = vec![0u8; STORAGE_DATA_BUFFER_CAPACITY];

    futures::executor::block_on(async {
        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &STORAGE_KEY_GENERATION,
            &42u64,
        )
        .await
        .unwrap();

        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &STORAGE_KEY_VAULT,
            &Vec::from(&b"flash-vault"[..]),
        )
        .await
        .unwrap();
    });

    let mut ctx = futures::executor::block_on(initialize_context_from_flash(&mut flash, range))
        .expect("context from flash");

    let request = HostRequest::PullHead(PullHeadRequest {
        protocol_version: PROTOCOL_VERSION,
    });
    let encoded = encode_host_request(&request).unwrap();
    let (command, response_bytes) =
        process_host_frame(CdcCommand::PullHead, &encoded, &mut ctx).unwrap();
    assert_eq!(command, CdcCommand::PullHead);

    let response = decode_device_response(&response_bytes).unwrap();
    match response {
        DeviceResponse::Head(head) => {
            assert_eq!(head.vault_generation, 42);
            assert!(!ctx.vault_image.is_empty());
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn initialize_context_from_flash_propagates_errors() {
    type Flash = MockFlashBase<16, 4, 1024>;
    let mut flash = Flash::new(WriteCountCheck::Twice, None, false);
    let range = Flash::FULL_FLASH_RANGE;
    let mut cache = NoCache::new();
    let mut buffer = vec![0u8; STORAGE_DATA_BUFFER_CAPACITY];

    futures::executor::block_on(async {
        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &STORAGE_KEY_VAULT_KEYS,
            &[0x01],
        )
        .await
        .unwrap();
    });

    let error =
        futures::executor::block_on(initialize_context_from_flash(&mut flash, range.clone()))
            .expect_err("corrupted key record should fail");

    match error {
        StorageError::Decode(message) => {
            assert!(message.contains("failed to decode key record"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn load_from_flash_rejects_oversized_vault_image() {
    let oversized_vault = vec![0xAA; VAULT_BUFFER_CAPACITY + 1];
    let error = SyncContext::validate_flash_blob::<()>(
        oversized_vault,
        VAULT_BUFFER_CAPACITY,
        "vault image",
    )
    .expect_err("oversized vault should be rejected");

    match error {
        StorageError::Decode(message) => {
            assert!(message.contains("vault image exceeds capacity"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn load_from_flash_rejects_oversized_recipients_manifest() {
    let oversized_recipients = vec![0xBB; RECIPIENTS_BUFFER_CAPACITY + 1];
    let error = SyncContext::validate_flash_blob::<()>(
        oversized_recipients,
        RECIPIENTS_BUFFER_CAPACITY,
        "recipients manifest",
    )
    .expect_err("oversized recipients should be rejected");

    match error {
        StorageError::Decode(message) => {
            assert!(message.contains("recipients manifest exceeds capacity"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn load_from_flash_rejects_oversized_signature() {
    let oversized_signature = vec![0xCC; SIGNATURE_BUFFER_CAPACITY + 1];
    let error = SyncContext::validate_signature_blob::<()>(oversized_signature)
        .expect_err("oversized signature should be rejected");

    match error {
        StorageError::Decode(message) => {
            assert!(message.contains("signature exceeds capacity"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn load_from_flash_rejects_partial_signature() {
    let partial_signature = vec![0xDD; SIGNATURE_BUFFER_CAPACITY - 1];
    let error = SyncContext::validate_signature_blob::<()>(partial_signature)
        .expect_err("incomplete signature should be rejected");

    match error {
        StorageError::Decode(message) => {
            assert!(message.contains("signature must be exactly"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn load_from_flash_restores_key_material() {
    type Flash = MockFlashBase<16, 4, 1024>;
    let mut flash = Flash::new(WriteCountCheck::Twice, None, false);
    let range = Flash::FULL_FLASH_RANGE;
    let mut cache = NoCache::new();
    let mut buffer = vec![0u8; STORAGE_DATA_BUFFER_CAPACITY];

    let mut ctx = fresh_context();
    let pin = b"111111";
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    ctx.crypto.wrap_new_keys(pin, &mut rng).unwrap();
    let record = ctx.crypto.record().expect("key record");
    let encoded_record = postcard_to_allocvec(&record).unwrap();

    futures::executor::block_on(async {
        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &STORAGE_KEY_VAULT,
            &Vec::from(&b"vault-image"[..]),
        )
        .await
        .unwrap();

        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &STORAGE_KEY_RECIPIENTS,
            &Vec::from(&b"recipients"[..]),
        )
        .await
        .unwrap();

        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &STORAGE_KEY_SIGNATURE,
            &vec![0xAB; SIGNATURE_BUFFER_CAPACITY],
        )
        .await
        .unwrap();

        let journal_bytes = encode_journal_operations(&[JournalOperation::Add {
            entry_id: String::from("flash-entry"),
        }])
        .unwrap();

        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &STORAGE_KEY_JOURNAL,
            &journal_bytes,
        )
        .await
        .unwrap();

        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &STORAGE_KEY_GENERATION,
            &7u64,
        )
        .await
        .unwrap();

        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &STORAGE_KEY_VAULT_KEYS,
            &encoded_record,
        )
        .await
        .unwrap();
    });

    let mut ctx = fresh_context();
    futures::executor::block_on(ctx.load_from_flash(&mut flash, range)).unwrap();

    assert_eq!(ctx.vault_image.as_slice(), b"vault-image");
    assert_eq!(ctx.recipients_manifest.as_slice(), b"recipients");
    assert_eq!(ctx.signature.as_slice(), &[0xAB; SIGNATURE_BUFFER_CAPACITY]);
    assert_eq!(ctx.vault_generation, 7);
    assert_eq!(ctx.journal_ops.len(), 1);

    ctx.crypto.unlock_vault_key(pin).unwrap();
    let payload = b"record-data".to_vec();
    let mut session_rng = ChaCha20Rng::from_seed([0x55; 32]);
    let (nonce, ciphertext) = ctx
        .crypto
        .encrypt_record(&mut session_rng, &payload)
        .unwrap();
    let roundtrip = ctx.crypto.decrypt_record(&nonce, &ciphertext).unwrap();
    assert_eq!(roundtrip, payload);
}
