use alloc::{string::String, vec::Vec};

use super::{storage, *};
use crate::crypto::{CryptoMaterial, KeyError, PinUnlockError};
use crate::storage::StorageError;
use crate::sync::test_helpers::fresh_context;
use futures::executor::block_on;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sequential_storage::mock_flash::{MockFlashBase, WriteCountCheck};
use sequential_storage::{cache::NoCache, map};
use shared::cdc::CdcCommand;
use shared::schema::{
    DeviceResponse, HostRequest, JournalOperation, PROTOCOL_VERSION, PullHeadRequest,
    decode_device_response, encode_host_request, encode_journal_operations,
};

#[test]
fn load_from_flash_populates_context() {
    type Flash = MockFlashBase<16, 4, 1_048_576>;
    let mut flash = Flash::new(WriteCountCheck::Twice, None, false);
    let range = Flash::FULL_FLASH_RANGE;
    let mut cache = NoCache::new();
    let mut buffer = vec![0u8; storage::STORAGE_DATA_BUFFER_CAPACITY];

    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let pin = b"123456";
    let mut crypto = CryptoMaterial::default();
    crypto.wrap_new_keys(pin, &mut rng).unwrap();
    let key_record = crypto.record().expect("key record");
    let encoded_record = postcard::to_allocvec(&key_record).unwrap();

    block_on(async {
        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &storage::STORAGE_KEY_VAULT,
            &Vec::from(&b"vault-image"[..]),
        )
        .await
        .unwrap();

        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &storage::STORAGE_KEY_RECIPIENTS,
            &Vec::from(&b"recipients"[..]),
        )
        .await
        .unwrap();

        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &storage::STORAGE_KEY_SIGNATURE,
            &Vec::from(&[0xAB; SIGNATURE_BUFFER_CAPACITY]),
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
            &storage::STORAGE_KEY_JOURNAL,
            &journal_bytes,
        )
        .await
        .unwrap();

        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &storage::STORAGE_KEY_GENERATION,
            &7u64,
        )
        .await
        .unwrap();

        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &storage::STORAGE_KEY_VAULT_KEYS,
            &encoded_record,
        )
        .await
        .unwrap();
    });

    let mut ctx = fresh_context();
    block_on(ctx.load_from_flash(&mut flash, range)).unwrap();

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

#[test]
fn initial_context_loaded_before_request_handling() {
    type Flash = MockFlashBase<16, 4, 1024>;
    let mut flash = Flash::new(WriteCountCheck::Twice, None, false);
    let range = Flash::FULL_FLASH_RANGE;
    let mut cache = NoCache::new();
    let mut buffer = vec![0u8; storage::STORAGE_DATA_BUFFER_CAPACITY];

    block_on(async {
        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &storage::STORAGE_KEY_GENERATION,
            &42u64,
        )
        .await
        .unwrap();

        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &storage::STORAGE_KEY_VAULT,
            &Vec::from(&b"flash-vault"[..]),
        )
        .await
        .unwrap();
    });

    let mut ctx = block_on(crate::storage::initialize_context_from_flash(
        &mut flash, range,
    ))
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
    let mut buffer = vec![0u8; storage::STORAGE_DATA_BUFFER_CAPACITY];

    block_on(async {
        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &storage::STORAGE_KEY_VAULT_KEYS,
            &[0x01],
        )
        .await
        .unwrap();
    });

    let error = block_on(crate::storage::initialize_context_from_flash(
        &mut flash, range,
    ))
    .expect_err("expected decode error");
    assert!(matches!(error, StorageError::Decode(_)));
}

#[test]
fn load_from_flash_rejects_oversized_vault_image() {
    type Flash = MockFlashBase<16, 4, 1_048_576>;
    let mut flash = Flash::new(WriteCountCheck::Twice, None, false);
    let range = Flash::FULL_FLASH_RANGE;
    let mut cache = NoCache::new();
    let mut buffer = vec![0u8; storage::STORAGE_DATA_BUFFER_CAPACITY];

    block_on(async {
        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &storage::STORAGE_KEY_VAULT,
            &vec![0xAA; VAULT_BUFFER_CAPACITY + 1],
        )
        .await
        .unwrap();
    });

    let mut ctx = fresh_context();
    let error = block_on(ctx.load_from_flash(&mut flash, range)).expect_err("oversized vault");
    assert!(matches!(error, StorageError::Decode(_)));
}

#[test]
fn load_from_flash_rejects_oversized_recipients_manifest() {
    type Flash = MockFlashBase<16, 4, 1_048_576>;
    let mut flash = Flash::new(WriteCountCheck::Twice, None, false);
    let range = Flash::FULL_FLASH_RANGE;
    let mut cache = NoCache::new();
    let mut buffer = vec![0u8; storage::STORAGE_DATA_BUFFER_CAPACITY];

    block_on(async {
        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &storage::STORAGE_KEY_RECIPIENTS,
            &vec![0xBB; RECIPIENTS_BUFFER_CAPACITY + 1],
        )
        .await
        .unwrap();
    });

    let mut ctx = fresh_context();
    let error = block_on(ctx.load_from_flash(&mut flash, range)).expect_err("oversized recips");
    assert!(matches!(error, StorageError::Decode(_)));
}

#[test]
fn load_from_flash_rejects_oversized_signature() {
    type Flash = MockFlashBase<16, 4, 1_048_576>;
    let mut flash = Flash::new(WriteCountCheck::Twice, None, false);
    let range = Flash::FULL_FLASH_RANGE;
    let mut cache = NoCache::new();
    let mut buffer = vec![0u8; storage::STORAGE_DATA_BUFFER_CAPACITY];

    block_on(async {
        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &storage::STORAGE_KEY_SIGNATURE,
            &vec![0xCC; SIGNATURE_BUFFER_CAPACITY + 1],
        )
        .await
        .unwrap();
    });

    let mut ctx = fresh_context();
    let error = block_on(ctx.load_from_flash(&mut flash, range)).expect_err("oversized sig");
    assert!(matches!(error, StorageError::Decode(_)));
}

#[test]
fn load_from_flash_rejects_partial_signature() {
    type Flash = MockFlashBase<16, 4, 1_048_576>;
    let mut flash = Flash::new(WriteCountCheck::Twice, None, false);
    let range = Flash::FULL_FLASH_RANGE;
    let mut cache = NoCache::new();
    let mut buffer = vec![0u8; storage::STORAGE_DATA_BUFFER_CAPACITY];

    block_on(async {
        map::store_item(
            &mut flash,
            range.clone(),
            &mut cache,
            buffer.as_mut_slice(),
            &storage::STORAGE_KEY_SIGNATURE,
            &vec![0xDD; SIGNATURE_BUFFER_CAPACITY - 1],
        )
        .await
        .unwrap();
    });

    let mut ctx = fresh_context();
    let error = block_on(ctx.load_from_flash(&mut flash, range)).expect_err("partial sig");
    assert!(matches!(error, StorageError::Decode(_)));
}

#[test]
fn wrap_new_keys_and_wipe_clears_sensitive_state() {
    let mut ctx = fresh_context();
    ctx.vault_image.extend_from_slice(b"data");
    ctx.recipients_manifest.extend_from_slice(b"recips");
    ctx.signature
        .extend_from_slice(&[0xEE; SIGNATURE_BUFFER_CAPACITY]);

    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    ctx.crypto.wrap_new_keys(b"222222", &mut rng).unwrap();
    ctx.crypto.unlock_vault_key(b"222222").unwrap();

    assert!(ctx.crypto.vault_key().is_ok());
    assert!(ctx.crypto.device_private_key().is_ok());
    assert!(ctx.crypto.device_public_key().is_some());

    ctx.wipe_sensitive();

    assert!(ctx.crypto.vault_key().is_err());
    assert!(ctx.crypto.device_private_key().is_err());
    assert!(ctx.vault_image.is_empty());
    assert!(ctx.recipients_manifest.is_empty());
    assert!(ctx.signature.is_empty());
}

#[test]
fn unlock_with_wrong_pin_is_rejected() {
    let mut ctx = fresh_context();
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    ctx.crypto.wrap_new_keys(b"123456", &mut rng).unwrap();
    ctx.crypto.wipe();

    let error = ctx
        .crypto
        .unlock_vault_key(b"654321")
        .expect_err("wrong PIN should not decrypt");
    assert_eq!(error, KeyError::CryptoFailure);
    assert!(ctx.crypto.vault_key().is_err());
}

#[test]
fn device_key_is_unlocked_with_correct_pin() {
    let mut ctx = fresh_context();
    let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
    ctx.crypto.wrap_new_keys(b"333333", &mut rng).unwrap();
    let public = ctx
        .crypto
        .device_public_key()
        .expect("public key available");
    assert_ne!(public, [0u8; 32]);
    ctx.crypto.wipe();

    ctx.unlock_with_pin(b"333333", 0).expect("unlock succeeds");
    let private = ctx.crypto.device_private_key().expect("private key");
    assert_ne!(private.as_ref(), &[0u8; 32]);
}

#[test]
fn pin_failures_apply_backoff_and_wipe() {
    let mut ctx = fresh_context();
    let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
    ctx.crypto.wrap_new_keys(b"444444", &mut rng).unwrap();
    ctx.crypto.wipe();

    let mut now = 0u64;
    let wrong_pin = b"000000";
    loop {
        match ctx.unlock_with_pin(wrong_pin, now) {
            Err(PinUnlockError::Key(KeyError::CryptoFailure)) => {
                now = now.saturating_add(500);
            }
            Err(PinUnlockError::Backoff { remaining_ms }) => {
                now = now.saturating_add(remaining_ms + 1);
            }
            Err(PinUnlockError::WipeRequired) => {
                break;
            }
            other => panic!("unexpected unlock result: {other:?}"),
        }
    }

    let mut status = ctx.pin_lock_status(now);
    if let Some(remaining) = status.backoff_remaining_ms {
        status = ctx.pin_lock_status(now.saturating_add(remaining + 1));
    }
    assert!(status.total_failures >= crate::crypto::PIN_WIPE_THRESHOLD);
    assert!(status.wipe_required);
    assert!(status.backoff_remaining_ms.is_none());
}

#[test]
fn wipe_lockout_blocks_subsequent_successful_pin() {
    let mut ctx = fresh_context();
    let mut rng = ChaCha20Rng::from_seed([15u8; 32]);
    ctx.crypto.wrap_new_keys(b"666666", &mut rng).unwrap();
    ctx.crypto.wipe();

    let mut now = 0u64;
    let wrong_pin = b"000000";

    loop {
        match ctx.unlock_with_pin(wrong_pin, now) {
            Err(PinUnlockError::Key(KeyError::CryptoFailure)) => now += 250,
            Err(PinUnlockError::Backoff { remaining_ms }) => now += remaining_ms + 1,
            Err(PinUnlockError::WipeRequired) => break,
            other => panic!("unexpected unlock result: {other:?}"),
        }
    }

    let error = ctx
        .unlock_with_pin(b"666666", now)
        .expect_err("wipe lockout should reject correct PIN");
    assert_eq!(error, PinUnlockError::WipeRequired);
    assert!(ctx.crypto.vault_key().is_err());
}

#[test]
fn successful_pin_resets_backoff() {
    let mut ctx = fresh_context();
    let mut rng = ChaCha20Rng::from_seed([14u8; 32]);
    ctx.crypto.wrap_new_keys(b"555555", &mut rng).unwrap();
    ctx.crypto.wipe();

    let wrong_pin = b"000000";
    assert!(matches!(
        ctx.unlock_with_pin(wrong_pin, 0),
        Err(PinUnlockError::Key(KeyError::CryptoFailure))
    ));
    let status = ctx.pin_lock_status(0);
    assert!(status.backoff_remaining_ms.is_some());

    ctx.unlock_with_pin(b"555555", 1_000).expect("unlock");
    let status_after = ctx.pin_lock_status(1_000);
    assert!(status_after.backoff_remaining_ms.is_none());
}
