use super::*;
use crate::sync::context::fresh_context;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

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
    let mut now = 0u64;

    loop {
        match ctx.unlock_with_pin(wrong_pin, now) {
            Err(PinUnlockError::Key(KeyError::CryptoFailure)) => now += 1_000,
            Err(PinUnlockError::Backoff { remaining_ms }) => {
                now += remaining_ms + 1;
                break;
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    ctx.unlock_with_pin(b"555555", now).expect("pin accepted");
    let status = ctx.pin_lock_status(now);
    assert_eq!(status.consecutive_failures, 0);
    assert!(status.backoff_remaining_ms.is_none());
}
