use alloc::{format, string::String, vec::Vec};

use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
#[cfg(any(test, feature = "ui-tests"))]
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::{KeyError, PinLockStatus, PinUnlockError};

#[cfg(any(test, feature = "ui-tests"))]
use shared::schema::JournalOperation;
use shared::schema::{DeviceErrorCode, NackResponse, PROTOCOL_VERSION};

use super::{SIGNATURE_BUFFER_CAPACITY, SyncContext, VAULT_SIGNATURE_PUBLIC_KEY};

impl SyncContext {
    pub fn unlock_with_pin(&mut self, pin: &[u8], now_ms: u64) -> Result<(), PinUnlockError> {
        if self.pin_lock.wipe_pending() {
            return Err(PinUnlockError::WipeRequired);
        }

        if let Some(remaining) = self.pin_lock.remaining_backoff(now_ms) {
            return Err(PinUnlockError::Backoff {
                remaining_ms: remaining,
            });
        }

        match self.crypto.unlock_vault_key(pin) {
            Ok(()) => {
                self.pin_lock.register_success();
                Ok(())
            }
            Err(err) => {
                if matches!(err, KeyError::CryptoFailure) {
                    self.pin_lock.register_failure(now_ms);
                    if self.pin_lock.wipe_pending() {
                        return Err(PinUnlockError::WipeRequired);
                    }
                    if let Some(remaining) = self.pin_lock.remaining_backoff(now_ms)
                        && remaining > 0
                    {
                        return Err(PinUnlockError::Backoff {
                            remaining_ms: remaining,
                        });
                    }
                }
                Err(PinUnlockError::Key(err))
            }
        }
    }

    pub fn pin_lock_status(&self, now_ms: u64) -> PinLockStatus {
        self.pin_lock.status(now_ms)
    }

    pub fn wipe_sensitive(&mut self) {
        self.vault_image.iter_mut().for_each(|byte| *byte = 0);
        self.vault_image.clear();

        self.recipients_manifest
            .iter_mut()
            .for_each(|byte| *byte = 0);
        self.recipients_manifest.clear();

        self.signature.iter_mut().for_each(|byte| *byte = 0);
        self.signature.clear();
        self.expected_signature = None;
        self.reset_incoming_state();

        self.crypto.wipe();
        self.reset_transfer_state();
        self.frame_tracker.clear();
    }

    pub(crate) fn reset_incoming_state(&mut self) {
        self.incoming_vault.iter_mut().for_each(|byte| *byte = 0);
        self.incoming_vault.clear();
        self.incoming_recipients
            .iter_mut()
            .for_each(|byte| *byte = 0);
        self.incoming_recipients.clear();
        self.incoming_signature
            .iter_mut()
            .for_each(|byte| *byte = 0);
        self.incoming_signature.clear();
        self.incoming_vault_complete = false;
        self.incoming_recipients_complete = false;
        self.incoming_signature_complete = false;
    }

    pub(crate) fn finalize_incoming_payload(&mut self) -> Result<String, NackResponse> {
        if self.incoming_signature.len() != SIGNATURE_BUFFER_CAPACITY {
            self.reset_incoming_state();
            return Err(NackResponse {
                protocol_version: PROTOCOL_VERSION,
                code: DeviceErrorCode::ChecksumMismatch,
                message: format!(
                    "signature must contain exactly {} bytes",
                    SIGNATURE_BUFFER_CAPACITY
                ),
            });
        }

        let signature_bytes: [u8; SIGNATURE_BUFFER_CAPACITY] =
            match self.incoming_signature.as_slice().try_into() {
                Ok(bytes) => bytes,
                Err(_) => {
                    self.reset_incoming_state();
                    return Err(NackResponse {
                        protocol_version: PROTOCOL_VERSION,
                        code: DeviceErrorCode::ChecksumMismatch,
                        message: "failed to decode signature payload".into(),
                    });
                }
            };

        let verifying_key = match VerifyingKey::from_bytes(&VAULT_SIGNATURE_PUBLIC_KEY) {
            Ok(key) => key,
            Err(_) => {
                self.reset_incoming_state();
                return Err(NackResponse {
                    protocol_version: PROTOCOL_VERSION,
                    code: DeviceErrorCode::InternalFailure,
                    message: "invalid vault signing public key".into(),
                });
            }
        };

        let signature = match Ed25519Signature::try_from(signature_bytes.as_slice()) {
            Ok(sig) => sig,
            Err(_) => {
                self.reset_incoming_state();
                return Err(NackResponse {
                    protocol_version: PROTOCOL_VERSION,
                    code: DeviceErrorCode::ChecksumMismatch,
                    message: "signature payload rejected".into(),
                });
            }
        };

        let mut signed_payload =
            Vec::with_capacity(self.incoming_vault.len() + self.incoming_recipients.len());
        signed_payload.extend_from_slice(self.incoming_vault.as_slice());
        signed_payload.extend_from_slice(self.incoming_recipients.as_slice());

        if verifying_key.verify(&signed_payload, &signature).is_err() {
            self.reset_incoming_state();
            return Err(NackResponse {
                protocol_version: PROTOCOL_VERSION,
                code: DeviceErrorCode::ChecksumMismatch,
                message: "vault signature verification failed".into(),
            });
        }

        self.vault_image.iter_mut().for_each(|byte| *byte = 0);
        self.vault_image = Zeroizing::new(self.incoming_vault.as_slice().to_vec());
        self.recipients_manifest
            .iter_mut()
            .for_each(|byte| *byte = 0);
        self.recipients_manifest = Zeroizing::new(self.incoming_recipients.as_slice().to_vec());
        self.signature.iter_mut().for_each(|byte| *byte = 0);
        self.signature = Zeroizing::new(signature_bytes.to_vec());
        self.expected_signature = Some(signature_bytes);

        self.vault_generation = self.vault_generation.saturating_add(1);
        self.reset_transfer_state();
        self.reset_incoming_state();

        Ok(format!(
            "updated vault artifacts (vault {} bytes, recipients {} bytes)",
            self.vault_image.len(),
            self.recipients_manifest.len()
        ))
    }

    #[cfg(any(test, feature = "ui-tests"))]
    pub fn test_set_vault_key(&mut self, key: [u8; 32]) {
        self.crypto.test_set_vault_key(key);
    }

    #[cfg(any(test, feature = "ui-tests"))]
    pub fn test_set_vault_image(&mut self, image: Vec<u8>) {
        self.vault_image = Zeroizing::new(image);
    }

    #[cfg(any(test, feature = "ui-tests"))]
    pub fn test_set_journal(&mut self, ops: Vec<JournalOperation>) {
        self.journal_ops = ops;
    }

    #[cfg(any(test, feature = "ui-tests"))]
    pub fn test_configure_pin<R: RngCore + CryptoRng>(
        &mut self,
        pin: &[u8],
        rng: &mut R,
    ) -> Result<(), KeyError> {
        self.crypto.wrap_new_keys(pin, rng)?;
        self.crypto.wipe();
        Ok(())
    }
}
