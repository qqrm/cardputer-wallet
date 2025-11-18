use alloc::{format, string::String, vec::Vec};

use crate::crypto::{KeyError, PinLockStatus, PinUnlockError};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use shared::schema::{DeviceErrorCode, NackResponse, PROTOCOL_VERSION};

use super::{SyncContext, context::SIGNATURE_BUFFER_CAPACITY};

const VAULT_SIGNATURE_PUBLIC_KEY: [u8; 32] = [
    0xD7, 0x5A, 0x98, 0x01, 0x82, 0xB1, 0x0A, 0xB7, 0xD5, 0x4B, 0xFE, 0xD3, 0xC9, 0x64, 0x07, 0x3A,
    0x0E, 0xE1, 0x72, 0xF3, 0xDA, 0xA6, 0x23, 0x25, 0xAF, 0x02, 0x1A, 0x68, 0xF7, 0x07, 0x51, 0x1A,
];

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

    pub(crate) fn finalize_incoming_payload(&mut self) -> Result<String, NackResponse> {
        let mut verifying_key = match VerifyingKey::from_bytes(&VAULT_SIGNATURE_PUBLIC_KEY) {
            Ok(key) => key,
            Err(_) => {
                return Err(NackResponse {
                    protocol_version: PROTOCOL_VERSION,
                    code: DeviceErrorCode::InternalFailure,
                    message: "invalid vault signature key".into(),
                });
            }
        };

        let signature_bytes: [u8; SIGNATURE_BUFFER_CAPACITY] =
            match self.incoming_signature.as_slice().try_into() {
                Ok(bytes) => bytes,
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

        if verifying_key
            .verify(
                &signed_payload,
                &Ed25519Signature::from_bytes(&signature_bytes),
            )
            .is_err()
        {
            self.reset_incoming_state();
            return Err(NackResponse {
                protocol_version: PROTOCOL_VERSION,
                code: DeviceErrorCode::ChecksumMismatch,
                message: "vault signature verification failed".into(),
            });
        }

        self.write_vault_payloads(
            self.incoming_vault.as_slice(),
            self.incoming_recipients.as_slice(),
        );
        self.update_expected_signature(signature_bytes);

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
    pub fn test_configure_pin<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        pin: &[u8],
        rng: &mut R,
    ) -> Result<(), KeyError> {
        self.crypto.wrap_new_keys(pin, rng)?;
        self.crypto.wipe();
        Ok(())
    }
}

#[cfg(test)]
mod crypto_tests;
