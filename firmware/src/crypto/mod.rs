//! Cryptographic helpers for key derivation, PIN handling, and symmetric primitives used by the
//! firmware sync protocol.
use alloc::vec::Vec;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use rand_core::{CryptoRng, RngCore};
use scrypt::{
    Params as ScryptParams,
    errors::{InvalidOutputLen, InvalidParams},
};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SCRYPT_LOG_N: u8 = 14;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

pub(crate) const PIN_BACKOFF_THRESHOLD: u8 = 3;
pub(crate) const PIN_WIPE_THRESHOLD: u8 = 10;
pub(crate) const PIN_BACKOFF_BASE_MS: u64 = 1_000;

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    InvalidParameters,
    InvalidOutput,
    KekUnavailable,
    VaultKeyUnavailable,
    VaultKeyLength,
    DeviceKeyUnavailable,
    DeviceKeyLength,
    CryptoFailure,
}

impl From<InvalidParams> for KeyError {
    fn from(_: InvalidParams) -> Self {
        KeyError::InvalidParameters
    }
}

impl From<InvalidOutputLen> for KeyError {
    fn from(_: InvalidOutputLen) -> Self {
        KeyError::InvalidOutput
    }
}

impl From<chacha20poly1305::aead::Error> for KeyError {
    fn from(_: chacha20poly1305::aead::Error) -> Self {
        KeyError::CryptoFailure
    }
}

impl core::fmt::Display for KeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let label = match self {
            KeyError::InvalidParameters => "invalid scrypt parameters",
            KeyError::InvalidOutput => "invalid scrypt output length",
            KeyError::KekUnavailable => "missing KEK",
            KeyError::VaultKeyUnavailable => "vault key unavailable",
            KeyError::VaultKeyLength => "unexpected vault key length",
            KeyError::DeviceKeyUnavailable => "device key unavailable",
            KeyError::DeviceKeyLength => "unexpected device key length",
            KeyError::CryptoFailure => "encryption failure",
        };
        write!(f, "{label}")
    }
}

impl core::error::Error for KeyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinLockStatus {
    pub consecutive_failures: u8,
    pub total_failures: u8,
    pub backoff_remaining_ms: Option<u64>,
    pub wipe_required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinFailureFeedback {
    backoff_until_ms: Option<u64>,
    wipe_triggered: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinLockState {
    consecutive_failures: u8,
    total_failures: u8,
    backoff_until_ms: Option<u64>,
    wipe_triggered: bool,
}

impl Default for PinLockState {
    fn default() -> Self {
        Self::new()
    }
}

impl PinLockState {
    pub const fn new() -> Self {
        Self {
            consecutive_failures: 0,
            total_failures: 0,
            backoff_until_ms: None,
            wipe_triggered: false,
        }
    }

    pub fn register_success(&mut self) {
        self.consecutive_failures = 0;
        self.backoff_until_ms = None;
    }

    pub fn register_failure(&mut self, now_ms: u64) -> PinFailureFeedback {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.total_failures = self.total_failures.saturating_add(1);

        if self.total_failures >= PIN_WIPE_THRESHOLD {
            self.wipe_triggered = true;
        }

        if self.consecutive_failures >= PIN_BACKOFF_THRESHOLD {
            let exponent = (self.consecutive_failures - PIN_BACKOFF_THRESHOLD) as u32;
            let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
            let delay = PIN_BACKOFF_BASE_MS.saturating_mul(multiplier);
            self.backoff_until_ms = now_ms.checked_add(delay);
        }

        PinFailureFeedback {
            backoff_until_ms: self.backoff_until_ms,
            wipe_triggered: self.wipe_triggered,
        }
    }

    pub fn remaining_backoff(&self, now_ms: u64) -> Option<u64> {
        self.backoff_until_ms.and_then(|until| {
            if now_ms >= until {
                None
            } else {
                Some(until - now_ms)
            }
        })
    }

    pub fn status(&self, now_ms: u64) -> PinLockStatus {
        PinLockStatus {
            consecutive_failures: self.consecutive_failures,
            total_failures: self.total_failures,
            backoff_remaining_ms: self.remaining_backoff(now_ms),
            wipe_required: self.wipe_triggered,
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn wipe_pending(&self) -> bool {
        self.wipe_triggered
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PinUnlockError {
    Backoff { remaining_ms: u64 },
    WipeRequired,
    Key(KeyError),
}

impl From<KeyError> for PinUnlockError {
    fn from(value: KeyError) -> Self {
        PinUnlockError::Key(value)
    }
}

impl core::fmt::Display for PinUnlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PinUnlockError::Backoff { remaining_ms } => {
                write!(f, "PIN entry temporarily disabled for {remaining_ms} ms")
            }
            PinUnlockError::WipeRequired => write!(f, "device requires secure wipe"),
            PinUnlockError::Key(err) => write!(f, "{err}"),
        }
    }
}

impl core::error::Error for PinUnlockError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ScryptParamsRecord {
    log_n: u8,
    r: u32,
    p: u32,
}

impl ScryptParamsRecord {
    fn to_params(&self) -> Result<ScryptParams, KeyError> {
        ScryptParams::new(self.log_n, self.r, self.p).map_err(Into::into)
    }
}

impl From<ScryptParams> for ScryptParamsRecord {
    fn from(params: ScryptParams) -> Self {
        Self {
            log_n: params.log_n(),
            r: params.r(),
            p: params.p(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct KeyRecord {
    pub(crate) salt: [u8; 16],
    pub(crate) vault_nonce: [u8; 12],
    pub(crate) device_nonce: [u8; 12],
    pub(crate) wrapped_vault_key: Vec<u8>,
    pub(crate) wrapped_device_key: Vec<u8>,
    pub(crate) device_public_key: [u8; 32],
    pub(crate) scrypt: ScryptParamsRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RecordNonce([u8; 12]);

impl RecordNonce {
    pub fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    pub const fn as_array(&self) -> &[u8; 12] {
        &self.0
    }

    pub fn into_inner(self) -> [u8; 12] {
        self.0
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct CryptoMaterial {
    kek: Option<Zeroizing<[u8; 32]>>,
    vault_key: Option<Zeroizing<[u8; 32]>>,
    device_private_key: Option<Zeroizing<[u8; 32]>>,
    device_public_key: Option<[u8; 32]>,
    pin_salt: [u8; 16],
    kek_nonce: [u8; 12],
    device_key_nonce: [u8; 12],
    wrapped_vault_key: Zeroizing<Vec<u8>>,
    wrapped_device_private_key: Zeroizing<Vec<u8>>,
    #[zeroize(skip)]
    scrypt_params: ScryptParams,
}

impl Default for CryptoMaterial {
    fn default() -> Self {
        Self {
            kek: None,
            vault_key: None,
            device_private_key: None,
            device_public_key: None,
            pin_salt: [0u8; 16],
            kek_nonce: [0u8; 12],
            device_key_nonce: [0u8; 12],
            wrapped_vault_key: Zeroizing::new(Vec::new()),
            wrapped_device_private_key: Zeroizing::new(Vec::new()),
            scrypt_params: ScryptParams::recommended(),
        }
    }
}

impl CryptoMaterial {
    fn derive_kek(&mut self, pin: &[u8]) -> Result<(), KeyError> {
        let mut derived = Zeroizing::new([0u8; 32]);
        let pin_guard = Zeroizing::new(pin.to_vec());
        scrypt::scrypt(
            pin_guard.as_ref(),
            &self.pin_salt,
            &self.scrypt_params,
            derived.as_mut(),
        )
        .map_err(KeyError::from)?;
        self.kek = Some(derived);
        Ok(())
    }

    fn cipher_from_kek(&self) -> Result<ChaCha20Poly1305, KeyError> {
        let kek = self.kek.as_ref().ok_or(KeyError::KekUnavailable)?;
        ChaCha20Poly1305::new_from_slice(kek.as_ref()).map_err(|_| KeyError::CryptoFailure)
    }

    fn ensure_vault_key(&self) -> Result<&Zeroizing<[u8; 32]>, KeyError> {
        self.vault_key.as_ref().ok_or(KeyError::VaultKeyUnavailable)
    }

    fn ensure_device_key(&self) -> Result<&Zeroizing<[u8; 32]>, KeyError> {
        self.device_private_key
            .as_ref()
            .ok_or(KeyError::DeviceKeyUnavailable)
    }

    pub(crate) fn configure_from_record(&mut self, record: &KeyRecord) -> Result<(), KeyError> {
        self.pin_salt = record.salt;
        self.kek_nonce = record.vault_nonce;
        self.device_key_nonce = record.device_nonce;
        self.wrapped_vault_key = Zeroizing::new(record.wrapped_vault_key.clone());
        self.wrapped_device_private_key = Zeroizing::new(record.wrapped_device_key.clone());
        self.device_public_key = Some(record.device_public_key);
        self.scrypt_params = record.scrypt.to_params()?;
        self.kek = None;
        self.vault_key = None;
        self.device_private_key = None;
        Ok(())
    }

    pub(crate) fn record(&self) -> Option<KeyRecord> {
        if self.wrapped_vault_key.is_empty() || self.wrapped_device_private_key.is_empty() {
            return None;
        }

        let public_key = self.device_public_key?;

        Some(KeyRecord {
            salt: self.pin_salt,
            vault_nonce: self.kek_nonce,
            device_nonce: self.device_key_nonce,
            wrapped_vault_key: (*self.wrapped_vault_key).clone(),
            wrapped_device_key: (*self.wrapped_device_private_key).clone(),
            device_public_key: public_key,
            scrypt: self.scrypt_params.into(),
        })
    }

    pub fn wrap_new_keys<R: RngCore + CryptoRng>(
        &mut self,
        pin: &[u8],
        rng: &mut R,
    ) -> Result<(), KeyError> {
        rng.fill_bytes(&mut self.pin_salt);
        rng.fill_bytes(&mut self.kek_nonce);
        rng.fill_bytes(&mut self.device_key_nonce);

        self.scrypt_params = ScryptParams::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)?;

        let mut fresh_vault_key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(fresh_vault_key.as_mut());

        let mut device_secret = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(device_secret.as_mut());
        let static_secret = X25519StaticSecret::from(*device_secret);
        let device_public = X25519PublicKey::from(&static_secret);
        let device_private_key = Zeroizing::new(static_secret.to_bytes());
        drop(static_secret);

        self.derive_kek(pin)?;
        let cipher = self.cipher_from_kek()?;
        let vault_nonce = Nonce::from(self.kek_nonce);
        let vault_ciphertext = cipher.encrypt(&vault_nonce, fresh_vault_key.as_ref())?;
        let device_nonce = Nonce::from(self.device_key_nonce);
        let device_ciphertext = cipher.encrypt(&device_nonce, device_private_key.as_ref())?;

        self.wrapped_vault_key = Zeroizing::new(vault_ciphertext);
        self.wrapped_device_private_key = Zeroizing::new(device_ciphertext);
        self.vault_key = Some(fresh_vault_key);
        self.device_private_key = Some(device_private_key);
        self.device_public_key = Some(device_public.to_bytes());
        Ok(())
    }

    pub fn unlock_vault_key(&mut self, pin: &[u8]) -> Result<(), KeyError> {
        if self.wrapped_vault_key.is_empty() {
            return Err(KeyError::VaultKeyUnavailable);
        }

        if self.wrapped_device_private_key.is_empty() {
            return Err(KeyError::DeviceKeyUnavailable);
        }

        self.derive_kek(pin)?;
        let cipher = self.cipher_from_kek()?;
        let vault_nonce = Nonce::from(self.kek_nonce);
        let vault_plaintext =
            Zeroizing::new(cipher.decrypt(&vault_nonce, self.wrapped_vault_key.as_slice())?);

        if vault_plaintext.len() != 32 {
            return Err(KeyError::VaultKeyLength);
        }

        let mut vault_key = Zeroizing::new([0u8; 32]);
        vault_key.copy_from_slice(&vault_plaintext[..32]);
        let device_nonce = Nonce::from(self.device_key_nonce);
        let device_plaintext = Zeroizing::new(
            cipher.decrypt(&device_nonce, self.wrapped_device_private_key.as_slice())?,
        );

        if device_plaintext.len() != 32 {
            return Err(KeyError::DeviceKeyLength);
        }

        let mut device_private = Zeroizing::new([0u8; 32]);
        device_private.copy_from_slice(&device_plaintext[..32]);
        self.vault_key = Some(vault_key);
        self.device_private_key = Some(device_private);
        Ok(())
    }

    pub fn encrypt_record<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
    ) -> Result<(RecordNonce, Vec<u8>), KeyError> {
        let vault_key = self.ensure_vault_key()?;
        let cipher = ChaCha20Poly1305::new_from_slice(vault_key.as_ref())
            .map_err(|_| KeyError::CryptoFailure)?;
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(KeyError::from)?;
        Ok((RecordNonce::new(nonce_bytes), ciphertext))
    }

    pub fn decrypt_record(
        &self,
        nonce: &RecordNonce,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KeyError> {
        let vault_key = self.ensure_vault_key()?;
        let cipher = ChaCha20Poly1305::new_from_slice(vault_key.as_ref())
            .map_err(|_| KeyError::CryptoFailure)?;
        let nonce = Nonce::from(*nonce.as_array());
        cipher.decrypt(&nonce, ciphertext).map_err(KeyError::from)
    }

    pub fn device_public_key(&self) -> Option<[u8; 32]> {
        self.device_public_key
    }

    pub fn device_private_key(&self) -> Result<&Zeroizing<[u8; 32]>, KeyError> {
        self.ensure_device_key()
    }

    pub fn vault_key(&self) -> Result<&Zeroizing<[u8; 32]>, KeyError> {
        self.ensure_vault_key()
    }

    pub fn wipe(&mut self) {
        if let Some(kek) = self.kek.take() {
            drop(kek);
        }
        if let Some(vault_key) = self.vault_key.take() {
            drop(vault_key);
        }
        if let Some(device_key) = self.device_private_key.take() {
            drop(device_key);
        }
    }
}
