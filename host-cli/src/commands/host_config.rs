use std::fs;
use std::path::Path;

use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use shared::error::SharedError;

use crate::constants::SIGNATURE_SIZE;

#[derive(Debug, Deserialize, Default)]
pub struct HostConfig {
    #[serde(default)]
    signing_public_key: Option<String>,
    #[serde(default)]
    signing_secret_key: Option<String>,
    #[serde(default)]
    vault_key: Option<String>,
}

impl HostConfig {
    pub fn load(path: &Path) -> Result<Self, SharedError> {
        let raw = fs::read_to_string(path).map_err(|err| {
            SharedError::Transport(format!(
                "failed to read credentials from '{}': {err}",
                path.display()
            ))
        })?;
        serde_json::from_str(&raw)
            .map_err(|err| SharedError::Transport(format!("invalid credentials file: {err}")))
    }

    pub fn verifying_key(&self) -> Result<Option<VerifyingKey>, SharedError> {
        if let Some(public) = &self.signing_public_key {
            let bytes = decode_key_bytes::<{ SIGNATURE_SIZE / 2 }>(public)?;
            return VerifyingKey::from_bytes(&bytes)
                .map(Some)
                .map_err(|err| SharedError::Transport(format!("invalid verifying key: {err}")));
        }

        if let Some(secret) = &self.signing_secret_key {
            let seed = decode_key_bytes::<{ SIGNATURE_SIZE / 2 }>(secret)?;
            let signing = SigningKey::from_bytes(&seed);
            return Ok(Some(signing.verifying_key()));
        }

        Ok(None)
    }

    pub fn signing_key(&self) -> Result<Option<SigningKey>, SharedError> {
        match &self.signing_secret_key {
            Some(secret) => {
                let seed = decode_key_bytes::<{ SIGNATURE_SIZE / 2 }>(secret)?;
                Ok(Some(SigningKey::from_bytes(&seed)))
            }
            None => Ok(None),
        }
    }

    pub fn vault_key(&self) -> Option<[u8; 32]> {
        self.vault_key
            .as_deref()
            .and_then(|value| decode_key_bytes::<32>(value).ok())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSnapshot {
    pub version: u16,
    pub metadata: shared::vault::VaultMetadata,
    pub entries: Vec<shared::vault::VaultEntry>,
}

pub(crate) fn decode_key_bytes<const N: usize>(input: &str) -> Result<[u8; N], SharedError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(SharedError::Transport("key material is empty".into()));
    }

    match base64::engine::general_purpose::STANDARD.decode(trimmed.as_bytes()) {
        Ok(bytes) if bytes.len() == N => bytes
            .try_into()
            .map_err(|_| SharedError::Transport("failed to read fixed-length key material".into())),
        Ok(bytes) => Err(SharedError::Transport(format!(
            "expected {N} decoded bytes but got {}",
            bytes.len()
        ))),
        Err(_) => {
            let hex_bytes = hex::decode(trimmed).map_err(|err| {
                SharedError::Transport(format!("failed to decode key material: {err}"))
            })?;
            if hex_bytes.len() != N {
                Err(SharedError::Transport(format!(
                    "expected {N} decoded bytes but got {}",
                    hex_bytes.len()
                )))
            } else {
                hex_bytes.try_into().map_err(|_| {
                    SharedError::Transport("failed to read fixed-length key material".into())
                })
            }
        }
    }
}
