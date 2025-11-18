use alloc::vec;
use alloc::vec::Vec;
use core::ops::Range;

use crate::crypto::KeyRecord;
use crate::storage::StorageError;
use embedded_storage_async::nor_flash::NorFlash;
use postcard::{from_bytes as postcard_from_bytes, to_allocvec as postcard_to_allocvec};
use sequential_storage::{cache::NoCache, map};
use shared::journal::JournalOperation;
use shared::schema::{
    DeviceErrorCode, NackResponse, PROTOCOL_VERSION, VaultArtifact, decode_journal_operations,
};
use zeroize::Zeroizing;

use super::SyncContext;
use super::context::{
    RECIPIENTS_BUFFER_CAPACITY, SIGNATURE_BUFFER_CAPACITY, STORAGE_DATA_BUFFER_CAPACITY,
    VAULT_BUFFER_CAPACITY,
};

const STORAGE_KEY_VAULT: u8 = 0x01;
const STORAGE_KEY_RECIPIENTS: u8 = 0x02;
const STORAGE_KEY_JOURNAL: u8 = 0x03;
const STORAGE_KEY_GENERATION: u8 = 0x04;
const STORAGE_KEY_VAULT_KEYS: u8 = 0x05;
const STORAGE_KEY_SIGNATURE: u8 = 0x06;

impl SyncContext {
    /// Load persistent state from sequential flash storage.
    pub async fn load_from_flash<S>(
        &mut self,
        flash: &mut S,
        range: Range<u32>,
    ) -> Result<(), StorageError<S::Error>>
    where
        S: NorFlash,
    {
        let mut cache = NoCache::new();
        let mut scratch = Zeroizing::new(vec![0u8; STORAGE_DATA_BUFFER_CAPACITY]);

        self.vault_image = Zeroizing::new(Vec::new());
        if let Some(vault) = map::fetch_item::<u8, Vec<u8>, _>(
            flash,
            range.clone(),
            &mut cache,
            scratch.as_mut_slice(),
            &STORAGE_KEY_VAULT,
        )
        .await
        .map_err(StorageError::Flash)?
        {
            self.vault_image =
                Self::validate_flash_blob::<S::Error>(vault, VAULT_BUFFER_CAPACITY, "vault image")?;
        }

        self.recipients_manifest = Zeroizing::new(Vec::new());
        if let Some(recipients) = map::fetch_item::<u8, Vec<u8>, _>(
            flash,
            range.clone(),
            &mut cache,
            scratch.as_mut_slice(),
            &STORAGE_KEY_RECIPIENTS,
        )
        .await
        .map_err(StorageError::Flash)?
        {
            let blob = Self::validate_flash_blob::<S::Error>(
                recipients,
                RECIPIENTS_BUFFER_CAPACITY,
                "recipients manifest",
            )
            .map_err(|err| self.reset_vault_on_error(err))?;
            self.recipients_manifest = blob;
        }

        self.signature = Zeroizing::new(Vec::new());
        self.expected_signature = None;
        if let Some(signature) = map::fetch_item::<u8, Vec<u8>, _>(
            flash,
            range.clone(),
            &mut cache,
            scratch.as_mut_slice(),
            &STORAGE_KEY_SIGNATURE,
        )
        .await
        .map_err(StorageError::Flash)?
        {
            let blob = Self::validate_signature_blob::<S::Error>(signature)
                .map_err(|err| self.reset_vault_on_error(err))?;
            self.signature = blob;
            if self.signature.len() == SIGNATURE_BUFFER_CAPACITY
                && let Ok(bytes) = self.signature.as_slice().try_into()
            {
                self.expected_signature = Some(bytes);
            }
        }

        if let Some(journal_bytes) = map::fetch_item::<u8, Vec<u8>, _>(
            flash,
            range.clone(),
            &mut cache,
            scratch.as_mut_slice(),
            &STORAGE_KEY_JOURNAL,
        )
        .await
        .map_err(StorageError::Flash)?
        {
            self.journal_ops = decode_journal_operations(&journal_bytes).map_err(|err| {
                StorageError::Decode(format!("failed to decode journal operations: {err}"))
            })?;
        } else {
            self.journal_ops.clear();
        }

        if let Some(generation) = map::fetch_item::<u8, u64, _>(
            flash,
            range.clone(),
            &mut cache,
            scratch.as_mut_slice(),
            &STORAGE_KEY_GENERATION,
        )
        .await
        .map_err(StorageError::Flash)?
        {
            self.vault_generation = generation;
        }

        if let Some(key_bytes) = map::fetch_item::<u8, Vec<u8>, _>(
            flash,
            range,
            &mut cache,
            scratch.as_mut_slice(),
            &STORAGE_KEY_VAULT_KEYS,
        )
        .await
        .map_err(StorageError::Flash)?
        {
            let record: KeyRecord = postcard_from_bytes(&key_bytes).map_err(|err| {
                StorageError::Decode(format!("failed to decode key record: {err}"))
            })?;
            self.crypto.configure_from_record(&record)?;
        }

        self.reset_transfer_state();
        self.frame_tracker.clear();
        self.next_sequence = 1;

        Ok(())
    }

    pub async fn persist_crypto_material<S>(
        &self,
        flash: &mut S,
        range: Range<u32>,
    ) -> Result<(), StorageError<S::Error>>
    where
        S: NorFlash,
    {
        if let Some(record) = self.crypto.record() {
            let mut cache = NoCache::new();
            let mut scratch = Zeroizing::new(vec![0u8; STORAGE_DATA_BUFFER_CAPACITY]);
            let encoded = postcard_to_allocvec(&record)
                .map_err(|err| StorageError::Decode(err.to_string()))?;

            map::store_item(
                flash,
                range,
                &mut cache,
                scratch.as_mut_slice(),
                &STORAGE_KEY_VAULT_KEYS,
                &encoded,
            )
            .await
            .map_err(StorageError::Flash)?;
        }

        Ok(())
    }

    pub(crate) fn validate_flash_blob<E>(
        data: Vec<u8>,
        capacity: usize,
        label: &'static str,
    ) -> Result<Zeroizing<Vec<u8>>, StorageError<E>> {
        if data.len() > capacity {
            return Err(StorageError::Decode(format!(
                "{label} exceeds capacity ({} > {})",
                data.len(),
                capacity
            )));
        }

        Ok(Zeroizing::new(data))
    }

    pub(crate) fn validate_signature_blob<E>(
        data: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, StorageError<E>> {
        if data.len() > SIGNATURE_BUFFER_CAPACITY {
            return Err(StorageError::Decode(format!(
                "signature exceeds capacity ({} > {})",
                data.len(),
                SIGNATURE_BUFFER_CAPACITY
            )));
        }

        if !(data.is_empty() || data.len() == SIGNATURE_BUFFER_CAPACITY) {
            return Err(StorageError::Decode(format!(
                "signature must be exactly {} bytes when present (found {})",
                SIGNATURE_BUFFER_CAPACITY,
                data.len()
            )));
        }

        Ok(Zeroizing::new(data))
    }

    pub(crate) fn reset_vault_on_error<E>(&mut self, err: StorageError<E>) -> StorageError<E> {
        self.reset_vault_buffers();
        err
    }

    pub(crate) fn missing_signature_response() -> NackResponse {
        NackResponse {
            protocol_version: PROTOCOL_VERSION,
            code: DeviceErrorCode::ChecksumMismatch,
            message: "vault signature missing".into(),
        }
    }

    pub(crate) fn signature_overflow_response() -> NackResponse {
        NackResponse {
            protocol_version: PROTOCOL_VERSION,
            code: DeviceErrorCode::ChecksumMismatch,
            message: "signature payload exceeds capacity".into(),
        }
    }

    pub(crate) fn unknown_artifact_response(artifact: VaultArtifact) -> NackResponse {
        NackResponse {
            protocol_version: PROTOCOL_VERSION,
            code: DeviceErrorCode::ChecksumMismatch,
            message: format!("unexpected artifact chunk: {artifact:?}"),
        }
    }
}

#[cfg(test)]
mod storage_tests;
