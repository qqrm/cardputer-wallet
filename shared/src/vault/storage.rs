use crate::vault::{
    cipher::{EnvelopeAlgorithm, PageCipher},
    model::{EncryptedJournalPage, JOURNAL_AAD, JOURNAL_PAGE_VERSION, JournalPage, JournalRecord},
};
use alloc::{vec, vec::Vec};
use core::ops::Range;
use embedded_storage_async::nor_flash::NorFlash;
use sequential_storage::{Error as SequentialStorageError, cache::CacheImpl, erase_all, queue};
use zeroize::Zeroizing;

/// Errors raised while persisting encrypted journal pages.
#[derive(Debug, thiserror::Error)]
pub enum VaultStorageError<SE>
where
    SE: core::fmt::Debug,
{
    #[error("storage error: {0:?}")]
    Storage(SequentialStorageError<SE>),
    #[error("serialization error: {0}")]
    Codec(#[from] postcard::Error),
    #[error("authentication failed")]
    Authentication,
    #[error("unsupported journal version {0}")]
    UnsupportedVersion(u16),
    #[error("nonce counter exhausted")]
    NonceExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{
        EntryUpdate, JournalOperation, JournalRecord, TotpAlgorithm, TotpConfig, VaultEntry,
    };
    use futures::executor::block_on;
    use sequential_storage::{
        cache::NoCache,
        mock_flash::{MockFlashBase, WriteCountCheck},
    };
    use uuid::Uuid;

    type Flash = MockFlashBase<8, 4, 256>;

    fn init_flash() -> Flash {
        Flash::new(WriteCountCheck::Twice, None, false)
    }

    fn sample_entry(id: Uuid) -> VaultEntry {
        VaultEntry {
            id,
            title: "Example".into(),
            service: "mail".into(),
            domains: vec!["example.com".into()],
            username: "alice".into(),
            password: "hunter2".into(),
            totp: Some(TotpConfig {
                secret: "JBSWY3DPEHPK3PXP".into(),
                algorithm: TotpAlgorithm::Sha1,
                digits: 6,
                period: 30,
            }),
            tags: vec!["prod".into()],
            r#macro: Some("{{username}}\t{{password}}".into()),
            updated_at: "2024-01-01T00:00:00Z".into(),
            used_at: Some("2024-01-01T00:00:00Z".into()),
        }
    }

    fn run_flow(cipher: PageCipher) {
        block_on(async {
            let mut flash = init_flash();
            let flash_range = Flash::FULL_FLASH_RANGE.clone();

            let mut journal = VaultJournal::new(cipher.clone());
            let mut cache = NoCache::new();
            assert!(
                journal
                    .load_records(&mut flash, flash_range.clone(), &mut cache)
                    .await
                    .unwrap()
                    .is_empty()
            );

            let id = Uuid::from_bytes([1; 16]);
            let entry = sample_entry(id);
            let add_record = JournalRecord {
                operation: JournalOperation::Add {
                    entry: entry.clone(),
                },
                timestamp: "2024-01-01T00:00:00Z".into(),
            };
            journal
                .append_record(
                    &mut flash,
                    flash_range.clone(),
                    &mut NoCache::new(),
                    add_record.clone(),
                )
                .await
                .unwrap();

            let mut cache = NoCache::new();
            assert_eq!(
                journal
                    .load_records(&mut flash, flash_range.clone(), &mut cache)
                    .await
                    .unwrap(),
                vec![add_record.clone()]
            );

            let mut journal_restarted = VaultJournal::new(cipher);
            let mut cache = NoCache::new();
            assert_eq!(
                journal_restarted
                    .load_records(&mut flash, flash_range.clone(), &mut cache)
                    .await
                    .unwrap(),
                vec![add_record.clone()]
            );

            let update_record = JournalRecord {
                operation: JournalOperation::Update {
                    id,
                    changes: EntryUpdate {
                        password: Some("n3wp@ss".into()),
                        tags: Some(vec!["prod".into(), "rotated".into()]),
                        updated_at: Some("2024-01-02T00:00:00Z".into()),
                        ..EntryUpdate::default()
                    },
                },
                timestamp: "2024-01-02T00:00:00Z".into(),
            };
            let delete_record = JournalRecord {
                operation: JournalOperation::Delete { id },
                timestamp: "2024-01-03T00:00:00Z".into(),
            };
            journal_restarted
                .append_records(
                    &mut flash,
                    flash_range.clone(),
                    &mut NoCache::new(),
                    vec![update_record.clone(), delete_record.clone()],
                )
                .await
                .unwrap();

            let mut cache = NoCache::new();
            assert_eq!(
                journal_restarted
                    .load_records(&mut flash, flash_range.clone(), &mut cache)
                    .await
                    .unwrap(),
                vec![
                    add_record.clone(),
                    update_record.clone(),
                    delete_record.clone()
                ]
            );

            journal_restarted
                .clear(&mut flash, flash_range.clone(), &mut NoCache::new())
                .await
                .unwrap();
            let mut cache = NoCache::new();
            assert!(
                journal_restarted
                    .load_records(&mut flash, flash_range.clone(), &mut cache)
                    .await
                    .unwrap()
                    .is_empty()
            );

            let post_clear_record = JournalRecord {
                operation: JournalOperation::Add {
                    entry: sample_entry(Uuid::from_bytes([2; 16])),
                },
                timestamp: "2024-01-04T00:00:00Z".into(),
            };
            journal_restarted
                .append_record(
                    &mut flash,
                    flash_range.clone(),
                    &mut NoCache::new(),
                    post_clear_record.clone(),
                )
                .await
                .unwrap();

            let mut cache = NoCache::new();
            assert_eq!(
                journal_restarted
                    .load_records(&mut flash, flash_range, &mut cache)
                    .await
                    .unwrap(),
                vec![post_clear_record]
            );
        });
    }

    #[test]
    fn journal_flow_chacha() {
        run_flow(PageCipher::chacha20_poly1305([0x11; 32]));
    }

    #[test]
    fn journal_flow_aes() {
        run_flow(PageCipher::aes256_gcm([0x22; 32]));
    }

    #[test]
    fn clear_keeps_nonce_counter_monotonic() {
        block_on(async {
            let mut flash = init_flash();
            let flash_range = Flash::FULL_FLASH_RANGE.clone();

            let mut journal = VaultJournal::new(PageCipher::chacha20_poly1305([0x33; 32]));
            let record = JournalRecord {
                operation: JournalOperation::Delete {
                    id: Uuid::from_bytes([9; 16]),
                },
                timestamp: "2024-02-01T00:00:00Z".into(),
            };

            journal
                .append_record(&mut flash, flash_range.clone(), &mut NoCache::new(), record)
                .await
                .unwrap();

            let counter_after_append = journal.next_counter;

            journal
                .clear(&mut flash, flash_range, &mut NoCache::new())
                .await
                .unwrap();

            assert_eq!(journal.next_counter, counter_after_append);
        });
    }
}

impl<SE> From<SequentialStorageError<SE>> for VaultStorageError<SE>
where
    SE: core::fmt::Debug,
{
    fn from(value: SequentialStorageError<SE>) -> Self {
        Self::Storage(value)
    }
}

/// Wrapper around `sequential-storage` that encrypts every page using an AEAD envelope.
#[derive(Debug, Clone)]
pub struct VaultJournal {
    cipher: PageCipher,
    next_counter: u64,
}

impl VaultJournal {
    const NONCE_DOMAIN: [u8; 4] = *b"JNL1";

    /// Create a new journal for the provided cipher.
    pub const fn new(cipher: PageCipher) -> Self {
        Self {
            cipher,
            next_counter: 0,
        }
    }

    /// Return the configured envelope algorithm.
    pub const fn algorithm(&self) -> EnvelopeAlgorithm {
        self.cipher.algorithm()
    }

    /// Load and decrypt every record currently stored in flash.
    ///
    /// The call updates the nonce counter so future writes remain monotonic.
    pub async fn load_records<S, CI, SE>(
        &mut self,
        flash: &mut S,
        flash_range: Range<u32>,
        cache: &mut CI,
    ) -> Result<Vec<JournalRecord>, VaultStorageError<SE>>
    where
        S: NorFlash<Error = SE>,
        CI: CacheImpl,
        SE: core::fmt::Debug,
    {
        let mut buffer = vec![0u8; S::ERASE_SIZE];
        let mut records = Vec::new();
        let mut last_counter = None;

        let mut iter = queue::iter(flash, flash_range.clone(), cache).await?;
        while let Some(entry) = iter.next(&mut buffer).await? {
            let slice = entry.into_buf();
            let envelope: EncryptedJournalPage = postcard::from_bytes(slice)?;
            let plaintext = Zeroizing::new(
                self.cipher
                    .decrypt(&envelope.nonce, JOURNAL_AAD, &envelope.ciphertext)
                    .map_err(|_| VaultStorageError::Authentication)?,
            );
            let page: JournalPage = postcard::from_bytes(plaintext.as_slice())?;
            if page.version != JOURNAL_PAGE_VERSION {
                return Err(VaultStorageError::UnsupportedVersion(page.version));
            }

            last_counter =
                Some(last_counter.map_or(page.counter, |prev: u64| prev.max(page.counter)));
            records.extend(page.records.into_iter());
        }

        if let Some(counter) = last_counter {
            self.next_counter = self.next_counter.max(
                counter
                    .checked_add(1)
                    .ok_or(VaultStorageError::NonceExhausted)?,
            );
        }

        Ok(records)
    }

    /// Append a batch of journal records. Returns without touching flash when the batch is empty.
    pub async fn append_records<S, CI, SE>(
        &mut self,
        flash: &mut S,
        flash_range: Range<u32>,
        cache: &mut CI,
        records: impl IntoIterator<Item = JournalRecord>,
    ) -> Result<(), VaultStorageError<SE>>
    where
        S: NorFlash<Error = SE>,
        CI: CacheImpl,
        SE: core::fmt::Debug,
    {
        let records: Vec<JournalRecord> = records.into_iter().collect();
        if records.is_empty() {
            return Ok(());
        }

        let counter = self.next_counter;
        let nonce = Self::build_nonce(counter)?;
        self.next_counter = self
            .next_counter
            .checked_add(1)
            .ok_or(VaultStorageError::NonceExhausted)?;

        let page = JournalPage {
            version: JOURNAL_PAGE_VERSION,
            counter,
            records,
        };
        let plaintext = Zeroizing::new(postcard::to_allocvec(&page)?);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, JOURNAL_AAD, plaintext.as_slice())
            .map_err(|_| VaultStorageError::Authentication)?;
        let envelope = EncryptedJournalPage {
            counter,
            nonce,
            ciphertext,
        };
        let encoded = postcard::to_allocvec(&envelope)?;

        queue::push(flash, flash_range, cache, &encoded, false).await?;
        Ok(())
    }

    /// Append a single record to the journal.
    pub async fn append_record<S, CI, SE>(
        &mut self,
        flash: &mut S,
        flash_range: Range<u32>,
        cache: &mut CI,
        record: JournalRecord,
    ) -> Result<(), VaultStorageError<SE>>
    where
        S: NorFlash<Error = SE>,
        CI: CacheImpl,
        SE: core::fmt::Debug,
    {
        self.append_records(flash, flash_range, cache, core::iter::once(record))
            .await
    }

    /// Remove every stored record by erasing the configured range.
    ///
    /// The nonce counter remains monotonic so future appends continue to use
    /// fresh nonces for the configured cipher key.
    pub async fn clear<S, CI, SE>(
        &mut self,
        flash: &mut S,
        flash_range: Range<u32>,
        _cache: &mut CI,
    ) -> Result<(), VaultStorageError<SE>>
    where
        S: NorFlash<Error = SE>,
        CI: CacheImpl,
        SE: core::fmt::Debug,
    {
        erase_all(flash, flash_range.clone()).await?;
        Ok(())
    }

    fn build_nonce<SE>(counter: u64) -> Result<[u8; 12], VaultStorageError<SE>>
    where
        SE: core::fmt::Debug,
    {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&Self::NONCE_DOMAIN);
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        Ok(nonce)
    }
}
