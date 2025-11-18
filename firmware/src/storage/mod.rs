//! Persistent storage glue for flash-backed bootstrapping and context persistence.
#[cfg(any(test, target_arch = "xtensa"))]
use core::ops::Range;
#[cfg(target_arch = "xtensa")]
use embedded_storage::nor_flash::NorFlash as BlockingNorFlash;
#[cfg(target_arch = "xtensa")]
use embedded_storage::nor_flash::ReadNorFlash;
#[cfg(any(test, target_arch = "xtensa"))]
use embedded_storage_async::nor_flash::NorFlash as AsyncNorFlash;
use sequential_storage::Error as FlashStorageError;

#[cfg(any(test, target_arch = "xtensa"))]
use crate::sync::SyncContext;

#[derive(Debug)]
pub enum StorageError<E> {
    Flash(FlashStorageError<E>),
    Decode(alloc::string::String),
    Key(crate::crypto::KeyError),
}

impl<E> From<FlashStorageError<E>> for StorageError<E> {
    fn from(error: FlashStorageError<E>) -> Self {
        StorageError::Flash(error)
    }
}

impl<E> From<crate::crypto::KeyError> for StorageError<E> {
    fn from(error: crate::crypto::KeyError) -> Self {
        StorageError::Key(error)
    }
}

impl<E> core::fmt::Display for StorageError<E>
where
    FlashStorageError<E>: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StorageError::Flash(err) => write!(f, "flash error: {err}"),
            StorageError::Decode(err) => write!(f, "decode error: {err}"),
            StorageError::Key(err) => write!(f, "key error: {err}"),
        }
    }
}

impl<E> core::error::Error for StorageError<E>
where
    FlashStorageError<E>: core::fmt::Debug + core::fmt::Display,
    E: core::fmt::Debug,
{
}

#[cfg(any(test, target_arch = "xtensa"))]
pub async fn initialize_context_from_flash<S>(
    flash: &mut S,
    range: Range<u32>,
) -> Result<SyncContext, StorageError<S::Error>>
where
    S: AsyncNorFlash,
{
    let mut ctx = SyncContext::new();
    ctx.load_from_flash(flash, range).await?;
    Ok(ctx)
}

#[cfg(target_arch = "xtensa")]
pub struct BootFlash<'d> {
    storage: embassy_embedded_hal::adapter::BlockingAsync<esp_storage::FlashStorage<'d>>,
}

#[cfg(target_arch = "xtensa")]
impl<'d> BootFlash<'d> {
    pub fn new(storage: esp_storage::FlashStorage<'d>) -> Self {
        Self {
            storage: embassy_embedded_hal::adapter::BlockingAsync::new(storage),
        }
    }

    pub fn flash_capacity(&self) -> usize {
        embedded_storage_async::nor_flash::ReadNorFlash::capacity(&self.storage)
    }

    pub async fn sequential_storage_range(&mut self) -> Option<Range<u32>> {
        use core::str;
        use embedded_storage_async::nor_flash::ReadNorFlash;

        const PARTITION_MAGIC: u16 = 0x50AA;
        const PARTITION_TABLE_OFFSET: u32 = 0x8000;
        const PARTITION_TABLE_SIZE: usize = 0x1000;
        const PARTITION_ENTRY_SIZE: usize = 32;
        const DATA_PARTITION_TYPE: u8 = 0x01;
        const FILESYSTEM_SUBTYPES: [u8; 3] = [0x81, 0x82, 0x83];
        const SYNC_LABELS: [&str; 5] = [
            "cardputer-sync",
            "cardputer_sync",
            "wallet-sync",
            "wallet_sync",
            "sync",
        ];

        let mut table = [0u8; PARTITION_TABLE_SIZE];
        if ReadNorFlash::read(&mut self.storage, PARTITION_TABLE_OFFSET, &mut table)
            .await
            .is_err()
        {
            return None;
        }

        let mut preferred: Option<Range<u32>> = None;
        let mut filesystem: Option<Range<u32>> = None;

        for entry in table.chunks_exact(PARTITION_ENTRY_SIZE) {
            let magic = u16::from_le_bytes([entry[0], entry[1]]);
            if magic == 0xFFFF {
                break;
            }
            if magic != PARTITION_MAGIC {
                continue;
            }

            let partition_type = entry[2];
            if partition_type != DATA_PARTITION_TYPE {
                continue;
            }

            let subtype = entry[3];
            let offset = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
            let size = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
            if size == 0 {
                continue;
            }

            let end = match offset.checked_add(size) {
                Some(limit) => limit,
                None => continue,
            };

            let label_bytes = &entry[12..28];
            let label_end = label_bytes
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(label_bytes.len());
            let label = match str::from_utf8(&label_bytes[..label_end]) {
                Ok(value) => value,
                Err(_) => continue,
            };

            let range = offset..end;

            if SYNC_LABELS
                .iter()
                .any(|expected| label.eq_ignore_ascii_case(expected))
            {
                return Some(range);
            }

            if subtype >= 0x40 && preferred.is_none() {
                preferred = Some(range.clone());
            }

            if FILESYSTEM_SUBTYPES.contains(&subtype) && filesystem.is_none() {
                filesystem = Some(range);
            }
        }

        preferred.or(filesystem)
    }
}

#[cfg(target_arch = "xtensa")]
impl<'d> embedded_storage_async::nor_flash::ErrorType for BootFlash<'d> {
    type Error = esp_storage::FlashStorageError;
}

#[cfg(target_arch = "xtensa")]
impl<'d> embedded_storage_async::nor_flash::ReadNorFlash for BootFlash<'d> {
    const READ_SIZE: usize = esp_storage::FlashStorage::READ_SIZE as usize;

    fn capacity(&self) -> usize {
        self.flash_capacity()
    }

    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.storage.read(offset, bytes).await
    }
}

#[cfg(target_arch = "xtensa")]
impl<'d> embedded_storage_async::nor_flash::NorFlash for BootFlash<'d> {
    const WRITE_SIZE: usize = <esp_storage::FlashStorage as BlockingNorFlash>::WRITE_SIZE as usize;
    const ERASE_SIZE: usize = <esp_storage::FlashStorage as BlockingNorFlash>::ERASE_SIZE as usize;

    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.storage.erase(from, to).await
    }

    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.storage.write(offset, bytes).await
    }
}
