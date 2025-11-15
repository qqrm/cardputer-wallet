//! Firmware crate entry point wiring together crypto, storage, sync, HID, and UI stacks.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(all(not(test), target_arch = "xtensa"), no_main)]

extern crate alloc;

pub mod crypto;
pub mod hid;
pub mod storage;
pub mod sync;
pub mod ui;

pub use crypto::{
    CryptoMaterial, KeyError, PinLockState, PinLockStatus, PinUnlockError, RecordNonce,
};
#[cfg(target_arch = "xtensa")]
pub use storage::BootFlash;
pub use storage::StorageError;
#[cfg(any(test, target_arch = "xtensa"))]
pub use storage::block_on;
#[cfg(any(test, target_arch = "xtensa"))]
pub use storage::initialize_context_from_flash;

#[cfg(target_arch = "xtensa")]
pub use hid::runtime;
pub use sync::{FRAME_MAX_SIZE, ProtocolError, SyncContext, process_host_frame};
