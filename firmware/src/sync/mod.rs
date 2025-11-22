//! Host synchronization state machine, frame encoding, and protocol validation tests.
use alloc::{string::String, vec::Vec};

use crate::crypto::{CryptoMaterial, PinLockState};
use crate::time::{self, CalibratedClock};
use shared::journal::FrameTracker;
use shared::schema::JournalOperation;
use shared::transfer::ArtifactStream;
use shared::vault::VaultEntry;
use zeroize::Zeroizing;

mod crypto;
mod protocol;
mod storage;

#[cfg_attr(not(target_arch = "xtensa"), allow(unused_imports))]
pub(crate) use protocol::encode_response;
pub use protocol::{ProtocolError, process_host_frame};

/// Maximum payload size (in bytes) that a single postcard frame is allowed to occupy on the wire.
pub const FRAME_MAX_SIZE: usize = 4096;

/// Capacity provisioned for the encrypted vault image buffer.
const VAULT_BUFFER_CAPACITY: usize = 64 * 1024;
/// Capacity provisioned for the recipients manifest buffer.
const RECIPIENTS_BUFFER_CAPACITY: usize = 4 * 1024;
/// Capacity provisioned for the detached signature buffer.
const SIGNATURE_BUFFER_CAPACITY: usize = 64;
/// Ed25519 public key that signs repository vault artifacts.
const VAULT_SIGNATURE_PUBLIC_KEY: [u8; 32] = [
    0xD7, 0x5A, 0x98, 0x01, 0x82, 0xB1, 0x0A, 0xB7, 0xD5, 0x4B, 0xFE, 0xD3, 0xC9, 0x64, 0x07, 0x3A,
    0x0E, 0xE1, 0x72, 0xF3, 0xDA, 0xA6, 0x23, 0x25, 0xAF, 0x02, 0x1A, 0x68, 0xF7, 0x07, 0x51, 0x1A,
];
/// Runtime state required to service synchronization requests from the host.
#[derive(Debug)]
pub struct SyncContext {
    journal_ops: Vec<JournalOperation>,
    frame_tracker: FrameTracker,
    next_sequence: u32,
    vault_image: Zeroizing<Vec<u8>>,
    recipients_manifest: Zeroizing<Vec<u8>>,
    signature: Zeroizing<Vec<u8>>,
    expected_signature: Option<[u8; SIGNATURE_BUFFER_CAPACITY]>,
    incoming_vault: Zeroizing<Vec<u8>>,
    incoming_recipients: Zeroizing<Vec<u8>>,
    incoming_signature: Zeroizing<Vec<u8>>,
    incoming_vault_complete: bool,
    incoming_recipients_complete: bool,
    incoming_signature_complete: bool,
    transfer: ArtifactStream,
    crypto: CryptoMaterial,
    pin_lock: PinLockState,
    session_id: u32,
    device_name: String,
    firmware_version: String,
    vault_generation: u64,
    clock: CalibratedClock,
}

impl Default for SyncContext {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncContext {
    /// Construct a new synchronization context with pre-allocated buffers.
    pub fn new() -> Self {
        Self {
            journal_ops: Vec::new(),
            frame_tracker: FrameTracker::new(),
            next_sequence: 1,
            vault_image: Zeroizing::new(Vec::with_capacity(VAULT_BUFFER_CAPACITY)),
            recipients_manifest: Zeroizing::new(Vec::with_capacity(RECIPIENTS_BUFFER_CAPACITY)),
            signature: Zeroizing::new(Vec::with_capacity(SIGNATURE_BUFFER_CAPACITY)),
            expected_signature: None,
            incoming_vault: Zeroizing::new(Vec::with_capacity(VAULT_BUFFER_CAPACITY)),
            incoming_recipients: Zeroizing::new(Vec::with_capacity(RECIPIENTS_BUFFER_CAPACITY)),
            incoming_signature: Zeroizing::new(Vec::with_capacity(SIGNATURE_BUFFER_CAPACITY)),
            incoming_vault_complete: false,
            incoming_recipients_complete: false,
            incoming_signature_complete: false,
            transfer: ArtifactStream::new(),
            crypto: CryptoMaterial::default(),
            pin_lock: PinLockState::new(),
            session_id: 0,
            device_name: String::from("Cardputer Wallet"),
            firmware_version: String::from(env!("CARGO_PKG_VERSION")),
            vault_generation: 0,
            clock: CalibratedClock::new(),
        }
    }

    pub fn current_time_ms(&self) -> u64 {
        self.clock.current_time_ms()
    }

    pub fn journal_operations(&self) -> Vec<JournalOperation> {
        self.journal_ops.clone()
    }

    pub fn vault_entries(&self) -> Vec<VaultEntry> {
        postcard::from_bytes(self.vault_image.as_slice()).unwrap_or_default()
    }

    pub fn set_epoch_time_ms(&mut self, epoch_ms: u64) -> u64 {
        let now = self.clock.set_time_ms(epoch_ms);
        time::publish_time(now);
        now
    }

    /// Register a journal operation that should be emitted on the next pull.
    pub fn record_operation(&mut self, operation: JournalOperation) {
        self.journal_ops.push(operation);
    }
}

#[cfg(any(test, feature = "ui-tests"))]
impl SyncContext {
    pub fn test_set_current_time_ms(&mut self, now_ms: u64) {
        self.set_epoch_time_ms(now_ms);
    }
}

#[cfg(test)]
mod sync_storage_tests;
#[cfg(test)]
mod test_helpers;
#[cfg(test)]
mod tests_pull;
#[cfg(test)]
mod tests_push;
#[cfg(test)]
mod tests_time;
#[cfg(test)]
mod tests_transport;
