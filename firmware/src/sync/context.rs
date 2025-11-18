use alloc::{string::String, vec::Vec};
use core::ops::Range;

use crate::crypto::{CryptoMaterial, PinLockState};
use crate::time::{self, CalibratedClock};
use shared::journal::{FrameTracker, JournalOperation};
use shared::transfer::{ArtifactLengths, ArtifactStream};
use shared::vault::VaultEntry;
use zeroize::Zeroizing;

/// Maximum payload size (in bytes) that a single postcard frame is allowed to occupy on the wire.
pub const FRAME_MAX_SIZE: usize = 4096;

/// Capacity provisioned for the encrypted vault image buffer.
pub(crate) const VAULT_BUFFER_CAPACITY: usize = 64 * 1024;
/// Capacity provisioned for the recipients manifest buffer.
pub(crate) const RECIPIENTS_BUFFER_CAPACITY: usize = 4 * 1024;
/// Capacity provisioned for the detached signature buffer.
pub(crate) const SIGNATURE_BUFFER_CAPACITY: usize = 64;
/// Scratch buffer used when interacting with sequential storage.
pub(crate) const STORAGE_DATA_BUFFER_CAPACITY: usize =
    VAULT_BUFFER_CAPACITY + RECIPIENTS_BUFFER_CAPACITY + SIGNATURE_BUFFER_CAPACITY;

/// Runtime state required to service synchronization requests from the host.
#[derive(Debug)]
pub struct SyncContext {
    pub(crate) journal_ops: Vec<JournalOperation>,
    pub(crate) frame_tracker: FrameTracker,
    pub(crate) next_sequence: u32,
    pub(crate) vault_image: Zeroizing<Vec<u8>>,
    pub(crate) recipients_manifest: Zeroizing<Vec<u8>>,
    pub(crate) signature: Zeroizing<Vec<u8>>,
    pub(crate) expected_signature: Option<[u8; SIGNATURE_BUFFER_CAPACITY]>,
    pub(crate) incoming_vault: Zeroizing<Vec<u8>>,
    pub(crate) incoming_recipients: Zeroizing<Vec<u8>>,
    pub(crate) incoming_signature: Zeroizing<Vec<u8>>,
    pub(crate) incoming_vault_complete: bool,
    pub(crate) incoming_recipients_complete: bool,
    pub(crate) incoming_signature_complete: bool,
    pub(crate) transfer: ArtifactStream,
    pub(crate) crypto: CryptoMaterial,
    pub(crate) pin_lock: PinLockState,
    pub(crate) session_id: u32,
    pub(crate) device_name: String,
    pub(crate) firmware_version: String,
    pub(crate) vault_generation: u64,
    pub(crate) clock: CalibratedClock,
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

    /// Reset sensitive buffers once a session finishes.
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

    pub(crate) fn reset_transfer_state(&mut self) {
        let lengths = ArtifactLengths {
            vault: self.vault_image.len(),
            recipients: self.recipients_manifest.len(),
            signature: self.signature.len(),
        };
        self.transfer.reset(lengths);
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

    pub(crate) fn reset_vault_buffers(&mut self) {
        self.vault_image = Zeroizing::new(Vec::new());
    }

    pub(crate) fn update_expected_signature(&mut self, signature: [u8; SIGNATURE_BUFFER_CAPACITY]) {
        self.signature.iter_mut().for_each(|byte| *byte = 0);
        self.signature = Zeroizing::new(signature.to_vec());
        self.expected_signature = Some(signature);
    }

    pub(crate) fn write_vault_payloads(&mut self, vault: &[u8], recipients: &[u8]) {
        self.vault_image.iter_mut().for_each(|byte| *byte = 0);
        self.vault_image = Zeroizing::new(vault.to_vec());
        self.recipients_manifest
            .iter_mut()
            .for_each(|byte| *byte = 0);
        self.recipients_manifest = Zeroizing::new(recipients.to_vec());
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
    pub fn test_set_current_time_ms(&mut self, now_ms: u64) {
        self.set_epoch_time_ms(now_ms);
    }

    #[cfg(any(test, feature = "ui-tests"))]
    pub fn test_reset_incoming_state(&mut self) {
        self.reset_incoming_state();
    }

    #[cfg(any(test, feature = "ui-tests"))]
    pub fn test_transfer_range(&self) -> Range<u32> {
        0..self.transfer.total_size() as u32
    }
}

#[cfg(test)]
pub(crate) fn fresh_context() -> SyncContext {
    crate::hid::actions::clear();
    SyncContext::new()
}
