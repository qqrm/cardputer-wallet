use crate::vault::{
    cipher::{EnvelopeAlgorithm, PageCipher},
    errors::JournalError,
    nonce,
};

/// Minimal cipher state shared between the CLI and firmware.
///
/// Firmware extends this state via [`flash`](crate::vault::flash) to talk to NOR flash,
/// while the host CLI sticks to the pure-Rust helpers exposed here when preparing
/// encrypted payloads to push over USB.
#[derive(Debug, Clone)]
pub struct VaultJournal {
    pub(crate) cipher: PageCipher,
    pub(crate) next_counter: u64,
}

impl VaultJournal {
    pub(crate) const NONCE_DOMAIN: [u8; 4] = *b"JNL1";

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

    pub(crate) fn reserve_nonce<E>(&mut self) -> Result<(u64, [u8; 12]), JournalError<E>>
    where
        E: core::fmt::Debug,
    {
        let counter = self.next_counter;
        self.next_counter = self
            .next_counter
            .checked_add(1)
            .ok_or(JournalError::NonceExhausted)?;
        Ok((counter, nonce::build(Self::NONCE_DOMAIN, counter)))
    }

    pub(crate) fn observe_counter<E>(&mut self, counter: u64) -> Result<(), JournalError<E>>
    where
        E: core::fmt::Debug,
    {
        let next = counter.checked_add(1).ok_or(JournalError::NonceExhausted)?;
        if self.next_counter < next {
            self.next_counter = next;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_can_stage_nonce_without_flash() {
        let mut journal = VaultJournal::new(PageCipher::chacha20_poly1305([0x55; 32]));
        let (counter, nonce) = journal.reserve_nonce::<()>().unwrap();
        assert_eq!(counter, 0);
        assert_eq!(&nonce[..4], b"JNL1");
        assert_eq!(&nonce[4..], &0u64.to_be_bytes());
        assert_eq!(journal.next_counter, 1);
    }
}
