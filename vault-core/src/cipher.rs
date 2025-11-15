use aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use alloc::vec::Vec;
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Symmetric encryption algorithms supported for journal page envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeAlgorithm {
    /// ChaCha20-Poly1305 with a 256-bit key.
    ChaCha20Poly1305,
    /// AES-256-GCM with a 256-bit key.
    Aes256Gcm,
}

/// AEAD envelope used to protect journal pages stored on flash.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PageCipher {
    #[zeroize(skip)]
    algorithm: EnvelopeAlgorithm,
    key: [u8; 32],
}

impl PageCipher {
    /// Create a cipher using ChaCha20-Poly1305.
    pub const fn chacha20_poly1305(key: [u8; 32]) -> Self {
        Self {
            algorithm: EnvelopeAlgorithm::ChaCha20Poly1305,
            key,
        }
    }

    /// Create a cipher using AES-256-GCM.
    pub const fn aes256_gcm(key: [u8; 32]) -> Self {
        Self {
            algorithm: EnvelopeAlgorithm::Aes256Gcm,
            key,
        }
    }

    fn encrypt_impl(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, aead::Error> {
        match self.algorithm {
            EnvelopeAlgorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .expect("32-byte ChaCha20-Poly1305 key");
                cipher.encrypt(
                    nonce.into(),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
            }
            EnvelopeAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key).expect("32-byte AES-256-GCM key");
                cipher.encrypt(
                    nonce.into(),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
            }
        }
    }

    fn decrypt_impl(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, aead::Error> {
        match self.algorithm {
            EnvelopeAlgorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .expect("32-byte ChaCha20-Poly1305 key");
                cipher.decrypt(
                    nonce.into(),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
            }
            EnvelopeAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key).expect("32-byte AES-256-GCM key");
                cipher.decrypt(
                    nonce.into(),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
            }
        }
    }

    /// Encrypt the provided plaintext using the configured algorithm.
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, aead::Error> {
        self.encrypt_impl(nonce, aad, plaintext)
    }

    /// Decrypt the provided ciphertext using the configured algorithm.
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, aead::Error> {
        self.decrypt_impl(nonce, aad, ciphertext)
    }

    /// Return the configured algorithm.
    pub const fn algorithm(&self) -> EnvelopeAlgorithm {
        self.algorithm
    }
}
