use alloc::{format, string::String, vec::Vec};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::vault::{TotpAlgorithm, TotpConfig};

/// Resulting TOTP code and metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpCode {
    pub code: String,
    pub period: u16,
    pub remaining_ms: u32,
}

/// Errors returned while generating a TOTP value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TotpError {
    InvalidSecret,
    UnsupportedDigits,
    InvalidPeriod,
}

impl core::fmt::Display for TotpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TotpError::InvalidSecret => write!(f, "secret is not valid base32"),
            TotpError::UnsupportedDigits => write!(f, "digits must be 6 or 8"),
            TotpError::InvalidPeriod => write!(f, "period must be greater than zero"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TotpError {}

/// Generate a RFC 6238 compliant TOTP code for the provided configuration.
pub fn generate(config: &TotpConfig, unix_time_ms: u64) -> Result<TotpCode, TotpError> {
    if config.digits != 6 && config.digits != 8 {
        return Err(TotpError::UnsupportedDigits);
    }
    if config.period == 0 {
        return Err(TotpError::InvalidPeriod);
    }

    let secret = normalize_secret(&config.secret).ok_or(TotpError::InvalidSecret)?;
    let counter = unix_time_ms / 1_000 / config.period as u64;
    let hash = hmac_digest(config.algorithm, &secret, counter)?;
    let value = dynamic_truncate(&hash);
    let modulo = 10u32.pow(config.digits as u32);
    let code = format!("{:0width$}", value % modulo, width = config.digits as usize);
    let period_ms = config.period as u32 * 1_000;
    let elapsed = (unix_time_ms % period_ms as u64) as u32;
    let remaining = if elapsed == 0 {
        period_ms
    } else {
        period_ms - elapsed
    };

    Ok(TotpCode {
        code,
        period: config.period,
        remaining_ms: remaining,
    })
}

fn normalize_secret(secret: &str) -> Option<Vec<u8>> {
    let normalized: String = secret
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    BASE32_NOPAD.decode(normalized.as_bytes()).ok()
}

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

fn hmac_digest(algorithm: TotpAlgorithm, key: &[u8], counter: u64) -> Result<Vec<u8>, TotpError> {
    let counter_bytes = counter.to_be_bytes();
    match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(key).map_err(|_| TotpError::InvalidSecret)?;
            mac.update(&counter_bytes);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(key).map_err(|_| TotpError::InvalidSecret)?;
            mac.update(&counter_bytes);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = HmacSha512::new_from_slice(key).map_err(|_| TotpError::InvalidSecret)?;
            mac.update(&counter_bytes);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

fn dynamic_truncate(hash: &[u8]) -> u32 {
    let offset = (hash.last().cloned().unwrap_or(0) & 0x0F) as usize;
    let slice = &hash[offset..offset + 4];
    let value = u32::from_be_bytes(slice.try_into().unwrap());
    value & 0x7FFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{SecretString, TotpAlgorithm};

    fn config(secret: &str, algorithm: TotpAlgorithm) -> TotpConfig {
        TotpConfig {
            secret: SecretString::from(secret),
            algorithm,
            digits: 8,
            period: 30,
        }
    }

    #[test]
    fn rfc_vectors_sha1() {
        let cfg = config("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", TotpAlgorithm::Sha1);
        let code = generate(&cfg, 59_000).expect("code");
        assert_eq!(code.code, "94287082");
    }

    #[test]
    fn rfc_vectors_sha256() {
        let cfg = config(
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
            TotpAlgorithm::Sha256,
        );
        let code = generate(&cfg, 59_000).expect("code");
        assert_eq!(code.code, "46119246");
    }

    #[test]
    fn rfc_vectors_sha512() {
        let cfg = config(
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
            TotpAlgorithm::Sha512,
        );
        let code = generate(&cfg, 59_000).expect("code");
        assert_eq!(code.code, "90693936");
    }

    #[test]
    fn rejects_invalid_secret() {
        let cfg = TotpConfig {
            secret: SecretString::from("***"),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
        };
        assert!(matches!(generate(&cfg, 0), Err(TotpError::InvalidSecret)));
    }
}
