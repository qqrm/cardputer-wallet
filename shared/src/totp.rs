use alloc::{format, string::String, vec::Vec};

use data_encoding::BASE32_NOPAD;
use totp_embed::{Sha1, Sha256, Sha512, totp_custom};

use crate::vault::{TotpAlgorithm, TotpConfig};

/// Resulting TOTP code and metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpCode {
    pub code: String,
    pub period: u16,
    pub remaining_ms: u32,
}

/// Errors returned while generating a TOTP value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TotpError {
    #[error("secret is not valid base32")]
    InvalidSecret,
    #[error("digits must be 6 or 8")]
    UnsupportedDigits,
    #[error("period must be greater than zero")]
    InvalidPeriod,
}

/// Generate a RFC 6238 compliant TOTP code for the provided configuration.
pub fn generate(config: &TotpConfig, unix_time_ms: u64) -> Result<TotpCode, TotpError> {
    if config.digits != 6 && config.digits != 8 {
        return Err(TotpError::UnsupportedDigits);
    }
    if config.period == 0 {
        return Err(TotpError::InvalidPeriod);
    }

    let secret = normalize_secret(&config.secret).ok_or(TotpError::InvalidSecret)?;
    let digits = config.digits as u32;
    let code_value = match config.algorithm {
        TotpAlgorithm::Sha1 => {
            totp_custom::<Sha1>(config.period as u64, digits, &secret, unix_time_ms / 1_000)
        }
        TotpAlgorithm::Sha256 => {
            totp_custom::<Sha256>(config.period as u64, digits, &secret, unix_time_ms / 1_000)
        }
        TotpAlgorithm::Sha512 => {
            totp_custom::<Sha512>(config.period as u64, digits, &secret, unix_time_ms / 1_000)
        }
    };
    let code = format!("{:0width$}", code_value, width = digits as usize);
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
