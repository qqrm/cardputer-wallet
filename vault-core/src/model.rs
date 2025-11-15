use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::fmt;
use core::ops::{Deref, DerefMut};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Journal page version marker.
pub const JOURNAL_PAGE_VERSION: u16 = 1;

/// Additional authenticated data for journal page envelopes.
pub const JOURNAL_AAD: &[u8] = b"cardputer.vault.journal.v1";

/// Metadata describing the decrypted vault payload shipped over sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub generation: u64,
    pub created_at: String,
    pub updated_at: String,
}

/// Supported hashing algorithm for TOTP codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    #[serde(rename = "sha1")]
    Sha1,
    #[serde(rename = "sha256")]
    Sha256,
    #[serde(rename = "sha512")]
    Sha512,
}

/// Wrapper around sensitive strings that zeroize their memory on drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretString(pub Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl Deref for SecretString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self::new(value))
    }
}

/// Time based OTP configuration associated with an entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpConfig {
    pub secret: SecretString,
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u16,
}

/// Password vault entry aligned with SPEC §6 fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: Uuid,
    pub title: String,
    pub service: String,
    pub domains: Vec<String>,
    pub username: String,
    pub password: SecretString,
    pub totp: Option<TotpConfig>,
    pub tags: Vec<String>,
    pub r#macro: Option<String>,
    pub updated_at: String,
    pub used_at: Option<String>,
}

/// Field level updates as required by SPEC §7 for journal operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EntryUpdate {
    pub title: Option<String>,
    pub service: Option<String>,
    pub domains: Option<Vec<String>>,
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub totp: Option<TotpConfig>,
    pub tags: Option<Vec<String>>,
    pub r#macro: Option<String>,
    pub updated_at: Option<String>,
    pub used_at: Option<Option<String>>,
}

/// Legacy journal fields emitted by early firmware revisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyField {
    Title,
    Service,
    Domains,
    Username,
    Password,
    Totp,
    Tags,
    Macro,
    UpdatedAt,
    UsedAt,
}

impl LegacyField {
    /// Stable identifier matching on-device payloads.
    pub const fn as_str(self) -> &'static str {
        match self {
            LegacyField::Title => "title",
            LegacyField::Service => "service",
            LegacyField::Domains => "domains",
            LegacyField::Username => "username",
            LegacyField::Password => "password",
            LegacyField::Totp => "totp",
            LegacyField::Tags => "tags",
            LegacyField::Macro => "macro",
            LegacyField::UpdatedAt => "updated_at",
            LegacyField::UsedAt => "used_at",
        }
    }
}

impl fmt::Display for LegacyField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when parsing an unknown legacy field name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyFieldParseError {
    value: String,
}

impl LegacyFieldParseError {
    /// Raw identifier extracted from the payload.
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for LegacyFieldParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported legacy journal field '{}'", self.value)
    }
}

impl TryFrom<&str> for LegacyField {
    type Error = LegacyFieldParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let field = match value {
            "title" => LegacyField::Title,
            "service" => LegacyField::Service,
            "domains" => LegacyField::Domains,
            "username" => LegacyField::Username,
            "password" => LegacyField::Password,
            "totp" => LegacyField::Totp,
            "tags" => LegacyField::Tags,
            "macro" => LegacyField::Macro,
            "updated_at" => LegacyField::UpdatedAt,
            "used_at" => LegacyField::UsedAt,
            _ => {
                return Err(LegacyFieldParseError {
                    value: value.to_owned(),
                });
            }
        };

        Ok(field)
    }
}

#[cfg(test)]
mod tests {
    use super::LegacyField;
    use core::convert::TryFrom;

    #[test]
    fn legacy_field_round_trip() {
        for (raw, expected) in [
            ("title", LegacyField::Title),
            ("service", LegacyField::Service),
            ("domains", LegacyField::Domains),
            ("username", LegacyField::Username),
            ("password", LegacyField::Password),
            ("totp", LegacyField::Totp),
            ("tags", LegacyField::Tags),
            ("macro", LegacyField::Macro),
            ("updated_at", LegacyField::UpdatedAt),
            ("used_at", LegacyField::UsedAt),
        ] {
            let parsed = LegacyField::try_from(raw).expect("field parsed");
            assert_eq!(parsed, expected);
            assert_eq!(parsed.to_string(), raw);
        }
    }

    #[test]
    fn legacy_field_rejects_unknown_values() {
        let err = LegacyField::try_from("unknown").expect_err("expected failure");
        assert_eq!(
            err.to_string(),
            "unsupported legacy journal field 'unknown'"
        );
        assert_eq!(err.value(), "unknown");
    }
}

/// Journal operations captured in the sequential log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalOperation {
    Add { entry: VaultEntry },
    Update { id: Uuid, changes: EntryUpdate },
    Delete { id: Uuid },
}

/// Timestamped operation stored on a journal page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRecord {
    pub operation: JournalOperation,
    pub timestamp: String,
}

/// Plaintext journal page that gets encrypted before hitting flash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalPage {
    pub version: u16,
    pub counter: u64,
    pub records: Vec<JournalRecord>,
}

/// Ciphertext payload stored in sequential-storage pages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedJournalPage {
    pub counter: u64,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}
