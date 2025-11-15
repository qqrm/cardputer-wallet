use core::{fmt, str::FromStr};

use crate::{checksum::accumulate_checksum, schema::JournalOperation};

/// Initial seed used by the rolling journal checksum.
const JOURNAL_SEED: u32 = 0xA5A5_5A5A;

/// Computes checksums for journal operations emitted by the device or host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalHasher {
    state: u32,
}

impl JournalHasher {
    /// Create a hasher with the default seed.
    pub const fn new() -> Self {
        Self {
            state: JOURNAL_SEED,
        }
    }

    /// Reset the internal accumulator back to the initial seed.
    pub fn reset(&mut self) {
        self.state = JOURNAL_SEED;
    }

    /// Feed a single journal operation into the checksum and return the updated value.
    pub fn update(&mut self, operation: &JournalOperation) -> u32 {
        self.state = Self::fold_operation(self.state, operation);
        self.state
    }

    /// Final checksum value for the processed operations.
    pub const fn finish(&self) -> u32 {
        self.state
    }

    /// Compute the checksum for an entire slice of operations in one step.
    pub fn digest(operations: &[JournalOperation]) -> u32 {
        let mut hasher = Self::new();
        for operation in operations {
            hasher.update(operation);
        }
        hasher.finish()
    }

    fn fold_operation(state: u32, operation: &JournalOperation) -> u32 {
        match operation {
            JournalOperation::Add { entry_id } => accumulate_checksum(state, entry_id.as_bytes()),
            JournalOperation::UpdateField {
                entry_id,
                field,
                value_checksum,
            } => {
                let updated = accumulate_checksum(state, entry_id.as_bytes());
                let updated = accumulate_checksum(updated, field.as_bytes());
                updated ^ value_checksum
            }
            JournalOperation::Delete { entry_id } => {
                accumulate_checksum(state, entry_id.as_bytes()) ^ 0xFFFF_FFFF
            }
        }
    }
}

impl Default for JournalHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// State persisted between frames to confirm acknowledgements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameState {
    /// Sequential identifier assigned to the frame.
    pub sequence: u32,
    /// Rolling checksum protecting the frame payload.
    pub checksum: u32,
}

impl fmt::Display for FrameState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.sequence, self.checksum)
    }
}

/// Errors returned while parsing [`FrameState`] from a persisted representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameStateParseError {
    /// Missing delimiter separating the sequence and checksum fields.
    MissingDelimiter,
    /// Sequence failed to parse as an unsigned 32-bit integer.
    InvalidSequence,
    /// Checksum failed to parse as an unsigned 32-bit integer.
    InvalidChecksum,
}

impl fmt::Display for FrameStateParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameStateParseError::MissingDelimiter => {
                write!(f, "missing ':' delimiter in frame state")
            }
            FrameStateParseError::InvalidSequence => {
                write!(f, "invalid frame sequence value")
            }
            FrameStateParseError::InvalidChecksum => {
                write!(f, "invalid frame checksum value")
            }
        }
    }
}

impl FromStr for FrameState {
    type Err = FrameStateParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (sequence, checksum) = s
            .split_once(':')
            .ok_or(FrameStateParseError::MissingDelimiter)?;
        let sequence = sequence
            .trim()
            .parse::<u32>()
            .map_err(|_| FrameStateParseError::InvalidSequence)?;
        let checksum = checksum
            .trim()
            .parse::<u32>()
            .map_err(|_| FrameStateParseError::InvalidChecksum)?;
        Ok(FrameState { sequence, checksum })
    }
}

/// Tracks the most recent frame that needs to be acknowledged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameTracker {
    state: Option<FrameState>,
}

impl FrameTracker {
    /// Create an empty tracker.
    pub const fn new() -> Self {
        Self { state: None }
    }

    /// Record a new frame sequence and checksum pair.
    pub fn record(&mut self, sequence: u32, checksum: u32) {
        self.state = Some(FrameState { sequence, checksum });
    }

    /// Store a frame state directly.
    pub fn record_state(&mut self, state: FrameState) {
        self.state = Some(state);
    }

    /// Return the currently tracked frame, if any.
    pub const fn state(&self) -> Option<FrameState> {
        self.state
    }

    /// Whether there is a pending frame awaiting acknowledgement.
    pub const fn is_pending(&self) -> bool {
        self.state.is_some()
    }

    /// Clear any pending frame data.
    pub fn clear(&mut self) {
        self.state = None;
    }

    /// Confirm that the acknowledgement matches the pending frame and clear it.
    pub fn confirm(&mut self, sequence: u32, checksum: u32) -> bool {
        if self.state == Some(FrameState { sequence, checksum }) {
            self.state = None;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::String, vec};

    fn legacy_checksum(operations: &[JournalOperation]) -> u32 {
        operations
            .iter()
            .fold(JOURNAL_SEED, |acc, operation| match operation {
                JournalOperation::Add { entry_id } => accumulate_checksum(acc, entry_id.as_bytes()),
                JournalOperation::UpdateField {
                    entry_id,
                    field,
                    value_checksum,
                } => {
                    let updated = accumulate_checksum(acc, entry_id.as_bytes());
                    let updated = accumulate_checksum(updated, field.as_bytes());
                    updated ^ value_checksum
                }
                JournalOperation::Delete { entry_id } => {
                    accumulate_checksum(acc, entry_id.as_bytes()) ^ 0xFFFF_FFFF
                }
            })
    }

    #[test]
    fn journal_hasher_matches_legacy_logic() {
        let operations = vec![
            JournalOperation::Add {
                entry_id: String::from("alpha"),
            },
            JournalOperation::UpdateField {
                entry_id: String::from("beta"),
                field: String::from("service"),
                value_checksum: 0x1234_5678,
            },
            JournalOperation::Delete {
                entry_id: String::from("gamma"),
            },
        ];

        let expected = legacy_checksum(&operations);
        let actual = JournalHasher::digest(&operations);

        assert_eq!(actual, expected);
    }

    #[test]
    fn frame_state_round_trip() {
        let state = FrameState {
            sequence: 42,
            checksum: 0xDEAD_BEEF,
        };
        let encoded = state.to_string();
        assert_eq!(encoded, "42:3735928559");

        let decoded = encoded.parse::<FrameState>().expect("state parsed");
        assert_eq!(decoded, state);
    }

    #[test]
    fn frame_state_parse_errors_are_classified() {
        assert_eq!(
            "missing".parse::<FrameState>().unwrap_err(),
            FrameStateParseError::MissingDelimiter
        );
        assert_eq!(
            "x:1".parse::<FrameState>().unwrap_err(),
            FrameStateParseError::InvalidSequence
        );
        assert_eq!(
            "1:y".parse::<FrameState>().unwrap_err(),
            FrameStateParseError::InvalidChecksum
        );
    }

    #[test]
    fn frame_tracker_confirms_and_clears() {
        let mut tracker = FrameTracker::new();
        tracker.record(7, 0xAA55_AA55);
        assert!(tracker.is_pending());
        assert!(tracker.confirm(7, 0xAA55_AA55));
        assert!(!tracker.is_pending());
        assert!(!tracker.confirm(7, 0xAA55_AA55));
    }
}
