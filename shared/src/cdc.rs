use core::fmt;

use crc32fast::Hasher;

pub const FRAME_MAGIC: u32 = 0x4643_4443; // "CDCF"
pub const FRAME_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FrameCommand {
    HostPullVault = 0x0001,
    HostAckPush = 0x0002,
    HostAbort = 0x0003,
    DeviceJournalFrame = 0x8001,
    DeviceVaultChunk = 0x8002,
    DeviceCompleted = 0x8003,
    DeviceError = 0x8004,
}

impl FrameCommand {
    pub fn from_wire(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(FrameCommand::HostPullVault),
            0x0002 => Some(FrameCommand::HostAckPush),
            0x0003 => Some(FrameCommand::HostAbort),
            0x8001 => Some(FrameCommand::DeviceJournalFrame),
            0x8002 => Some(FrameCommand::DeviceVaultChunk),
            0x8003 => Some(FrameCommand::DeviceCompleted),
            0x8004 => Some(FrameCommand::DeviceError),
            _ => None,
        }
    }

    pub fn to_wire(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub magic: u32,
    pub version: u16,
    pub command: FrameCommand,
    pub payload_length: u32,
}

impl FrameHeader {
    pub const ENCODED_LEN: usize = 12;

    pub fn new(command: FrameCommand, payload_length: u32) -> Self {
        Self {
            magic: FRAME_MAGIC,
            version: FRAME_VERSION,
            command,
            payload_length,
        }
    }

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0u8; Self::ENCODED_LEN];
        bytes[0..4].copy_from_slice(&self.magic.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.version.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.command.to_wire().to_le_bytes());
        bytes[8..12].copy_from_slice(&self.payload_length.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: [u8; Self::ENCODED_LEN]) -> Result<Self, FrameHeaderError> {
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != FRAME_MAGIC {
            return Err(FrameHeaderError::InvalidMagic(magic));
        }

        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != FRAME_VERSION {
            return Err(FrameHeaderError::UnsupportedVersion(version));
        }

        let command_value = u16::from_le_bytes([bytes[6], bytes[7]]);
        let command = FrameCommand::from_wire(command_value)
            .ok_or(FrameHeaderError::UnknownCommand(command_value))?;

        let payload_length = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        Ok(Self {
            magic,
            version,
            command,
            payload_length,
        })
    }

    pub fn checksum(&self, payload: &[u8]) -> u32 {
        let mut hasher = Hasher::new();
        hasher.update(&self.encode());
        hasher.update(payload);
        hasher.finalize()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameHeaderError {
    InvalidMagic(u32),
    UnsupportedVersion(u16),
    UnknownCommand(u16),
}

impl fmt::Display for FrameHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameHeaderError::InvalidMagic(actual) => {
                write!(f, "invalid frame magic 0x{actual:08X}")
            }
            FrameHeaderError::UnsupportedVersion(actual) => {
                write!(f, "unsupported frame version {actual}")
            }
            FrameHeaderError::UnknownCommand(value) => {
                write!(f, "unknown frame command 0x{value:04X}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let header = FrameHeader::new(FrameCommand::DeviceCompleted, 42);
        let encoded = header.encode();
        let decoded = FrameHeader::decode(encoded).expect("decode header");
        assert_eq!(decoded, header);
    }

    #[test]
    fn checksum_covers_header_and_payload() {
        let payload = [1u8, 2, 3, 4];
        let header = FrameHeader::new(FrameCommand::DeviceJournalFrame, payload.len() as u32);
        let checksum = header.checksum(&payload);

        let mut hasher = Hasher::new();
        hasher.update(&header.encode());
        hasher.update(&payload);
        assert_eq!(checksum, hasher.finalize());
    }

    #[test]
    fn decode_rejects_invalid_magic() {
        let mut header = FrameHeader::new(FrameCommand::HostAbort, 0);
        header.magic = 0xDEAD_BEEF;
        let encoded = header.encode();
        let err = FrameHeader::decode(encoded).expect_err("magic should fail");
        assert!(matches!(err, FrameHeaderError::InvalidMagic(0xDEAD_BEEF)));
    }

    #[test]
    fn decode_rejects_unknown_command() {
        let mut bytes = FrameHeader::new(FrameCommand::HostAbort, 0).encode();
        bytes[6..8].copy_from_slice(&0x00FFu16.to_le_bytes());
        let err = FrameHeader::decode(bytes).expect_err("unknown command should fail");
        assert!(matches!(err, FrameHeaderError::UnknownCommand(0x00FF)));
    }
}
