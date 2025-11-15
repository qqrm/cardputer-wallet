use core::convert::TryFrom;

pub mod transport;

/// Magic number identifying CDC frames exchanged between the host and the device.
pub const FRAME_MAGIC: [u8; 4] = *b"CDCF";

/// Size in bytes of the fixed CDC frame header.
pub const FRAME_HEADER_SIZE: usize = 4 + 2 + 2 + 4 + 4;

/// Commands supported by the CDC framing protocol as described in the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CdcCommand {
    Hello = 0x0001,
    Status = 0x0002,
    SetTime = 0x0003,
    GetTime = 0x0004,
    PullHead = 0x0005,
    PullVault = 0x0006,
    PushOps = 0x0007,
    Ack = 0x0008,
    Nack = 0x0009,
    PushVault = 0x000A,
}

impl TryFrom<u16> for CdcCommand {
    type Error = FrameHeaderError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(CdcCommand::Hello),
            0x0002 => Ok(CdcCommand::Status),
            0x0003 => Ok(CdcCommand::SetTime),
            0x0004 => Ok(CdcCommand::GetTime),
            0x0005 => Ok(CdcCommand::PullHead),
            0x0006 => Ok(CdcCommand::PullVault),
            0x0007 => Ok(CdcCommand::PushOps),
            0x0008 => Ok(CdcCommand::Ack),
            0x0009 => Ok(CdcCommand::Nack),
            0x000A => Ok(CdcCommand::PushVault),
            other => Err(FrameHeaderError::UnknownCommand(other)),
        }
    }
}

impl From<CdcCommand> for u16 {
    fn from(value: CdcCommand) -> Self {
        value as u16
    }
}

/// Errors that can occur while decoding a CDC frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameHeaderError {
    /// Header did not contain the expected magic value.
    InvalidMagic([u8; 4]),
    /// Header declared a payload length that does not fit in memory.
    LengthOverflow,
    /// Header encoded an unknown command identifier.
    UnknownCommand(u16),
}

impl core::fmt::Display for FrameHeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameHeaderError::InvalidMagic(magic) => {
                write!(
                    f,
                    "invalid CDC magic 0x{:02X}{:02X}{:02X}{:02X}",
                    magic[0], magic[1], magic[2], magic[3]
                )
            }
            FrameHeaderError::LengthOverflow => write!(f, "payload length exceeds u32 range"),
            FrameHeaderError::UnknownCommand(cmd) => write!(f, "unknown CDC command 0x{cmd:04X}"),
        }
    }
}

/// Frame header transmitted before every payload on the CDC link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u16,
    pub command: CdcCommand,
    pub length: u32,
    pub checksum: u32,
}

impl FrameHeader {
    /// Construct a header for the given payload metadata.
    pub const fn new(version: u16, command: CdcCommand, length: u32, checksum: u32) -> Self {
        Self {
            version,
            command,
            length,
            checksum,
        }
    }

    /// Encode the header into a fixed-size byte array.
    pub fn to_bytes(self) -> [u8; FRAME_HEADER_SIZE] {
        let mut bytes = [0u8; FRAME_HEADER_SIZE];
        bytes[..4].copy_from_slice(&FRAME_MAGIC);
        bytes[4..6].copy_from_slice(&self.version.to_le_bytes());
        let command: u16 = self.command.into();
        bytes[6..8].copy_from_slice(&command.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.length.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.checksum.to_le_bytes());
        bytes
    }

    /// Decode a header from a byte array.
    pub fn from_bytes(bytes: [u8; FRAME_HEADER_SIZE]) -> Result<Self, FrameHeaderError> {
        if bytes[..4] != FRAME_MAGIC {
            return Err(FrameHeaderError::InvalidMagic([
                bytes[0], bytes[1], bytes[2], bytes[3],
            ]));
        }

        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        let command_raw = u16::from_le_bytes([bytes[6], bytes[7]]);
        let command = CdcCommand::try_from(command_raw)?;
        let length = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let checksum = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

        Ok(Self {
            version,
            command,
            length,
            checksum,
        })
    }
}

/// Compute the CRC32 checksum for the given payload.
pub fn compute_crc32(payload: &[u8]) -> u32 {
    use crc32fast::Hasher;

    let mut hasher = Hasher::new();
    hasher.update(payload);
    hasher.finalize()
}
