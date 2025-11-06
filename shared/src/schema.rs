use serde::{Deserialize, Serialize};

/// Version tag used by both the host and the device when negotiating sync messages.
pub const PROTOCOL_VERSION: u16 = 1;

/// Host initiated requests travelling from the CLI to the device during a sync session.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum HostRequest {
    /// Initiate a fresh session with the device and negotiate capabilities.
    Hello(HelloRequest),
    /// Query the device for its current synchronization status.
    Status(StatusRequest),
    /// Update the device real time clock to a host supplied timestamp.
    SetTime(SetTimeRequest),
    /// Ask the device to report its notion of wall clock time.
    GetTime(GetTimeRequest),
    /// Request the device to provide metadata describing the latest vault head.
    PullHead(PullHeadRequest),
    /// Request the device to stream its latest vault back to the host.
    PullVault(PullVaultRequest),
    /// Deliver a batch of journal operations for the device to apply.
    PushOps(PushOperationsFrame),
    /// Confirm that a sequence of journal frames has been applied successfully by the host.
    Ack(AckRequest),
}

/// Responses sent by the device back to the host during a sync session.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum DeviceResponse {
    /// Confirmation that a session has been established with device metadata.
    Hello(HelloResponse),
    /// Summary of the device sync state.
    Status(StatusResponse),
    /// Current notion of wall clock time exposed by the device.
    Time(TimeResponse),
    /// Metadata describing the latest encrypted vault artifacts.
    Head(PullHeadResponse),
    /// A batch of journal operations produced by the device for the host to apply.
    JournalFrame(JournalFrame),
    /// A chunk of the encrypted vault streamed from the device.
    VaultChunk(VaultChunk),
    /// Confirmation that a host initiated command completed successfully.
    Ack(AckResponse),
    /// Failure reported by the device while handling the previous host request.
    Nack(NackResponse),
}

/// Payload for the HELLO request sent by the host.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct HelloRequest {
    /// Version of the protocol expected by the host for this session.
    pub protocol_version: u16,
    /// Identifier for the host environment (helpful for logs).
    pub client_name: String,
    /// Version string describing the host CLI.
    pub client_version: String,
}

/// Device metadata returned after a successful HELLO handshake.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct HelloResponse {
    /// Protocol version agreed for the session.
    pub protocol_version: u16,
    /// Human readable identifier for the device.
    pub device_name: String,
    /// Firmware version currently running on the device.
    pub firmware_version: String,
    /// Opaque identifier used to correlate subsequent requests with this session.
    pub session_id: u32,
}

/// Host request asking for the current device status.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct StatusRequest {
    /// Protocol version expected by the host.
    pub protocol_version: u16,
}

/// Snapshot of the device sync status.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct StatusResponse {
    /// Protocol version used when generating the response.
    pub protocol_version: u16,
    /// Monotonic generation counter for the vault.
    pub vault_generation: u64,
    /// Number of journal operations waiting to be synced to the host.
    pub pending_operations: u32,
    /// Device notion of the current wall clock in milliseconds since the Unix epoch.
    pub current_time_ms: u64,
}

/// Host request to update the device notion of wall clock time.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct SetTimeRequest {
    /// Protocol version expected by the host.
    pub protocol_version: u16,
    /// Milliseconds since the Unix epoch provided by the host.
    pub epoch_millis: u64,
}

/// Host request to read the device notion of wall clock time.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct GetTimeRequest {
    /// Protocol version expected by the host.
    pub protocol_version: u16,
}

/// Current wall clock time returned by the device.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct TimeResponse {
    /// Protocol version used when encoding the response.
    pub protocol_version: u16,
    /// Milliseconds since the Unix epoch according to the device.
    pub epoch_millis: u64,
}

/// Host request for high level vault metadata.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PullHeadRequest {
    /// Protocol version expected by the host.
    pub protocol_version: u16,
}

/// Metadata describing the latest vault artefacts.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PullHeadResponse {
    /// Protocol version used when encoding the response.
    pub protocol_version: u16,
    /// Monotonic generation counter for the vault artefact.
    pub vault_generation: u64,
    /// Hash of the encrypted vault content.
    pub vault_hash: [u8; 32],
    /// Hash of the recipients manifest associated with the vault.
    pub recipients_hash: [u8; 32],
}

/// Metadata accompanying the host request to pull the vault from the device.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PullVaultRequest {
    /// Version of the protocol expected by the host for this request.
    pub protocol_version: u16,
    /// Maximum number of payload bytes that fit in the host receive buffer.
    pub host_buffer_size: u32,
    /// Largest chunk size (in bytes) that the host can process per frame.
    pub max_chunk_size: u32,
    /// Generation number known by the host to detect stale device state.
    pub known_generation: Option<u64>,
}

/// Host acknowledgement that a push flow journal was persisted successfully.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct AckRequest {
    /// Version of the protocol used by the host for the acknowledgement.
    pub protocol_version: u16,
    /// Sequential identifier that matches the last processed journal frame.
    pub last_frame_sequence: u32,
    /// Rolling CRC32 of the journal payloads applied by the host.
    pub journal_checksum: u32,
}

/// Journal operations produced by the host and pushed to the device.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PushOperationsFrame {
    /// Version of the protocol expected by the host for the push payload.
    pub protocol_version: u16,
    /// Sequential identifier that allows the device to acknowledge frames in order.
    pub sequence: u32,
    /// Journal operations describing the changes that should be applied locally on the device.
    pub operations: Vec<JournalOperation>,
    /// CRC32 computed over the encoded journal operations to guard against corruption.
    pub checksum: u32,
    /// Whether this frame is the final payload in the push session.
    pub is_last: bool,
}

/// Journal data generated by the device and consumed by the host.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct JournalFrame {
    /// Version of the protocol used by the device for this frame.
    pub protocol_version: u16,
    /// Sequence number that allows the host to reassemble frames in order.
    pub sequence: u32,
    /// Number of operations still queued after this frame.
    pub remaining_operations: u32,
    /// Journal operations describing vault changes since the previous sync.
    pub operations: Vec<JournalOperation>,
    /// CRC32 computed over the encoded journal operations to guard against corruption.
    pub checksum: u32,
}

/// Supported journal operations derived from the sync specification.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum JournalOperation {
    /// A new vault entry has been inserted.
    Add { entry_id: String },
    /// A single field of an existing entry has been updated.
    UpdateField {
        /// Identifier of the entry being modified.
        entry_id: String,
        /// Logical field path (e.g. "service", "username").
        field: String,
        /// CRC32 of the updated value allowing the host to detect mismatches.
        value_checksum: u32,
    },
    /// A vault entry was removed on the device.
    Delete { entry_id: String },
}

/// Identifies the artifact being transferred to the host.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
pub enum ArtifactKind {
    /// Encrypted vault image containing the credentials database.
    Vault,
    /// Recipients manifest describing the vault access policy.
    Recipients,
}

/// Chunk of the encrypted vault payload streamed to the host.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct VaultChunk {
    /// Version of the protocol carried by the chunk metadata.
    pub protocol_version: u16,
    /// Position of the chunk within the transfer.
    pub sequence: u32,
    /// Artifact associated with this chunk.
    pub artifact: ArtifactKind,
    /// Total size in bytes of the complete artifact being transferred.
    pub total_size: u64,
    /// Number of bytes still remaining after this chunk.
    pub remaining_bytes: u64,
    /// Maximum chunk size that the device can emit for the session.
    pub device_chunk_size: u32,
    /// Raw encrypted data payload from the vault artifact.
    pub data: Vec<u8>,
    /// CRC32 protecting the payload bytes in this chunk.
    pub checksum: u32,
    /// Whether this chunk finalises the artifact transfer.
    pub is_last: bool,
}

/// Response sent when a host command completes successfully.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct AckResponse {
    /// Protocol version used when encoding the acknowledgement.
    pub protocol_version: u16,
    /// Short description of the action that completed.
    pub message: String,
}

/// Describes an error condition detected by the device.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct NackResponse {
    /// Protocol version in use when the error was detected.
    pub protocol_version: u16,
    /// Stable error code for programmatic handling.
    pub code: DeviceErrorCode,
    /// Human readable description intended for logs.
    pub message: String,
}

/// Enumerates error codes that can be produced by the device.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum DeviceErrorCode {
    /// Host provided stale metadata or generation number.
    StaleGeneration,
    /// Payload checksum validation failed.
    ChecksumMismatch,
    /// Device resources (buffer, storage) are exhausted.
    ResourceExhausted,
    /// Any other unrecoverable internal failure.
    InternalFailure,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_request_roundtrip() {
        let request = HostRequest::Hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            client_name: "cli".into(),
            client_version: "0.1.0".into(),
        });

        let encoded = serde_cbor::to_vec(&request).expect("encode");
        let decoded: HostRequest = serde_cbor::from_slice(&encoded).expect("decode");

        assert_eq!(decoded, request);
    }

    #[test]
    fn device_response_roundtrip() {
        let response = DeviceResponse::Status(StatusResponse {
            protocol_version: PROTOCOL_VERSION,
            vault_generation: 7,
            pending_operations: 2,
            current_time_ms: 1_700_000_000_000,
        });

        let encoded = serde_cbor::to_vec(&response).expect("encode");
        let decoded: DeviceResponse = serde_cbor::from_slice(&encoded).expect("decode");

        assert_eq!(decoded, response);
    }

    #[test]
    fn handshake_and_pull_sequence_roundtrip() {
        let hello = HostRequest::Hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            client_name: "cli".into(),
            client_version: "0.1.0".into(),
        });
        let status = HostRequest::Status(StatusRequest {
            protocol_version: PROTOCOL_VERSION,
        });
        let head = HostRequest::PullHead(PullHeadRequest {
            protocol_version: PROTOCOL_VERSION,
        });
        let pull = HostRequest::PullVault(PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: 64 * 1024,
            max_chunk_size: 4096,
            known_generation: None,
        });

        for request in [hello, status, head, pull] {
            let encoded = serde_cbor::to_vec(&request).expect("encode");
            let decoded: HostRequest = serde_cbor::from_slice(&encoded).expect("decode");
            assert_eq!(decoded, request);
        }
    }

    #[test]
    fn push_frame_roundtrip() {
        let push = HostRequest::PushOps(PushOperationsFrame {
            protocol_version: PROTOCOL_VERSION,
            sequence: 1,
            operations: vec![JournalOperation::Add {
                entry_id: "alpha".into(),
            }],
            checksum: 0xDEADBEEF,
            is_last: true,
        });

        let encoded = serde_cbor::to_vec(&push).expect("encode");
        let decoded: HostRequest = serde_cbor::from_slice(&encoded).expect("decode");

        assert_eq!(decoded, push);
    }
}
