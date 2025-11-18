//! Host synchronization state machine, frame encoding, and protocol validation tests.

mod context;
mod crypto;
mod protocol;
mod storage;

pub use context::{FRAME_MAX_SIZE, SyncContext};
pub use protocol::encode_response;
pub use protocol::{ProtocolError, process_host_frame};
