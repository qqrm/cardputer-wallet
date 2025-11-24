use shared::cdc::transport::{decode_frame_header, encode_frame};
use shared::cdc::{CdcCommand, FrameHeader};
use shared::checksum::accumulate_checksum;
use shared::schema::PROTOCOL_VERSION;

use super::{FRAME_MAX_SIZE, SyncContext};

pub(super) fn fresh_context() -> SyncContext {
    crate::hid::core::actions::clear();
    SyncContext::new()
}

pub(super) fn checksum(data: &[u8]) -> u32 {
    accumulate_checksum(0, data)
}

pub(super) fn frame_header_for_payload(command: CdcCommand, payload: &[u8]) -> FrameHeader {
    let header_bytes = encode_frame(PROTOCOL_VERSION, command, payload, FRAME_MAX_SIZE)
        .expect("frame header bytes");
    decode_frame_header(PROTOCOL_VERSION, FRAME_MAX_SIZE, header_bytes).expect("frame header")
}
