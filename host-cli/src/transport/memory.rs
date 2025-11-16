use std::collections::VecDeque;

use shared::cdc::CdcCommand;
use shared::cdc::transport::command_for_response;
use shared::error::SharedError;
use shared::schema::DeviceResponse;

use super::DeviceTransport;

/// In-memory transport that records transmitted frames and replays queued responses.
#[derive(Default)]
pub struct MemoryDeviceTransport {
    queued_frames: VecDeque<(CdcCommand, Vec<u8>)>,
    pub sent_frames: Vec<(CdcCommand, Vec<u8>)>,
}

impl MemoryDeviceTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a raw CDC frame that will be returned on the next read.
    pub fn queue_frame(&mut self, command: CdcCommand, payload: Vec<u8>) {
        self.queued_frames.push_back((command, payload));
    }

    /// Queue an encoded device response for later consumption.
    pub fn queue_response(&mut self, response: DeviceResponse) -> Result<(), SharedError> {
        let payload = postcard::to_allocvec(&response).map_err(SharedError::from)?;
        let command = command_for_response(&response);
        self.queue_frame(command, payload);
        Ok(())
    }

    /// Access the most recent frame written by the host.
    pub fn last_sent(&self) -> Option<&(CdcCommand, Vec<u8>)> {
        self.sent_frames.last()
    }
}

impl DeviceTransport for MemoryDeviceTransport {
    fn write_frame(&mut self, command: CdcCommand, payload: &[u8]) -> Result<(), SharedError> {
        self.sent_frames.push((command, payload.to_vec()));
        Ok(())
    }

    fn read_frame(&mut self) -> Result<(CdcCommand, Vec<u8>), SharedError> {
        self.queued_frames
            .pop_front()
            .ok_or_else(|| SharedError::Transport("memory transport has no queued frames".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::schema::{AckResponse, DeviceResponse, PROTOCOL_VERSION};

    #[test]
    fn records_sent_frames() {
        let mut transport = MemoryDeviceTransport::new();
        transport
            .write_frame(CdcCommand::Hello, b"ping")
            .expect("write frame");
        let last = transport.last_sent().expect("last frame");
        assert_eq!(last.0, CdcCommand::Hello);
        assert_eq!(last.1, b"ping");
    }

    #[test]
    fn replays_queued_responses() {
        let mut transport = MemoryDeviceTransport::new();
        transport
            .queue_response(DeviceResponse::Ack(AckResponse {
                protocol_version: PROTOCOL_VERSION,
                message: "ok".into(),
            }))
            .expect("queue response");
        let (command, payload) = transport.read_frame().expect("frame");
        assert_eq!(command, CdcCommand::Ack);
        let response: DeviceResponse = postcard::from_bytes(&payload).expect("decode");
        match response {
            DeviceResponse::Ack(message) => assert_eq!(message.message, "ok"),
            other => panic!("unexpected response: {other:?}", other = other),
        }
    }
}
