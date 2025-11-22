use shared::error::SharedError;
use shared::schema::{DeviceResponse, HostRequest};

use crate::transport::DeviceTransport;

pub fn send_host_request<T>(transport: &mut T, request: &HostRequest) -> Result<(), SharedError>
where
    T: DeviceTransport + ?Sized,
{
    transport.send_request(request)
}

pub fn read_device_response<T>(transport: &mut T) -> Result<DeviceResponse, SharedError>
where
    T: DeviceTransport + ?Sized,
{
    transport.read_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    use shared::cdc::CdcCommand;
    use shared::cdc::transport::command_for_response;
    use shared::schema::{AckResponse, DeviceErrorCode, NackResponse, PROTOCOL_VERSION};

    use crate::transport::FrameTransport;

    #[derive(Default)]
    struct FakeFrameTransport {
        frames: VecDeque<(CdcCommand, Vec<u8>)>,
    }

    impl FakeFrameTransport {
        fn push_response(&mut self, response: DeviceResponse) -> Result<(), SharedError> {
            let payload = postcard::to_allocvec(&response).map_err(SharedError::from)?;
            let command = command_for_response(&response);
            self.frames.push_back((command, payload));
            Ok(())
        }

        fn push_frame(&mut self, command: CdcCommand, payload: Vec<u8>) {
            self.frames.push_back((command, payload));
        }
    }

    impl FrameTransport for FakeFrameTransport {
        fn write_frame(
            &mut self,
            _command: CdcCommand,
            _payload: &[u8],
        ) -> Result<(), SharedError> {
            Ok(())
        }

        fn read_frame(&mut self) -> Result<(CdcCommand, Vec<u8>), SharedError> {
            self.frames
                .pop_front()
                .ok_or_else(|| SharedError::Transport("no frames queued".into()))
        }
    }

    #[test]
    fn decodes_ack_response_from_fake_transport() {
        let mut transport = FakeFrameTransport::default();
        transport
            .push_response(DeviceResponse::Ack(AckResponse {
                protocol_version: PROTOCOL_VERSION,
                message: "ok".into(),
            }))
            .expect("queue response");

        let response = read_device_response(&mut transport).expect("response");
        match response {
            DeviceResponse::Ack(message) => assert_eq!(message.message, "ok"),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn surfaces_command_mismatch_from_fake_transport() {
        let nack = DeviceResponse::Nack(NackResponse {
            protocol_version: PROTOCOL_VERSION,
            code: DeviceErrorCode::InternalFailure,
            message: "boom".into(),
        });
        let payload = postcard::to_allocvec(&nack).expect("encode");
        let mut transport = FakeFrameTransport::default();
        transport.push_frame(CdcCommand::PullVault, payload);

        let err = read_device_response(&mut transport).expect_err("expected mismatch");
        match err {
            SharedError::Transport(message) => assert!(message.contains("unexpected command")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn reports_invalid_payload_from_fake_transport() {
        let mut transport = FakeFrameTransport::default();
        transport.push_frame(CdcCommand::Ack, vec![0xFF, 0x00]);

        let err = read_device_response(&mut transport).expect_err("expected decode failure");
        match err {
            SharedError::Transport(_) | SharedError::Codec(_) => {}
        }
    }
}
