use shared::error::SharedError;
use shared::schema::{DeviceResponse, HostRequest, PushOperationsFrame};

use crate::commands::DeviceTransport;
use crate::transport::{
    CliResponseAdapter, DeviceResponseAdapter, RecordingResponseAdapter, handle_device_response,
    print_ack, read_device_response, send_host_request,
};

pub(crate) fn send_operation_frames<T>(
    transport: &mut T,
    frames: Vec<PushOperationsFrame>,
) -> Result<(), SharedError>
where
    T: DeviceTransport + ?Sized,
{
    let mut cli_adapter = CliResponseAdapter;
    let mut recording_adapter = RecordingResponseAdapter::new(None, None);

    for frame in frames.into_iter() {
        let sequence = frame.sequence;
        let operation_count = frame.operations.len();
        println!(
            "Sending frame #{sequence} with {operation_count} operation{plural} ({last}).",
            plural = if operation_count == 1 { "" } else { "s" },
            last = if frame.is_last {
                "final frame"
            } else {
                "more frames pending"
            }
        );

        let request = HostRequest::PushOps(frame);
        send_host_request(transport, &request)?;

        expect_ack(
            transport,
            &mut cli_adapter,
            &mut recording_adapter,
            "pushing operations",
        )?;
    }

    Ok(())
}

pub(crate) fn expect_ack<T>(
    transport: &mut T,
    cli_adapter: &mut CliResponseAdapter,
    recording_adapter: &mut RecordingResponseAdapter,
    context: &str,
) -> Result<(), SharedError>
where
    T: DeviceTransport + ?Sized,
{
    let response = read_device_response(transport)?;
    match response {
        DeviceResponse::Ack(message) => {
            print_ack(&message);
            Ok(())
        }
        DeviceResponse::Nack(nack) => Err(SharedError::Transport(format!(
            "device rejected {context}: {}",
            nack.message
        ))),
        other => {
            let description = format!("{other:?}");
            let mut adapters: [&mut dyn DeviceResponseAdapter; 2] = [
                cli_adapter as &mut dyn DeviceResponseAdapter,
                recording_adapter,
            ];
            handle_device_response(other, &mut adapters)?;
            Err(SharedError::Transport(format!(
                "unexpected device response while {context}: {description}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::schema::{AckResponse, DeviceErrorCode, NackResponse, PROTOCOL_VERSION};

    use crate::test_support::{MockPort, encode_response};

    #[test]
    fn send_operation_frames_succeeds_with_ack() {
        let frame = PushOperationsFrame {
            protocol_version: PROTOCOL_VERSION,
            sequence: 1,
            checksum: 0,
            is_last: true,
            operations: Vec::new(),
        };

        let ack = encode_response(DeviceResponse::Ack(AckResponse {
            protocol_version: PROTOCOL_VERSION,
            message: "ok".into(),
        }));

        let mut transport = MockPort::new(ack);
        send_operation_frames(&mut transport, vec![frame]).expect("frames sent");
    }

    #[test]
    fn expect_ack_returns_error_for_nack() {
        let nack = encode_response(DeviceResponse::Nack(NackResponse {
            protocol_version: PROTOCOL_VERSION,
            code: DeviceErrorCode::InternalFailure,
            message: "denied".into(),
        }));

        let mut transport = MockPort::new(nack);
        let mut cli_adapter = CliResponseAdapter;
        let mut recording_adapter = RecordingResponseAdapter::new(None, None);

        let error = expect_ack(
            &mut transport,
            &mut cli_adapter,
            &mut recording_adapter,
            "testing",
        )
        .expect_err("nack should fail");

        assert!(format!("{error}").contains("device rejected testing"));
    }
}
