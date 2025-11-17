use std::time::{SystemTime, UNIX_EPOCH};

use shared::error::SharedError;
use shared::schema::{GetTimeRequest, HostRequest, PROTOCOL_VERSION, SetTimeRequest};

use crate::SetTimeArgs;
use crate::commands::DeviceTransport;
use crate::transport::{handle_device_response, read_device_response, send_host_request};

pub fn run<P>(port: &mut P, args: &SetTimeArgs) -> Result<(), SharedError>
where
    P: DeviceTransport + ?Sized,
{
    let epoch = if args.system {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| SharedError::Transport(format!("system time is before epoch: {err}")))?
            .as_millis() as u64
    } else if let Some(value) = args.epoch_ms {
        value
    } else {
        return Err(SharedError::Transport(
            "either --epoch-ms or --system must be provided".into(),
        ));
    };

    let request = HostRequest::SetTime(SetTimeRequest {
        protocol_version: PROTOCOL_VERSION,
        epoch_millis: epoch,
    });
    send_host_request(port, &request)?;

    let response = read_device_response(port)?;
    handle_device_response(response, None, None)?;
    Ok(())
}

pub fn run_get_time<P>(port: &mut P) -> Result<(), SharedError>
where
    P: DeviceTransport + ?Sized,
{
    let request = HostRequest::GetTime(GetTimeRequest {
        protocol_version: PROTOCOL_VERSION,
    });
    send_host_request(port, &request)?;

    let response = read_device_response(port)?;
    handle_device_response(response, None, None)?;
    Ok(())
}
