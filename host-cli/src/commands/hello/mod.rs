use shared::error::SharedError;
use shared::schema::{HelloRequest, HostRequest, PROTOCOL_VERSION};

use crate::commands::DeviceTransport;
use crate::transport::{handle_device_response, read_device_response, send_host_request};

pub fn run<P>(port: &mut P) -> Result<(), SharedError>
where
    P: DeviceTransport + ?Sized,
{
    let request = HostRequest::Hello(HelloRequest {
        protocol_version: PROTOCOL_VERSION,
        client_name: env!("CARGO_PKG_NAME").into(),
        client_version: env!("CARGO_PKG_VERSION").into(),
    });
    send_host_request(port, &request)?;
    let response = read_device_response(port)?;
    handle_device_response(response, None, None)?;
    Ok(())
}
