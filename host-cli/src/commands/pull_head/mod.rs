use std::io::{Read, Write};

use shared::error::SharedError;
use shared::schema::{HostRequest, PROTOCOL_VERSION, PullHeadRequest};

use crate::transport::{
    handle_device_response, print_head, read_device_response, send_host_request,
};

pub fn run<P>(port: &mut P) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    let request = HostRequest::PullHead(PullHeadRequest {
        protocol_version: PROTOCOL_VERSION,
    });

    send_host_request(port, &request)?;
    let response = read_device_response(port)?;
    match response {
        shared::schema::DeviceResponse::Head(head) => {
            print_head(&head);
            Ok(())
        }
        other => {
            handle_device_response(other, None, None)?;
            Err(SharedError::Transport(
                "unexpected device response while fetching head metadata".into(),
            ))
        }
    }
}
