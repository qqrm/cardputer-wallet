use std::io::{Read, Write};

use shared::error::SharedError;
use shared::schema::{AckRequest, HostRequest, PROTOCOL_VERSION};

use crate::RepoArgs;
use crate::artifacts::load_sync_state;
use crate::commands::print_repo_banner;
use crate::transport::{handle_device_response, read_device_response, send_host_request};

pub fn run<P>(port: &mut P, args: &RepoArgs) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    print_repo_banner(args);

    let state = load_sync_state(&args.repo)?.ok_or_else(|| {
        eprintln!(
            "Missing journal state in '{}'. Run pull before confirming a push.",
            args.repo.display()
        );
        SharedError::Transport("journal state not found for push acknowledgement".into())
    })?;

    let request = HostRequest::Ack(AckRequest {
        protocol_version: PROTOCOL_VERSION,
        last_frame_sequence: state.sequence,
        journal_checksum: state.checksum,
    });

    send_host_request(port, &request)?;
    println!("Acknowledgement sent. Awaiting confirmation…");

    loop {
        let response = read_device_response(port)?;
        if !handle_device_response(response, None, None)? {
            break;
        }
    }

    Ok(())
}
