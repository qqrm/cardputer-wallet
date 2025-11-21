use shared::cdc::CdcCommand;
use shared::schema::{DeviceResponse, HelloResponse, PROTOCOL_VERSION};

use crate::{Cli, Command, commands};

#[test]
fn run_uses_supplied_transport_without_opening_ports() {
    let cli = Cli {
        port: Some("/dev/null".into()),
        any_port: false,
        command: Command::Hello,
    };

    let mut transport = crate::transport::memory::MemoryDeviceTransport::new();
    transport
        .queue_response(DeviceResponse::Hello(HelloResponse {
            protocol_version: PROTOCOL_VERSION,
            device_name: "Test".into(),
            firmware_version: "0.0.0".into(),
            session_id: 1,
        }))
        .expect("queue response");

    commands::run(cli, &mut transport).expect("run succeeds");

    let last = transport.last_sent().expect("sent frame");
    assert_eq!(last.0, CdcCommand::Hello);
}
