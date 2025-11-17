use shared::error::SharedError;

use crate::Cli;
use crate::commands::{self, TransportProvider};
use crate::transport::detect_first_serial_port;
use serialport::SerialPort;

pub struct SerialTransportProvider;

impl TransportProvider for SerialTransportProvider {
    type Transport = dyn SerialPort;

    fn connect(&self, port_path: &str) -> Result<Box<Self::Transport>, SharedError> {
        crate::transport::open_serial_port(port_path)
    }
}

pub fn select_port(cli: &Cli) -> Result<String, SharedError> {
    match &cli.port {
        Some(port) => Ok(port.clone()),
        None => detect_first_serial_port(cli.any_port),
    }
}

pub fn connect_transport<P>(
    cli: &Cli,
    transport_provider: &P,
) -> Result<Box<P::Transport>, SharedError>
where
    P: TransportProvider,
{
    let port_path = select_port(cli)?;
    println!("Connecting to Cardputer on {port_path}…");
    transport_provider.connect(&port_path)
}

pub fn execute<P>(cli: Cli, transport_provider: &P) -> Result<(), SharedError>
where
    P: TransportProvider,
{
    let mut transport = connect_transport(&cli, transport_provider)?;
    commands::run(cli, &mut *transport)
}
