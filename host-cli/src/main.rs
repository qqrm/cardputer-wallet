use anyhow::Result;
use clap::Parser;
use serialport::SerialPortType;

#[derive(Parser, Debug)]
#[command(author, version, about = "Cardputer host command line interface")]
struct Cli {
    /// Optional path to the serial device. Falls back to auto-detection when omitted.
    #[arg(short, long)]
    port: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let port = match cli.port {
        Some(port) => port,
        None => {
            detect_first_serial_port()?.ok_or_else(|| anyhow::anyhow!("no CDC device found"))?
        }
    };

    println!("Connecting to Cardputer on {port}…");
    // TODO: add CBOR request/response handling using the shared schema.
    Ok(())
}

fn detect_first_serial_port() -> Result<Option<String>> {
    let ports = serialport::available_ports()?;
    let port = ports
        .into_iter()
        .find(|p| matches!(p.port_type, SerialPortType::UsbPort(_)))
        .map(|p| p.port_name);
    Ok(port)
}
