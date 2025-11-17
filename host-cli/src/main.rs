mod application;
mod artifacts;
mod commands;
mod constants;
mod transport;

#[cfg(not(feature = "transport-usb"))]
compile_error!("Enable at least one host transport feature (currently only `transport-usb`).");

#[cfg(test)]
mod tests;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use shared::error::SharedError;

use crate::application::SerialTransportProvider;

#[derive(Parser, Debug)]
#[command(author, version, about = "Cardputer host command line interface")]
pub struct Cli {
    /// Optional path to the serial device. Falls back to auto-detection when omitted.
    #[arg(short, long)]
    pub port: Option<String>,

    /// Skip Cardputer VID/PID filtering and accept the first USB serial device.
    #[arg(long)]
    pub any_port: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Perform the HELLO handshake and print device metadata.
    Hello,
    /// Query the device for its current sync status.
    Status,
    /// Update the device clock.
    SetTime(SetTimeArgs),
    /// Read the device clock value.
    GetTime,
    /// Request the latest vault head metadata.
    PullHead,
    /// Fetch the latest vault data from the device.
    Pull(RepoArgs),
    /// Push local journal operations to the device.
    Push(RepoArgs),
    /// Confirm completion of a device initiated push flow.
    Confirm(RepoArgs),
}

#[derive(Args, Debug, Clone)]
pub struct RepoArgs {
    /// Path to the repository that should receive or provide data.
    #[arg(long, value_name = "PATH")]
    pub repo: std::path::PathBuf,
    /// Path to the credentials file used during the operation.
    #[arg(long, value_name = "PATH")]
    pub credentials: std::path::PathBuf,
    /// Optional path to a file containing the Ed25519 verifying key in base64 or hex.
    #[arg(long, value_name = "PATH")]
    pub signing_pubkey: Option<std::path::PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct SetTimeArgs {
    /// Epoch milliseconds to send to the device.
    #[arg(long, value_name = "MILLIS", conflicts_with = "system")]
    pub epoch_ms: Option<u64>,
    /// Use the host system time instead of an explicit value.
    #[arg(long)]
    pub system: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let provider = SerialTransportProvider;

    if let Err(err) = application::execute(cli, &provider) {
        match &err {
            SharedError::Transport(_) => {
                eprintln!("Transport failure: {err}");
            }
            SharedError::Codec(_) => {
                eprintln!("Codec error: {err}");
            }
        }
        return Err(anyhow::Error::from(err));
    }

    Ok(())
}
