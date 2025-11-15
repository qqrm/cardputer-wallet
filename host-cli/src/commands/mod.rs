use shared::error::SharedError;

use crate::transport::{detect_first_serial_port, open_serial_port};
use crate::{Cli, Command, RepoArgs};

pub mod confirm;
pub mod get_time;
pub mod hello;
pub mod host_config;
pub mod pull;
pub mod pull_head;
pub mod push;
pub mod set_time;
pub mod signature;
pub mod status;

pub fn run(cli: Cli) -> Result<(), SharedError> {
    let port_path = match cli.port {
        Some(port) => port,
        None => detect_first_serial_port(cli.any_port)?,
    };

    println!("Connecting to Cardputer on {port_path}…");
    let mut port = open_serial_port(&port_path)?;

    match cli.command {
        Command::Hello => hello::run(&mut *port),
        Command::Status => status::run(&mut *port),
        Command::SetTime(args) => set_time::run(&mut *port, &args),
        Command::GetTime => get_time::run(&mut *port),
        Command::PullHead => pull_head::run(&mut *port),
        Command::Pull(args) => pull::run(&mut *port, &args),
        Command::Push(args) => push::run(&mut *port, &args),
        Command::Confirm(args) => confirm::run(&mut *port, &args),
    }
}

pub(crate) fn print_repo_banner(args: &RepoArgs) {
    println!(
        "Preparing repository '{}' using credentials '{}'",
        args.repo.display(),
        args.credentials.display()
    );
}
