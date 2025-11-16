use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use shared::error::SharedError;
use shared::schema::VaultArtifact;

use crate::artifacts::io_error;
use crate::constants::{RECIPIENTS_FILE, SIGNATURE_FILE, VAULT_FILE};
use crate::transport::{detect_first_serial_port, open_serial_port};
use crate::{Cli, Command, RepoArgs};

pub use crate::transport::DeviceTransport;

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
        Command::Pull(args) => {
            let mut store = FilesystemArtifactStore::new(&args.repo);
            pull::run(&mut *port, &mut store, &args)
        }
        Command::Push(args) => {
            let mut store = FilesystemArtifactStore::new(&args.repo);
            push::run(&mut *port, &mut store, &args)
        }
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

pub trait RepoArtifactStore {
    fn load(&self, artifact: VaultArtifact) -> Result<Option<Vec<u8>>, SharedError>;
    fn persist(&mut self, artifact: VaultArtifact, data: &[u8]) -> Result<(), SharedError>;
}

pub struct FilesystemArtifactStore {
    repo: PathBuf,
}

impl FilesystemArtifactStore {
    pub fn new(repo: impl AsRef<Path>) -> Self {
        Self {
            repo: repo.as_ref().to_path_buf(),
        }
    }

    fn artifact_path(&self, artifact: VaultArtifact) -> (PathBuf, &'static str) {
        match artifact {
            VaultArtifact::Vault => (self.repo.join(VAULT_FILE), "vault artifact"),
            VaultArtifact::Recipients => (self.repo.join(RECIPIENTS_FILE), "recipients manifest"),
            VaultArtifact::Signature => (self.repo.join(SIGNATURE_FILE), "vault signature"),
        }
    }
}

impl RepoArtifactStore for FilesystemArtifactStore {
    fn load(&self, artifact: VaultArtifact) -> Result<Option<Vec<u8>>, SharedError> {
        let (path, _) = self.artifact_path(artifact);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(io_error("read artifact", &path, err)),
        }
    }

    fn persist(&mut self, artifact: VaultArtifact, data: &[u8]) -> Result<(), SharedError> {
        if data.is_empty() {
            return Ok(());
        }

        let (path, label) = self.artifact_path(artifact);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| io_error("prepare artifact directory", parent, err))?;
        }
        fs::write(&path, data).map_err(|err| io_error("write artifact", &path, err))?;
        println!("Saved {label} to '{}'.", path.display());
        Ok(())
    }
}
