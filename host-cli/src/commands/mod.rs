use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use shared::error::SharedError;
use shared::schema::VaultArtifact;

use crate::artifacts::io_error;
use crate::constants::{RECIPIENTS_FILE, SIGNATURE_FILE, VAULT_FILE};
use crate::{Cli, Command, RepoArgs};

pub use crate::transport::DeviceTransport;

pub trait TransportProvider {
    type Transport: DeviceTransport + ?Sized;

    fn connect(&self, port_path: &str) -> Result<Box<Self::Transport>, SharedError>;
}

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

pub fn run<T>(cli: Cli, transport: &mut T) -> Result<(), SharedError>
where
    T: DeviceTransport + ?Sized,
{
    match cli.command {
        Command::Hello => hello::run(transport),
        Command::Status => status::run(transport),
        Command::SetTime(args) => set_time::run(transport, &args),
        Command::GetTime => get_time::run(transport),
        Command::PullHead => pull_head::run(transport),
        Command::Pull(args) => {
            let mut store = FilesystemArtifactStore::new(&args.repo);
            pull::run(transport, &mut store, &args)
        }
        Command::Push(args) => {
            let mut store = FilesystemArtifactStore::new(&args.repo);
            push::run(transport, &mut store, &args)
        }
        Command::Confirm(args) => confirm::run(transport, &args),
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
