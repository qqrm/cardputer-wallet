use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD as Base64};
use blake3::Hasher;
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hex::decode as hex_decode;
use postcard::{from_bytes as postcard_from_bytes, to_allocvec as postcard_to_allocvec};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_cbor::{from_slice as cbor_from_slice, to_vec as cbor_to_vec};
use serde_json::from_str as json_from_str;
use serialport::{SerialPort, SerialPortType};

use shared::cdc::transport::{
    FrameTransportError, command_for_request, command_for_response, decode_frame,
    decode_frame_header, encode_frame,
};
use shared::cdc::{CdcCommand, FRAME_HEADER_SIZE, compute_crc32};
#[cfg(test)]
use shared::cdc::FrameHeader;
use shared::checksum::accumulate_checksum;
use shared::error::SharedError;
use shared::journal::{FrameState, FrameTracker, JournalHasher};
use shared::schema::{
    AckRequest, AckResponse, DeviceResponse, GetTimeRequest, HelloRequest, HelloResponse,
    HostRequest, JournalFrame, JournalOperation as DeviceJournalOperation, PROTOCOL_VERSION,
    PullHeadRequest, PullHeadResponse, PullVaultRequest, PushOperationsFrame, PushVaultFrame,
    SetTimeRequest, StatusRequest, StatusResponse, TimeResponse, VaultArtifact, VaultChunk,
    decode_journal_operations, encode_journal_operations,
};
use shared::vault::{
    EntryUpdate, JournalOperation as VaultJournalOperation, LegacyField, PageCipher, VaultEntry,
    VaultMetadata,
};
use uuid::Uuid;

const SERIAL_BAUD_RATE: u32 = 115_200;
const DEFAULT_TIMEOUT_SECS: u64 = 2;
const HOST_BUFFER_SIZE: u32 = 64 * 1024;
const MAX_CHUNK_SIZE: u32 = 4 * 1024;
const SIGNATURE_SIZE: usize = 64;
const CARDPUTER_USB_VID: u16 = 0x303A;
const CARDPUTER_USB_PID: u16 = 0x4001;
const CARDPUTER_IDENTITY_KEYWORDS: &[&str] = &["cardputer", "m5stack"];
const SYNC_STATE_FILE: &str = ".cardputer-sync-state";
const LOCAL_OPERATIONS_FILE: &str = ".cardputer-journal.postcard";
const LEGACY_LOCAL_OPERATIONS_FILE: &str = ".cardputer-journal.cbor";
const PUSH_FRAME_MAX_PAYLOAD: usize = (HOST_BUFFER_SIZE as usize).saturating_sub(1024);
const VAULT_FILE: &str = "vault.enc";
const RECIPIENTS_FILE: &str = "recips.json";
const SIGNATURE_FILE: &str = "vault.sig";
const CONFIG_FILE: &str = "config.json";
const SIGNATURE_DOMAIN: &[u8] = b"cardputer.vault.signature.v1";
const VAULT_AAD: &[u8] = b"cardputer.vault.snapshot.v1";
const VAULT_NONCE_SIZE: usize = 12;

#[derive(Parser, Debug)]
#[command(author, version, about = "Cardputer host command line interface")]
struct Cli {
    /// Optional path to the serial device. Falls back to auto-detection when omitted.
    #[arg(short, long)]
    port: Option<String>,

    /// Skip Cardputer VID/PID filtering and accept the first USB serial device.
    #[arg(long)]
    any_port: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
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
struct RepoArgs {
    /// Path to the repository that should receive or provide data.
    #[arg(long, value_name = "PATH")]
    repo: PathBuf,
    /// Path to the credentials file used during the operation.
    #[arg(long, value_name = "PATH")]
    credentials: PathBuf,
    /// Optional path to a file containing the Ed25519 verifying key in base64 or hex.
    #[arg(long, value_name = "PATH")]
    signing_pubkey: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
struct SetTimeArgs {
    /// Epoch milliseconds to send to the device.
    #[arg(long, value_name = "MILLIS", conflicts_with = "system")]
    epoch_ms: Option<u64>,
    /// Use the host system time instead of an explicit value.
    #[arg(long)]
    system: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
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

fn run(cli: Cli) -> Result<(), SharedError> {
    let port_path = match cli.port {
        Some(port) => port,
        None => detect_first_serial_port(cli.any_port)?,
    };

    println!("Connecting to Cardputer on {port_path}…");
    let mut port = open_serial_port(&port_path)?;

    match cli.command {
        Command::Hello => execute_hello(&mut *port),
        Command::Status => execute_status(&mut *port),
        Command::SetTime(args) => execute_set_time(&mut *port, &args),
        Command::GetTime => execute_get_time(&mut *port),
        Command::PullHead => execute_pull_head(&mut *port),
        Command::Pull(args) => execute_pull(&mut *port, &args),
        Command::Push(args) => execute_push(&mut *port, &args),
        Command::Confirm(args) => execute_confirm(&mut *port, &args),
    }
}

fn execute_pull<P>(port: &mut P, args: &RepoArgs) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    println!(
        "Preparing pull for repository '{}' using credentials '{}'",
        args.repo.display(),
        args.credentials.display()
    );

    let config = HostConfig::load(&args.credentials)?;
    let verifying_key = load_verifying_key(&config, args.signing_pubkey.as_deref())?;

    let head_request = HostRequest::PullHead(PullHeadRequest {
        protocol_version: PROTOCOL_VERSION,
    });

    send_host_request(port, &head_request)?;
    println!("Requested head metadata. Awaiting response…");

    let mut artifacts = PullArtifacts::default();
    let head_response = read_device_response(port)?;
    let DeviceResponse::Head(head) = head_response else {
        handle_device_response(head_response, None, Some(&mut artifacts))?;
        return Err(SharedError::Transport(
            "unexpected device response while fetching head metadata".into(),
        ));
    };

    print_head(&head);
    artifacts.record_log("head response");
    let recipients_expected = head.recipients_hash != [0u8; 32];
    artifacts.set_recipients_expected(recipients_expected);
    let signature_expected = head.signature_hash != [0u8; 32];
    artifacts.set_signature_expected(signature_expected);

    let request = HostRequest::PullVault(PullVaultRequest {
        protocol_version: PROTOCOL_VERSION,
        host_buffer_size: HOST_BUFFER_SIZE,
        max_chunk_size: MAX_CHUNK_SIZE,
        known_generation: None,
    });

    send_host_request(port, &request)?;
    println!("Request sent. Waiting for device responses…");

    let mut state_tracker = FrameTracker::default();
    let mut should_continue = true;

    while should_continue {
        let response = read_device_response(port)?;
        should_continue =
            handle_device_response(response, Some(&mut state_tracker), Some(&mut artifacts))?;
        if should_continue {
            send_host_request(port, &request)?;
        }
    }

    verify_pulled_signature(&artifacts, &args.repo, verifying_key.as_ref())?;
    artifacts.persist(&args.repo)?;
    persist_sync_state(&args.repo, state_tracker.state())
}

fn execute_push<P>(port: &mut P, args: &RepoArgs) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    println!(
        "Preparing push for repository '{}' using credentials '{}'",
        args.repo.display(),
        args.credentials.display()
    );

    let config = HostConfig::load(&args.credentials)?;
    let operations = load_local_operations(&args.repo, &config)?;
    if operations.is_empty() {
        println!("No pending operations to push.");
        return Ok(());
    }

    apply_operations_to_repo(&args.repo, &config, &operations)?;

    let plan = PushPlan::from_operations(&operations)?;

    println!(
        "Dispatching {} operation{} across {} frame{}…",
        plan.total_operations,
        if plan.total_operations == 1 { "" } else { "s" },
        plan.frames.len(),
        if plan.frames.len() == 1 { "" } else { "s" }
    );

    push_vault_artifacts(port, &args.repo)?;

    for frame in plan.frames.into_iter() {
        let sequence = frame.sequence;
        let operation_count = frame.operations.len();
        println!(
            "Sending frame #{sequence} with {operation_count} operation{plural} ({last}).",
            plural = if operation_count == 1 { "" } else { "s" },
            last = if frame.is_last {
                "final frame"
            } else {
                "more frames pending"
            }
        );

        let request = HostRequest::PushOps(frame);
        send_host_request(port, &request)?;

        let response = read_device_response(port)?;
        let DeviceResponse::Ack(message) = response else {
            let description = format!("{response:?}");
            handle_device_response(response, None, None)?;
            return Err(SharedError::Transport(format!(
                "unexpected device response while pushing operations: {description}"
            )));
        };
        print_ack(&message);
    }

    clear_local_operations(&args.repo)?;
    println!("Push operations completed. Cleared local journal state.");
    Ok(())
}

fn push_vault_artifacts<P>(port: &mut P, repo: &Path) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    let descriptors = [
        (VaultArtifact::Vault, repo.join(VAULT_FILE), "vault image"),
        (
            VaultArtifact::Recipients,
            repo.join(RECIPIENTS_FILE),
            "recipients manifest",
        ),
        (
            VaultArtifact::Signature,
            repo.join(SIGNATURE_FILE),
            "vault signature",
        ),
    ];

    let mut sequence = 1u32;

    for (artifact, path, label) in descriptors.into_iter() {
        if !path.exists() {
            continue;
        }

        let data = fs::read(&path).map_err(|err| io_error("read artifact", &path, err))?;

        if matches!(artifact, VaultArtifact::Signature) && data.len() != SIGNATURE_SIZE {
            return Err(SharedError::Transport(format!(
                "signature artifact '{}' must be exactly {} bytes (found {})",
                path.display(),
                SIGNATURE_SIZE,
                data.len()
            )));
        }

        println!(
            "Sending {label} ({} byte{}).",
            data.len(),
            if data.len() == 1 { "" } else { "s" }
        );

        let total_size = data.len() as u64;
        let chunk_size = MAX_CHUNK_SIZE as usize;
        let mut offset = 0usize;
        let mut first = true;

        while offset < data.len() || (first && data.is_empty()) {
            first = false;
            let end = (offset + chunk_size).min(data.len());
            let chunk = data[offset..end].to_vec();
            let remaining = total_size.saturating_sub(end as u64);
            offset = end;
            let checksum = accumulate_checksum(0, &chunk);

            let frame = PushVaultFrame {
                protocol_version: PROTOCOL_VERSION,
                sequence,
                artifact,
                total_size,
                remaining_bytes: remaining,
                data: chunk,
                checksum,
                is_last: remaining == 0,
            };
            sequence = sequence.saturating_add(1);

            let request = HostRequest::PushVault(frame);
            send_host_request(port, &request)?;
            let response = read_device_response(port)?;
            let DeviceResponse::Ack(message) = response else {
                if let DeviceResponse::Nack(nack) = response {
                    return Err(SharedError::Transport(format!(
                        "device rejected {label}: {}",
                        nack.message
                    )));
                }
                let description = format!("{response:?}");
                handle_device_response(response, None, None)?;
                return Err(SharedError::Transport(format!(
                    "unexpected device response while pushing {label}: {description}"
                )));
            };
            print_ack(&message);

            if remaining == 0 {
                break;
            }
        }
    }

    Ok(())
}

fn execute_confirm<P>(port: &mut P, args: &RepoArgs) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    println!(
        "Finalising push for repository '{}' using credentials '{}'",
        args.repo.display(),
        args.credentials.display()
    );

    let (sequence, checksum) = load_sync_state(&args.repo)?.ok_or_else(|| {
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

struct PushPlan {
    frames: Vec<PushOperationsFrame>,
    total_operations: usize,
}

impl PushPlan {
    fn from_operations(operations: &[VaultJournalOperation]) -> Result<Self, SharedError> {
        if operations.is_empty() {
            return Ok(Self {
                frames: Vec::new(),
                total_operations: 0,
            });
        }

        let frames = build_push_frames(operations)?;
        let total_operations = frames.iter().map(|frame| frame.operations.len()).sum();

        Ok(Self {
            frames,
            total_operations,
        })
    }
}

fn load_local_operations(
    repo_path: &Path,
    config: &HostConfig,
) -> Result<Vec<VaultJournalOperation>, SharedError> {
    let path = operations_log_path(repo_path);
    let data = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return migrate_legacy_operations(repo_path, &path);
        }
        Err(err) => {
            return Err(SharedError::Transport(format!(
                "failed to read local operations from '{}': {err}",
                path.display()
            )));
        }
    };

    if data.is_empty() {
        return Ok(Vec::new());
    }

    match decode_postcard_operations(&data) {
        Ok(operations) => Ok(operations),
        Err(primary) => match decode_journal_operations(&data) {
            Ok(device_ops) => {
                let converted = convert_device_operations(repo_path, config, device_ops)?;
                persist_host_operations(&path, &converted)?;
                Ok(converted)
            }
            Err(_) => Err(SharedError::Transport(format!(
                "failed to decode journal operations: {primary}"
            ))),
        },
    }
}

fn decode_postcard_operations(data: &[u8]) -> Result<Vec<VaultJournalOperation>, postcard::Error> {
    postcard_from_bytes(data)
}

fn migrate_legacy_operations(
    repo_path: &Path,
    new_path: &Path,
) -> Result<Vec<VaultJournalOperation>, SharedError> {
    let legacy_path = legacy_operations_log_path(repo_path);
    let legacy_data = match fs::read(&legacy_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(SharedError::Transport(format!(
                "failed to read legacy local operations from '{}': {err}",
                legacy_path.display()
            )));
        }
    };

    if legacy_data.is_empty() {
        let _ = fs::remove_file(&legacy_path);
        return Ok(Vec::new());
    }

    let operations: Vec<VaultJournalOperation> = cbor_from_slice(&legacy_data).map_err(|err| {
        SharedError::Transport(format!(
            "failed to decode legacy local operations from '{}': {err}",
            legacy_path.display()
        ))
    })?;

    let encoded = postcard_to_allocvec(&operations).map_err(|err| {
        SharedError::Transport(format!(
            "failed to encode migrated operations for '{}': {err}",
            new_path.display()
        ))
    })?;
    fs::write(new_path, &encoded).map_err(|err| {
        SharedError::Transport(format!(
            "failed to write migrated operations to '{}': {err}",
            new_path.display()
        ))
    })?;

    match fs::remove_file(&legacy_path) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(SharedError::Transport(format!(
                "failed to remove legacy operations file '{}': {err}",
                legacy_path.display()
            )));
        }
    }

    Ok(operations)
}

enum LegacyConvertedOp {
    Update(Uuid),
    Add(Uuid),
    Delete(Uuid),
}

fn convert_device_operations(
    repo_path: &Path,
    config: &HostConfig,
    device_ops: Vec<DeviceJournalOperation>,
) -> Result<Vec<VaultJournalOperation>, SharedError> {
    if device_ops.is_empty() {
        return Ok(Vec::new());
    }

    let vault_key = config
        .vault_key()
        .ok_or_else(|| SharedError::Transport("vault key missing from credentials".into()))?;
    let vault_path = repo_path.join(VAULT_FILE);
    let encrypted = fs::read(&vault_path).map_err(|err| {
        SharedError::Transport(format!(
            "failed to read vault from '{}': {err}",
            vault_path.display()
        ))
    })?;
    let snapshot = decrypt_vault(&encrypted, &vault_key)?;
    let mut snapshot_entries: BTreeMap<Uuid, VaultEntry> = snapshot
        .entries
        .into_iter()
        .map(|entry| (entry.id, entry))
        .collect();

    let mut pending_updates: BTreeMap<Uuid, EntryUpdate> = BTreeMap::new();
    let mut sequence: Vec<LegacyConvertedOp> = Vec::new();

    for operation in device_ops {
        match operation {
            DeviceJournalOperation::Add { entry_id } => {
                let id = parse_legacy_uuid(&entry_id)?;
                if pending_updates.contains_key(&id)
                    && !sequence.iter().any(|item| matches!(item, LegacyConvertedOp::Update(existing) if existing == &id))
                {
                    sequence.push(LegacyConvertedOp::Update(id));
                }
                sequence.push(LegacyConvertedOp::Add(id));
            }
            DeviceJournalOperation::UpdateField {
                entry_id,
                field,
                value_checksum,
            } => {
                let id = parse_legacy_uuid(&entry_id)?;
                let entry = find_entry(&snapshot_entries, &id)?;
                let update = get_or_insert_update(&mut pending_updates, &id);
                let field = LegacyField::try_from(field.as_str())
                    .map_err(|err| SharedError::Transport(err.to_string()))?;
                apply_field_update_from_entry(&id, entry, field, value_checksum, update)?;
                if !sequence.iter().any(
                    |item| matches!(item, LegacyConvertedOp::Update(existing) if existing == &id),
                ) {
                    sequence.push(LegacyConvertedOp::Update(id));
                }
            }
            DeviceJournalOperation::Delete { entry_id } => {
                let id = parse_legacy_uuid(&entry_id)?;
                if pending_updates.contains_key(&id)
                    && !sequence.iter().any(|item| matches!(item, LegacyConvertedOp::Update(existing) if existing == &id))
                {
                    sequence.push(LegacyConvertedOp::Update(id));
                }
                sequence.push(LegacyConvertedOp::Delete(id));
            }
        }
    }

    let mut host_ops = Vec::new();
    for item in sequence {
        match item {
            LegacyConvertedOp::Update(id) => {
                if let Some(update) = take_pending_update(&mut pending_updates, &id) {
                    host_ops.push(VaultJournalOperation::Update {
                        id,
                        changes: update,
                    });
                }
            }
            LegacyConvertedOp::Add(id) => {
                let entry = snapshot_entries.remove(&id).ok_or_else(|| {
                    SharedError::Transport(format!(
                        "legacy operations reference unknown entry {}",
                        id
                    ))
                })?;
                host_ops.push(VaultJournalOperation::Add { entry });
            }
            LegacyConvertedOp::Delete(id) => {
                if let Some(update) = take_pending_update(&mut pending_updates, &id) {
                    host_ops.push(VaultJournalOperation::Update {
                        id,
                        changes: update,
                    });
                }
                host_ops.push(VaultJournalOperation::Delete { id });
            }
        }
    }

    for (id, changes) in pending_updates.into_iter() {
        if !entry_update_is_empty(&changes) {
            host_ops.push(VaultJournalOperation::Update { id, changes });
        }
    }

    Ok(host_ops)
}

fn persist_host_operations(
    path: &Path,
    operations: &[VaultJournalOperation],
) -> Result<(), SharedError> {
    let encoded = postcard_to_allocvec(operations).map_err(|err| {
        SharedError::Transport(format!("failed to encode migrated operations: {err}"))
    })?;
    fs::write(path, encoded).map_err(|err| {
        SharedError::Transport(format!(
            "failed to write migrated operations to '{}': {err}",
            path.display()
        ))
    })
}

fn parse_legacy_uuid(raw: &str) -> Result<Uuid, SharedError> {
    Uuid::parse_str(raw).map_err(|err| {
        SharedError::Transport(format!("invalid legacy entry identifier '{raw}': {err}"))
    })
}

fn find_entry<'a>(
    entries: &'a BTreeMap<Uuid, VaultEntry>,
    id: &Uuid,
) -> Result<&'a VaultEntry, SharedError> {
    entries.get(id).ok_or_else(|| {
        SharedError::Transport(format!("legacy operations reference unknown entry {id}"))
    })
}

fn get_or_insert_update<'a>(
    updates: &'a mut BTreeMap<Uuid, EntryUpdate>,
    id: &Uuid,
) -> &'a mut EntryUpdate {
    updates.entry(*id).or_default()
}

fn take_pending_update(
    updates: &mut BTreeMap<Uuid, EntryUpdate>,
    id: &Uuid,
) -> Option<EntryUpdate> {
    updates
        .remove(id)
        .filter(|update| !entry_update_is_empty(update))
}

fn entry_update_is_empty(update: &EntryUpdate) -> bool {
    update.title.is_none()
        && update.service.is_none()
        && update.domains.is_none()
        && update.username.is_none()
        && update.password.is_none()
        && update.totp.is_none()
        && update.tags.is_none()
        && update.r#macro.is_none()
        && update.updated_at.is_none()
        && update.used_at.is_none()
}

fn apply_field_update_from_entry(
    id: &Uuid,
    entry: &VaultEntry,
    field: LegacyField,
    expected_checksum: u32,
    update: &mut EntryUpdate,
) -> Result<(), SharedError> {
    match field {
        LegacyField::Title => {
            verify_checksum(id, field, expected_checksum, entry.title.as_bytes())?;
            update.title = Some(entry.title.clone());
        }
        LegacyField::Service => {
            verify_checksum(id, field, expected_checksum, entry.service.as_bytes())?;
            update.service = Some(entry.service.clone());
        }
        LegacyField::Domains => {
            let encoded = cbor_to_vec(&entry.domains).map_err(|err| {
                SharedError::Transport(format!("failed to encode domains for entry {id}: {err}"))
            })?;
            verify_checksum(id, field, expected_checksum, &encoded)?;
            update.domains = Some(entry.domains.clone());
        }
        LegacyField::Username => {
            verify_checksum(id, field, expected_checksum, entry.username.as_bytes())?;
            update.username = Some(entry.username.clone());
        }
        LegacyField::Password => {
            verify_checksum(id, field, expected_checksum, entry.password.as_bytes())?;
            update.password = Some(entry.password.clone());
        }
        LegacyField::Totp => {
            let Some(totp) = entry.totp.as_ref() else {
                return Err(SharedError::Transport(format!(
                    "legacy operations reference missing TOTP configuration for entry {id}"
                )));
            };
            let encoded = cbor_to_vec(totp).map_err(|err| {
                SharedError::Transport(format!("failed to encode TOTP for entry {id}: {err}"))
            })?;
            verify_checksum(id, field, expected_checksum, &encoded)?;
            update.totp = Some(totp.clone());
        }
        LegacyField::Tags => {
            let encoded = cbor_to_vec(&entry.tags).map_err(|err| {
                SharedError::Transport(format!("failed to encode tags for entry {id}: {err}"))
            })?;
            verify_checksum(id, field, expected_checksum, &encoded)?;
            update.tags = Some(entry.tags.clone());
        }
        LegacyField::Macro => {
            let Some(value) = entry.r#macro.as_ref() else {
                return Err(SharedError::Transport(format!(
                    "legacy operations reference missing macro for entry {id}"
                )));
            };
            verify_checksum(id, field, expected_checksum, value.as_bytes())?;
            update.r#macro = Some(value.clone());
        }
        LegacyField::UpdatedAt => {
            verify_checksum(id, field, expected_checksum, entry.updated_at.as_bytes())?;
            update.updated_at = Some(entry.updated_at.clone());
        }
        LegacyField::UsedAt => {
            let encoded = cbor_to_vec(&entry.used_at).map_err(|err| {
                SharedError::Transport(format!("failed to encode used_at for entry {id}: {err}"))
            })?;
            verify_checksum(id, field, expected_checksum, &encoded)?;
            update.used_at = Some(entry.used_at.clone());
        }
    }

    Ok(())
}

fn verify_checksum(
    id: &Uuid,
    field: LegacyField,
    expected: u32,
    bytes: &[u8],
) -> Result<(), SharedError> {
    let actual = compute_crc32(bytes);
    if actual != expected {
        return Err(SharedError::Transport(format!(
            "legacy journal checksum mismatch for field '{field}' in entry {id}"
        )));
    }
    Ok(())
}

fn build_push_frames(
    operations: &[VaultJournalOperation],
) -> Result<Vec<PushOperationsFrame>, SharedError> {
    let mut flattened: Vec<DeviceJournalOperation> = Vec::new();
    for operation in operations {
        flattened.extend(operations_for_device(operation)?);
    }

    let mut frames: Vec<Vec<DeviceJournalOperation>> = Vec::new();
    let mut current: Vec<DeviceJournalOperation> = Vec::new();

    for operation in flattened {
        current.push(operation);
        let encoded_len = encode_journal_operations(&current)?.len();
        if encoded_len > PUSH_FRAME_MAX_PAYLOAD {
            let last = current
                .pop()
                .expect("pushed operation missing when building push frames");

            if current.is_empty() {
                return Err(SharedError::Transport(format!(
                    "operation payload exceeds maximum frame size of {} bytes",
                    PUSH_FRAME_MAX_PAYLOAD
                )));
            }

            frames.push(std::mem::take(&mut current));
            current.push(last);
            let single_len = encode_journal_operations(&current)?.len();
            if single_len > PUSH_FRAME_MAX_PAYLOAD {
                return Err(SharedError::Transport(format!(
                    "operation payload exceeds maximum frame size of {} bytes",
                    PUSH_FRAME_MAX_PAYLOAD
                )));
            }
        }
    }

    if !current.is_empty() {
        frames.push(current);
    }

    let total = frames.len();
    Ok(frames
        .into_iter()
        .enumerate()
        .map(|(index, operations)| PushOperationsFrame {
            protocol_version: PROTOCOL_VERSION,
            sequence: index as u32 + 1,
            checksum: compute_local_journal_checksum(&operations),
            is_last: index + 1 == total,
            operations,
        })
        .collect())
}

fn operations_for_device(
    operation: &VaultJournalOperation,
) -> Result<Vec<DeviceJournalOperation>, SharedError> {
    match operation {
        VaultJournalOperation::Add { entry } => Ok(vec![DeviceJournalOperation::Add {
            entry_id: entry.id.to_string(),
        }]),
        VaultJournalOperation::Update { id, changes } => build_update_operations(id, changes),
        VaultJournalOperation::Delete { id } => Ok(vec![DeviceJournalOperation::Delete {
            entry_id: id.to_string(),
        }]),
    }
}

fn build_update_operations(
    id: &Uuid,
    changes: &EntryUpdate,
) -> Result<Vec<DeviceJournalOperation>, SharedError> {
    let entry_id = id.to_string();
    let mut operations = Vec::new();

    if let Some(value) = &changes.title {
        push_update_bytes(
            &mut operations,
            &entry_id,
            LegacyField::Title,
            value.as_bytes(),
        );
    }

    if let Some(value) = &changes.service {
        push_update_bytes(
            &mut operations,
            &entry_id,
            LegacyField::Service,
            value.as_bytes(),
        );
    }

    if let Some(value) = &changes.domains {
        let encoded = cbor_to_vec(value).map_err(|err| {
            SharedError::Transport(format!("failed to encode domains update: {err}"))
        })?;
        push_update_bytes(&mut operations, &entry_id, LegacyField::Domains, &encoded);
    }

    if let Some(value) = &changes.username {
        push_update_bytes(
            &mut operations,
            &entry_id,
            LegacyField::Username,
            value.as_bytes(),
        );
    }

    if let Some(value) = &changes.password {
        push_update_bytes(
            &mut operations,
            &entry_id,
            LegacyField::Password,
            value.as_bytes(),
        );
    }

    if let Some(value) = &changes.totp {
        let encoded = cbor_to_vec(value).map_err(|err| {
            SharedError::Transport(format!("failed to encode TOTP update: {err}"))
        })?;
        push_update_bytes(&mut operations, &entry_id, LegacyField::Totp, &encoded);
    }

    if let Some(value) = &changes.tags {
        let encoded = cbor_to_vec(value).map_err(|err| {
            SharedError::Transport(format!("failed to encode tags update: {err}"))
        })?;
        push_update_bytes(&mut operations, &entry_id, LegacyField::Tags, &encoded);
    }

    if let Some(value) = &changes.r#macro {
        push_update_bytes(
            &mut operations,
            &entry_id,
            LegacyField::Macro,
            value.as_bytes(),
        );
    }

    if let Some(value) = &changes.updated_at {
        push_update_bytes(
            &mut operations,
            &entry_id,
            LegacyField::UpdatedAt,
            value.as_bytes(),
        );
    }

    if let Some(value) = &changes.used_at {
        let encoded = cbor_to_vec(value).map_err(|err| {
            SharedError::Transport(format!("failed to encode used_at update: {err}"))
        })?;
        push_update_bytes(&mut operations, &entry_id, LegacyField::UsedAt, &encoded);
    }

    Ok(operations)
}

fn push_update_bytes(
    operations: &mut Vec<DeviceJournalOperation>,
    entry_id: &str,
    field: LegacyField,
    bytes: &[u8],
) {
    let checksum = compute_crc32(bytes);
    operations.push(DeviceJournalOperation::UpdateField {
        entry_id: entry_id.to_owned(),
        field: field.to_string(),
        value_checksum: checksum,
    });
}

fn clear_local_operations(repo_path: &Path) -> Result<(), SharedError> {
    let path = operations_log_path(repo_path);
    match fs::remove_file(&path) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(SharedError::Transport(format!(
            "failed to clear local operations at '{}': {err}",
            path.display()
        ))),
    }
}

fn operations_log_path(repo_path: &Path) -> PathBuf {
    repo_path.join(LOCAL_OPERATIONS_FILE)
}

fn legacy_operations_log_path(repo_path: &Path) -> PathBuf {
    repo_path.join(LEGACY_LOCAL_OPERATIONS_FILE)
}

fn compute_local_journal_checksum(operations: &[DeviceJournalOperation]) -> u32 {
    JournalHasher::digest(operations)
}

fn execute_hello<P>(port: &mut P) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    println!("Initiating HELLO handshake…");

    let client_name = env::var("USER").unwrap_or_else(|_| "unknown".into());
    let request = HostRequest::Hello(HelloRequest {
        protocol_version: PROTOCOL_VERSION,
        client_name,
        client_version: env!("CARGO_PKG_VERSION").to_string(),
    });

    send_host_request(port, &request)?;
    let response = read_device_response(port)?;
    handle_device_response(response, None, None)?;
    Ok(())
}

fn execute_status<P>(port: &mut P) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    println!("Requesting device status…");
    let request = HostRequest::Status(StatusRequest {
        protocol_version: PROTOCOL_VERSION,
    });
    send_host_request(port, &request)?;
    let response = read_device_response(port)?;
    handle_device_response(response, None, None)?;
    Ok(())
}

fn execute_set_time<P>(port: &mut P, args: &SetTimeArgs) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    let epoch_ms = if args.system {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| SharedError::Transport(format!("system clock error: {err}")))?
            .as_millis() as u64
    } else if let Some(value) = args.epoch_ms {
        value
    } else {
        println!("No time provided, defaulting to zero.");
        0
    };

    println!("Setting device time to {epoch_ms} ms…");
    let request = HostRequest::SetTime(SetTimeRequest {
        protocol_version: PROTOCOL_VERSION,
        epoch_millis: epoch_ms,
    });
    send_host_request(port, &request)?;
    let response = read_device_response(port)?;
    handle_device_response(response, None, None)?;
    Ok(())
}

fn execute_get_time<P>(port: &mut P) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    println!("Requesting device time…");
    let request = HostRequest::GetTime(GetTimeRequest {
        protocol_version: PROTOCOL_VERSION,
    });
    send_host_request(port, &request)?;
    let response = read_device_response(port)?;
    handle_device_response(response, None, None)?;
    Ok(())
}

fn execute_pull_head<P>(port: &mut P) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    println!("Requesting vault head metadata…");
    let request = HostRequest::PullHead(PullHeadRequest {
        protocol_version: PROTOCOL_VERSION,
    });
    send_host_request(port, &request)?;
    let response = read_device_response(port)?;
    handle_device_response(response, None, None)?;
    Ok(())
}

fn handle_device_response(
    response: DeviceResponse,
    tracker: Option<&mut FrameTracker>,
    artifacts: Option<&mut PullArtifacts>,
) -> Result<bool, SharedError> {
    match response {
        DeviceResponse::Hello(info) => {
            print_hello(&info);
            if let Some(storage) = artifacts {
                storage.record_log("hello response");
            }
            Ok(false)
        }
        DeviceResponse::Status(status) => {
            print_status(&status);
            if let Some(storage) = artifacts {
                storage.record_log("status response");
            }
            Ok(false)
        }
        DeviceResponse::Time(time) => {
            print_time(&time);
            if let Some(storage) = artifacts {
                storage.record_log("time response");
            }
            Ok(false)
        }
        DeviceResponse::Head(head) => {
            print_head(&head);
            if let Some(storage) = artifacts {
                storage.record_log("head response");
            }
            Ok(false)
        }
        DeviceResponse::JournalFrame(frame) => {
            print_journal_frame(&frame);
            if let Some(state) = tracker {
                state.record(frame.sequence, frame.checksum);
            }
            if let Some(storage) = artifacts {
                storage.record_journal_frame(&frame);
            }
            Ok(frame.remaining_operations > 0)
        }
        DeviceResponse::VaultChunk(chunk) => {
            print_vault_chunk(&chunk);
            if let Some(state) = tracker {
                state.record(chunk.sequence, chunk.checksum);
            }
            let should_continue = if let Some(storage) = artifacts {
                storage.record_vault_chunk(&chunk)
            } else {
                !chunk.is_last
            };
            Ok(should_continue)
        }
        DeviceResponse::Ack(message) => {
            print_ack(&message);
            if let Some(storage) = artifacts {
                storage.record_log("ack response");
            }
            Ok(false)
        }
        DeviceResponse::Nack(err) => Err(SharedError::Transport(format!(
            "device reported {code:?}: {message}",
            code = err.code,
            message = err.message
        ))),
    }
}

#[derive(Default)]
struct PullArtifacts {
    vault: ArtifactBuffer,
    recipients: ArtifactBuffer,
    recipients_manifest: Option<Vec<u8>>,
    recipients_expected: bool,
    recipients_seen: bool,
    signature: ArtifactBuffer,
    signature_bytes: Option<Vec<u8>>,
    signature_expected: bool,
    signature_seen: bool,
    log_context: Vec<String>,
}

impl PullArtifacts {
    fn set_recipients_expected(&mut self, expected: bool) {
        self.recipients_expected = expected;
    }

    fn set_signature_expected(&mut self, expected: bool) {
        self.signature_expected = expected;
    }

    fn record_vault_chunk(&mut self, chunk: &VaultChunk) -> bool {
        match chunk.artifact {
            VaultArtifact::Vault => {
                self.vault.bytes.extend_from_slice(&chunk.data);
                self.vault.metadata.push(VaultChunkMetadata {
                    protocol_version: chunk.protocol_version,
                    sequence: chunk.sequence,
                    total_size: chunk.total_size,
                    remaining_bytes: chunk.remaining_bytes,
                    device_chunk_size: chunk.device_chunk_size,
                    checksum: chunk.checksum,
                    is_last: chunk.is_last,
                });
                if chunk.is_last {
                    if self.recipients_expected && !self.recipients_seen {
                        return true;
                    }
                    if self.signature_expected && !self.signature_seen {
                        return true;
                    }
                    return false;
                }
                true
            }
            VaultArtifact::Recipients => {
                if !self.recipients_seen || chunk.sequence == 1 {
                    self.recipients.bytes.clear();
                    self.recipients.metadata.clear();
                }
                self.recipients_seen = true;
                self.recipients.bytes.extend_from_slice(&chunk.data);
                self.recipients.metadata.push(VaultChunkMetadata {
                    protocol_version: chunk.protocol_version,
                    sequence: chunk.sequence,
                    total_size: chunk.total_size,
                    remaining_bytes: chunk.remaining_bytes,
                    device_chunk_size: chunk.device_chunk_size,
                    checksum: chunk.checksum,
                    is_last: chunk.is_last,
                });
                if chunk.is_last {
                    let data = self.recipients.bytes.clone();
                    self.record_recipients_manifest(&data);
                    if self.signature_expected && !self.signature_seen {
                        return true;
                    }
                    return false;
                }
                true
            }
            VaultArtifact::Signature => {
                if !self.signature_seen || chunk.sequence == 1 {
                    self.signature.bytes.clear();
                    self.signature.metadata.clear();
                }
                self.signature_seen = true;
                self.signature.bytes.extend_from_slice(&chunk.data);
                self.signature.metadata.push(VaultChunkMetadata {
                    protocol_version: chunk.protocol_version,
                    sequence: chunk.sequence,
                    total_size: chunk.total_size,
                    remaining_bytes: chunk.remaining_bytes,
                    device_chunk_size: chunk.device_chunk_size,
                    checksum: chunk.checksum,
                    is_last: chunk.is_last,
                });
                if chunk.is_last {
                    self.signature_bytes = Some(self.signature.bytes.clone());
                    return false;
                }
                true
            }
        }
    }

    fn record_journal_frame(&mut self, frame: &JournalFrame) {
        let summary = format!(
            "journal frame #{sequence} with {operations} operations and {remaining} pending",
            sequence = frame.sequence,
            operations = frame.operations.len(),
            remaining = frame.remaining_operations,
        );
        self.log_context.push(summary);
    }

    fn record_log(&mut self, context: impl Into<String>) {
        self.log_context.push(context.into());
    }

    #[allow(dead_code)]
    fn record_recipients_manifest(&mut self, data: &[u8]) {
        self.recipients_manifest = Some(data.to_vec());
    }

    fn persist(&self, repo: &Path) -> Result<(), SharedError> {
        if self.vault.bytes.is_empty() && self.recipients_manifest.is_none() {
            return Ok(());
        }

        fs::create_dir_all(repo)
            .map_err(|err| io_error("create repository directory", repo, err))?;

        if !self.vault.bytes.is_empty() {
            let vault_path = repo.join("vault.enc");
            if let Some(parent) = vault_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| io_error("prepare vault directory", parent, err))?;
            }
            fs::write(&vault_path, &self.vault.bytes)
                .map_err(|err| io_error("write vault artifact", &vault_path, err))?;
            println!("Saved vault artifact to '{}'.", vault_path.display());
        }

        if let Some(recipients) = &self.recipients_manifest {
            let recipients_path = repo.join("recips.json");
            if let Some(parent) = recipients_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| io_error("prepare recipients directory", parent, err))?;
            }
            fs::write(&recipients_path, recipients)
                .map_err(|err| io_error("write recipients artifact", &recipients_path, err))?;
            println!(
                "Saved recipients manifest to '{}'.",
                recipients_path.display()
            );
        }

        if let Some(signature) = &self.signature_bytes {
            let signature_path = repo.join("vault.sig");
            if let Some(parent) = signature_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| io_error("prepare signature directory", parent, err))?;
            }
            fs::write(&signature_path, signature)
                .map_err(|err| io_error("write signature artifact", &signature_path, err))?;
            println!("Saved vault signature to '{}'.", signature_path.display());
        }

        Ok(())
    }
}

#[derive(Default)]
struct ArtifactBuffer {
    bytes: Vec<u8>,
    metadata: Vec<VaultChunkMetadata>,
}

#[allow(dead_code)]
struct VaultChunkMetadata {
    protocol_version: u16,
    sequence: u32,
    total_size: u64,
    remaining_bytes: u64,
    device_chunk_size: u32,
    checksum: u32,
    is_last: bool,
}

fn io_error(context: &str, path: &Path, err: io::Error) -> SharedError {
    SharedError::Transport(format!("{context} at '{}': {err}", path.display()))
}

fn persist_sync_state(repo_path: &Path, state: Option<FrameState>) -> Result<(), SharedError> {
    let path = sync_state_path(repo_path);
    match state {
        Some(state) => {
            let content = format!("{}\n", state);
            fs::write(&path, content).map_err(|err| {
                SharedError::Transport(format!(
                    "failed to write sync state to '{}': {err}",
                    path.display()
                ))
            })?
        }
        None => match fs::remove_file(&path) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(SharedError::Transport(format!(
                    "failed to clear sync state at '{}': {err}",
                    path.display()
                )));
            }
        },
    }

    Ok(())
}

fn load_sync_state(repo_path: &Path) -> Result<Option<FrameState>, SharedError> {
    let path = sync_state_path(repo_path);
    let content = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(SharedError::Transport(format!(
                "failed to read sync state from '{}': {err}",
                path.display()
            )));
        }
    };

    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(SharedError::Transport(format!(
            "invalid sync state in '{}': empty content",
            path.display()
        )));
    }

    let state = trimmed.parse::<FrameState>().map_err(|err| {
        SharedError::Transport(format!("invalid sync state in '{}': {err}", path.display()))
    })?;

    Ok(Some(state))
}

fn sync_state_path(repo_path: &Path) -> PathBuf {
    repo_path.join(SYNC_STATE_FILE)
}

fn print_journal_frame(frame: &JournalFrame) {
    println!(
        "Received journal frame #{sequence} with {remaining} operations pending.",
        sequence = frame.sequence,
        remaining = frame.remaining_operations,
    );
    if frame.operations.is_empty() {
        println!("  No operations in this frame.");
    } else {
        println!("  Operations: {}", frame.operations.len());
        for op in &frame.operations {
            println!("    - {op:?}");
        }
    }
}

fn print_vault_chunk(chunk: &VaultChunk) {
    let artifact = match chunk.artifact {
        VaultArtifact::Vault => "vault image",
        VaultArtifact::Recipients => "recipients manifest",
        VaultArtifact::Signature => "vault signature",
    };
    println!(
        "Received {artifact} chunk #{sequence} ({size} bytes, {remaining} bytes remaining).",
        sequence = chunk.sequence,
        size = chunk.data.len(),
        remaining = chunk.remaining_bytes,
    );
    if chunk.is_last {
        println!("  This was the final chunk of the transfer.");
    }
}

fn print_hello(info: &HelloResponse) {
    println!(
        "HELLO response from '{name}' running firmware v{firmware} (session {session}).",
        name = info.device_name,
        firmware = info.firmware_version,
        session = info.session_id,
    );
}

fn print_status(status: &StatusResponse) {
    println!(
        "Status: generation {generation}, pending ops {pending}, device time {time} ms.",
        generation = status.vault_generation,
        pending = status.pending_operations,
        time = status.current_time_ms,
    );
}

fn print_time(time: &TimeResponse) {
    println!("Device time: {} ms since Unix epoch", time.epoch_millis);
}

fn print_head(head: &PullHeadResponse) {
    println!(
        "Vault head generation {generation}.",
        generation = head.vault_generation,
    );
    println!("  Vault hash   : {}", hex_encode(&head.vault_hash));
    println!("  Recipients hash: {}", hex_encode(&head.recipients_hash));
    println!("  Signature hash : {}", hex_encode(&head.signature_hash));
}

fn print_ack(message: &AckResponse) {
    println!("Acknowledgement: {}", message.message);
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = FmtWrite::write_fmt(&mut output, format_args!("{:02X}", byte));
    }
    output
}

fn send_host_request<W>(writer: &mut W, request: &HostRequest) -> Result<(), SharedError>
where
    W: Write + ?Sized,
{
    let payload = postcard_to_allocvec(request).map_err(SharedError::from)?;
    let command = command_for_request(request);
    write_framed_message(writer, command, &payload)
}

fn read_device_response<R>(reader: &mut R) -> Result<DeviceResponse, SharedError>
where
    R: Read + ?Sized,
{
    let (command, payload) = read_framed_message(reader)?;
    let response = postcard_from_bytes(&payload).map_err(SharedError::from)?;
    validate_response_command(command, &response)?;
    Ok(response)
}

fn write_framed_message<W>(
    writer: &mut W,
    command: CdcCommand,
    payload: &[u8],
) -> Result<(), SharedError>
where
    W: Write + ?Sized,
{
    let header = encode_frame(PROTOCOL_VERSION, command, payload, usize::MAX)
        .map_err(|err| map_transport_error("encode frame", err))?;
    writer
        .write_all(&header)
        .map_err(map_io_error("write frame header"))?;
    writer
        .write_all(payload)
        .map_err(map_io_error("write frame payload"))?;

    writer.flush().map_err(map_io_error("flush frame"))?;
    Ok(())
}

fn read_framed_message<R>(reader: &mut R) -> Result<(CdcCommand, Vec<u8>), SharedError>
where
    R: Read + ?Sized,
{
    let mut header_bytes = [0u8; FRAME_HEADER_SIZE];
    reader
        .read_exact(&mut header_bytes)
        .map_err(map_io_error("read frame header"))?;
    let header = decode_frame_header(PROTOCOL_VERSION, HOST_BUFFER_SIZE as usize, header_bytes)
        .map_err(|err| map_transport_error("decode frame header", err))?;

    let mut payload = vec![0u8; header.length as usize];
    reader
        .read_exact(&mut payload)
        .map_err(map_io_error("read frame payload"))?;

    decode_frame(&header, &payload)
        .map_err(|err| map_transport_error("validate frame payload", err))?;

    Ok((header.command, payload))
}

fn validate_response_command(
    command: CdcCommand,
    response: &DeviceResponse,
) -> Result<(), SharedError> {
    let expected = command_for_response(response);
    if command == expected {
        Ok(())
    } else {
        Err(SharedError::Transport(format!(
            "unexpected command {:?} for response {:?} (expected {:?})",
            command, response, expected
        )))
    }
}

fn open_serial_port(path: &str) -> Result<Box<dyn SerialPort>, SharedError> {
    let mut port = serialport::new(path, SERIAL_BAUD_RATE)
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .open()
        .map_err(|err| {
            SharedError::Transport(format!("failed to open serial port {path}: {err}"))
        })?;

    port.set_timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .map_err(|err| {
            SharedError::Transport(format!("failed to configure timeout on {path}: {err}"))
        })?;

    Ok(port)
}

fn detect_first_serial_port(allow_any_port: bool) -> Result<String, SharedError> {
    let ports = serialport::available_ports().map_err(|err| {
        SharedError::Transport(format!("failed to enumerate serial ports: {err}"))
    })?;

    select_serial_port(&ports, allow_any_port)
        .map(|info| info.port_name.clone())
        .ok_or_else(|| missing_cardputer_error(allow_any_port))
}

fn select_serial_port(
    ports: &[serialport::SerialPortInfo],
    allow_any_port: bool,
) -> Option<&serialport::SerialPortInfo> {
    if allow_any_port {
        return ports
            .iter()
            .find(|info| matches!(info.port_type, SerialPortType::UsbPort(_)));
    }

    let mut matches = ports
        .iter()
        .filter(|info| matches_cardputer_vid_pid(info))
        .peekable();

    let first = matches.next()?;
    if matches.peek().is_none() {
        return Some(first);
    }

    std::iter::once(first)
        .chain(matches)
        .find(|info| matches_cardputer_identity(info))
        .or(Some(first))
}

fn matches_cardputer_vid_pid(info: &serialport::SerialPortInfo) -> bool {
    matches!(&info.port_type, SerialPortType::UsbPort(usb) if usb.vid == CARDPUTER_USB_VID && usb.pid == CARDPUTER_USB_PID)
}

fn matches_cardputer_identity(info: &serialport::SerialPortInfo) -> bool {
    match &info.port_type {
        SerialPortType::UsbPort(usb) => {
            field_matches_keyword(usb.product.as_deref())
                || field_matches_keyword(usb.serial_number.as_deref())
                || field_matches_keyword(usb.manufacturer.as_deref())
        }
        _ => false,
    }
}

fn field_matches_keyword(field: Option<&str>) -> bool {
    field.is_some_and(contains_keyword)
}

fn contains_keyword(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    CARDPUTER_IDENTITY_KEYWORDS
        .iter()
        .any(|keyword| lower.contains(keyword))
}

fn missing_cardputer_error(allow_any_port: bool) -> SharedError {
    let mut message = format!(
        "Cardputer USB CDC device not found (expected VID 0x{CARDPUTER_USB_VID:04X}, PID 0x{CARDPUTER_USB_PID:04X})."
    );

    if !allow_any_port {
        message.push_str(" Pass --any-port to connect to the first available USB serial device.");
    }

    SharedError::Transport(message)
}

fn load_verifying_key(
    config: &HostConfig,
    override_path: Option<&Path>,
) -> Result<Option<VerifyingKey>, SharedError> {
    if let Some(path) = override_path {
        let raw = fs::read_to_string(path).map_err(|err| {
            SharedError::Transport(format!(
                "failed to read verifying key from '{}': {err}",
                path.display()
            ))
        })?;
        let decoded = decode_key_bytes::<{ SIGNATURE_SIZE / 2 }>(raw.trim())?;
        return VerifyingKey::from_bytes(&decoded)
            .map(Some)
            .map_err(|err| SharedError::Transport(format!("invalid verifying key: {err}")));
    }

    config.verifying_key()
}

fn verify_pulled_signature(
    artifacts: &PullArtifacts,
    repo: &Path,
    verifying_key: Option<&VerifyingKey>,
) -> Result<(), SharedError> {
    if artifacts.vault.bytes.is_empty() || !artifacts.signature_expected {
        return Ok(());
    }

    let key = verifying_key.ok_or_else(|| {
        SharedError::Transport(
            "signature verification requested but verifying key is missing".into(),
        )
    })?;

    let signature_bytes = artifacts
        .signature_bytes
        .as_ref()
        .ok_or_else(|| SharedError::Transport("vault signature missing from transfer".into()))?;

    let array: [u8; SIGNATURE_SIZE] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| SharedError::Transport("invalid vault signature length".into()))?;
    let signature = Signature::from_bytes(&array);

    let recipients = if artifacts.recipients_seen {
        Some(artifacts.recipients.bytes.as_slice())
    } else {
        None
    };

    let config_path = repo.join(CONFIG_FILE);
    let config_bytes = if config_path.exists() {
        Some(fs::read(&config_path).map_err(|err| {
            SharedError::Transport(format!(
                "failed to read config.json for signature verification: {err}"
            ))
        })?)
    } else {
        None
    };

    let message =
        compute_signature_message(&artifacts.vault.bytes, recipients, config_bytes.as_deref());

    key.verify(&message, &signature).map_err(|err| {
        SharedError::Transport(format!("vault signature verification failed: {err}"))
    })
}

fn compute_signature_message(
    vault: &[u8],
    recipients: Option<&[u8]>,
    config: Option<&[u8]>,
) -> [u8; 32] {
    fn append_component(hasher: &mut Hasher, label: &str, payload: Option<&[u8]>) {
        hasher.update(&(label.len() as u64).to_le_bytes());
        hasher.update(label.as_bytes());
        if let Some(bytes) = payload {
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        } else {
            hasher.update(&0u64.to_le_bytes());
        }
    }

    let mut hasher = Hasher::new();
    hasher.update(SIGNATURE_DOMAIN);
    append_component(&mut hasher, VAULT_FILE, Some(vault));
    append_component(&mut hasher, RECIPIENTS_FILE, recipients);
    append_component(&mut hasher, CONFIG_FILE, config);
    hasher.finalize().into()
}

fn apply_operations_to_repo(
    repo: &Path,
    config: &HostConfig,
    operations: &[VaultJournalOperation],
) -> Result<(), SharedError> {
    if operations.is_empty() {
        return Ok(());
    }

    let vault_key = config
        .vault_key()
        .ok_or_else(|| SharedError::Transport("vault key missing from credentials".into()))?;

    let vault_path = repo.join(VAULT_FILE);
    let encrypted = fs::read(&vault_path).map_err(|err| {
        SharedError::Transport(format!(
            "failed to read vault from '{}': {err}",
            vault_path.display()
        ))
    })?;

    let mut snapshot = decrypt_vault(&encrypted, &vault_key)?;
    apply_vault_operations(&mut snapshot, operations)?;

    let mut rng = OsRng;
    let encrypted_vault = encrypt_vault_with_rng(&snapshot, &vault_key, &mut rng)?;
    fs::write(&vault_path, &encrypted_vault).map_err(|err| {
        SharedError::Transport(format!(
            "failed to write updated vault to '{}': {err}",
            vault_path.display()
        ))
    })?;

    let recipients_path = repo.join(RECIPIENTS_FILE);
    let recipients = if recipients_path.exists() {
        Some(fs::read(&recipients_path).map_err(|err| {
            SharedError::Transport(format!(
                "failed to read recipients manifest from '{}': {err}",
                recipients_path.display()
            ))
        })?)
    } else {
        None
    };

    let config_path = repo.join(CONFIG_FILE);
    let config_bytes = if config_path.exists() {
        Some(fs::read(&config_path).map_err(|err| {
            SharedError::Transport(format!(
                "failed to read config.json from '{}': {err}",
                config_path.display()
            ))
        })?)
    } else {
        None
    };

    let signing_key = config
        .signing_key()?
        .ok_or_else(|| SharedError::Transport("signing key missing from credentials".into()))?;

    let message = compute_signature_message(
        &encrypted_vault,
        recipients.as_deref(),
        config_bytes.as_deref(),
    );
    let signature = signing_key.sign(&message);

    let signature_path = repo.join(SIGNATURE_FILE);
    fs::write(signature_path, signature.to_bytes())
        .map_err(|err| SharedError::Transport(format!("failed to write vault signature: {err}")))?;

    Ok(())
}

fn apply_vault_operations(
    snapshot: &mut VaultSnapshot,
    operations: &[VaultJournalOperation],
) -> Result<(), SharedError> {
    for operation in operations {
        match operation {
            VaultJournalOperation::Add { entry } => {
                snapshot.entries.retain(|existing| existing.id != entry.id);
                snapshot.entries.push(entry.clone());
            }
            VaultJournalOperation::Update { id, changes } => {
                let entry = snapshot
                    .entries
                    .iter_mut()
                    .find(|item| &item.id == id)
                    .ok_or_else(|| {
                        SharedError::Transport(format!("cannot update unknown entry {}", id))
                    })?;
                apply_entry_update(entry, changes);
            }
            VaultJournalOperation::Delete { id } => {
                let before = snapshot.entries.len();
                snapshot.entries.retain(|entry| &entry.id != id);
                if snapshot.entries.len() == before {
                    return Err(SharedError::Transport(format!(
                        "cannot delete unknown entry {}",
                        id
                    )));
                }
            }
        }
    }

    Ok(())
}

fn apply_entry_update(entry: &mut VaultEntry, update: &EntryUpdate) {
    if let Some(value) = &update.title {
        entry.title = value.clone();
    }

    if let Some(value) = &update.service {
        entry.service = value.clone();
    }

    if let Some(value) = &update.domains {
        entry.domains = value.clone();
    }

    if let Some(value) = &update.username {
        entry.username = value.clone();
    }

    if let Some(value) = &update.password {
        entry.password = value.clone();
    }

    if let Some(value) = &update.totp {
        entry.totp = Some(value.clone());
    }

    if let Some(value) = &update.tags {
        entry.tags = value.clone();
    }

    if let Some(value) = &update.r#macro {
        entry.r#macro = Some(value.clone());
    }

    if let Some(value) = &update.updated_at {
        entry.updated_at = value.clone();
    }

    if let Some(value) = &update.used_at {
        entry.used_at = value.clone();
    }
}

fn decrypt_vault(data: &[u8], key: &[u8; 32]) -> Result<VaultSnapshot, SharedError> {
    if data.len() < VAULT_NONCE_SIZE {
        return Err(SharedError::Transport(
            "vault payload too small to contain nonce".into(),
        ));
    }

    let (nonce_bytes, ciphertext) = data.split_at(VAULT_NONCE_SIZE);
    let nonce: [u8; VAULT_NONCE_SIZE] = nonce_bytes
        .try_into()
        .expect("nonce slice has fixed length");

    let cipher = PageCipher::chacha20_poly1305(*key);
    let plaintext = cipher
        .decrypt(&nonce, VAULT_AAD, ciphertext)
        .map_err(|err| SharedError::Transport(format!("failed to decrypt vault: {err}")))?;

    cbor_from_slice(&plaintext)
        .map_err(|err| SharedError::Transport(format!("invalid vault format: {err}")))
}

fn encrypt_vault_with_rng<R>(
    snapshot: &VaultSnapshot,
    key: &[u8; 32],
    rng: &mut R,
) -> Result<Vec<u8>, SharedError>
where
    R: RngCore + CryptoRng,
{
    let plaintext = cbor_to_vec(snapshot)
        .map_err(|err| SharedError::Transport(format!("failed to encode vault snapshot: {err}")))?;
    let cipher = PageCipher::chacha20_poly1305(*key);
    let mut nonce = [0u8; VAULT_NONCE_SIZE];
    rng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(&nonce, VAULT_AAD, &plaintext)
        .map_err(|err| SharedError::Transport(format!("failed to encrypt vault: {err}")))?;

    let mut buffer = Vec::with_capacity(VAULT_NONCE_SIZE + ciphertext.len());
    buffer.extend_from_slice(&nonce);
    buffer.extend_from_slice(&ciphertext);
    Ok(buffer)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultSnapshot {
    version: u16,
    metadata: VaultMetadata,
    entries: Vec<VaultEntry>,
}

#[derive(Debug, Deserialize, Default)]
struct HostConfig {
    #[serde(default)]
    signing_public_key: Option<String>,
    #[serde(default)]
    signing_secret_key: Option<String>,
    #[serde(default)]
    vault_key: Option<String>,
}

impl HostConfig {
    fn load(path: &Path) -> Result<Self, SharedError> {
        let raw = fs::read_to_string(path).map_err(|err| {
            SharedError::Transport(format!(
                "failed to read credentials from '{}': {err}",
                path.display()
            ))
        })?;
        json_from_str(&raw)
            .map_err(|err| SharedError::Transport(format!("invalid credentials file: {err}")))
    }

    fn verifying_key(&self) -> Result<Option<VerifyingKey>, SharedError> {
        if let Some(public) = &self.signing_public_key {
            let bytes = decode_key_bytes::<{ SIGNATURE_SIZE / 2 }>(public)?;
            return VerifyingKey::from_bytes(&bytes)
                .map(Some)
                .map_err(|err| SharedError::Transport(format!("invalid verifying key: {err}")));
        }

        if let Some(secret) = &self.signing_secret_key {
            let seed = decode_key_bytes::<{ SIGNATURE_SIZE / 2 }>(secret)?;
            let signing = SigningKey::from_bytes(&seed);
            return Ok(Some(signing.verifying_key()));
        }

        Ok(None)
    }

    fn signing_key(&self) -> Result<Option<SigningKey>, SharedError> {
        match &self.signing_secret_key {
            Some(secret) => {
                let seed = decode_key_bytes::<{ SIGNATURE_SIZE / 2 }>(secret)?;
                Ok(Some(SigningKey::from_bytes(&seed)))
            }
            None => Ok(None),
        }
    }

    fn vault_key(&self) -> Option<[u8; 32]> {
        self.vault_key
            .as_deref()
            .and_then(|value| decode_key_bytes::<32>(value).ok())
    }
}

fn decode_key_bytes<const N: usize>(input: &str) -> Result<[u8; N], SharedError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(SharedError::Transport("key material is empty".into()));
    }

    match Base64.decode(trimmed.as_bytes()) {
        Ok(bytes) if bytes.len() == N => bytes
            .try_into()
            .map_err(|_| SharedError::Transport("failed to read fixed-length key material".into())),
        Ok(bytes) => Err(SharedError::Transport(format!(
            "expected {N} decoded bytes but got {}",
            bytes.len()
        ))),
        Err(_) => {
            let hex_bytes = hex_decode(trimmed).map_err(|err| {
                SharedError::Transport(format!("failed to decode key material: {err}"))
            })?;
            if hex_bytes.len() != N {
                Err(SharedError::Transport(format!(
                    "expected {N} decoded bytes but got {}",
                    hex_bytes.len()
                )))
            } else {
                hex_bytes.try_into().map_err(|_| {
                    SharedError::Transport("failed to read fixed-length key material".into())
                })
            }
        }
    }
}

fn map_io_error(context: &'static str) -> impl Fn(io::Error) -> SharedError {
    move |err| {
        let mut message = format!("{context} failed: {err}");
        if err.kind() == io::ErrorKind::TimedOut {
            message.push_str(" (operation timed out)");
        }
        SharedError::Transport(message)
    }
}

fn map_transport_error(context: &'static str, error: FrameTransportError) -> SharedError {
    SharedError::Transport(format!("{context} failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD as Base64};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use serde_json::{Map, json};
    use shared::schema::{
        DeviceErrorCode, NackResponse, decode_host_request, encode_device_response,
        encode_host_request,
    };
    use shared::vault::SecretString;
    use std::fs;
    use std::io::Cursor;
    use tempfile::tempdir;
    use uuid::Uuid;

    const SIGNATURE_SIZE: usize = 64;
    const TEST_SIGNING_SEED: [u8; 32] = [0x21; 32];
    const TEST_VAULT_KEY: [u8; 32] = [0x34; 32];

    fn write_empty_credentials(path: &Path) {
        fs::write(path, json!({}).to_string()).expect("write empty credentials");
    }

    fn write_credentials_with_keys(
        path: &Path,
        include_secret: bool,
        include_vault: bool,
    ) -> SigningKey {
        let signing = SigningKey::from_bytes(&TEST_SIGNING_SEED);
        let verifying = signing.verifying_key();
        let mut content = Map::new();
        content.insert(
            "signing_public_key".into(),
            json!(Base64.encode(verifying.to_bytes())),
        );
        if include_secret {
            content.insert(
                "signing_secret_key".into(),
                json!(Base64.encode(signing.to_bytes())),
            );
        }
        if include_vault {
            content.insert("vault_key".into(), json!(Base64.encode(TEST_VAULT_KEY)));
        }
        fs::write(path, serde_json::Value::Object(content).to_string()).expect("write credentials");
        signing
    }

    fn deterministic_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([0xAA; 32])
    }

    fn write_encrypted_vault(repo: &Path, snapshot: &VaultSnapshot) {
        let mut rng = deterministic_rng();
        let encrypted =
            encrypt_vault_with_rng(snapshot, &TEST_VAULT_KEY, &mut rng).expect("encrypt vault");
        let path = repo.join(VAULT_FILE);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create vault directory");
        }
        fs::write(path, encrypted).expect("write vault");
    }

    fn sample_metadata() -> VaultMetadata {
        VaultMetadata {
            generation: 1,
            created_at: "2024-01-01T00:00:00Z".into(),
            updated_at: "2024-01-01T00:00:00Z".into(),
        }
    }

    fn sample_entry(id: Uuid, title: &str) -> VaultEntry {
        VaultEntry {
            id,
            title: title.into(),
            service: "service".into(),
            domains: vec![],
            username: "user".into(),
            password: SecretString::from("password"),
            totp: None,
            tags: vec![],
            r#macro: None,
            updated_at: "2024-01-01T00:00:00Z".into(),
            used_at: None,
        }
    }

    fn sample_snapshot(entries: Vec<VaultEntry>) -> VaultSnapshot {
        VaultSnapshot {
            version: 1,
            metadata: sample_metadata(),
            entries,
        }
    }

    fn sign_artifacts(
        signing: &SigningKey,
        vault: &[u8],
        recipients: Option<&[u8]>,
        config: Option<&[u8]>,
    ) -> Vec<u8> {
        let message = compute_signature_message(vault, recipients, config);
        signing.sign(&message).to_bytes().to_vec()
    }

    fn usb_port(
        name: &str,
        vid: u16,
        pid: u16,
        serial: Option<&str>,
        manufacturer: Option<&str>,
        product: Option<&str>,
    ) -> serialport::SerialPortInfo {
        serialport::SerialPortInfo {
            port_name: name.to_string(),
            port_type: SerialPortType::UsbPort(serialport::UsbPortInfo {
                vid,
                pid,
                serial_number: serial.map(|value| value.to_string()),
                manufacturer: manufacturer.map(|value| value.to_string()),
                product: product.map(|value| value.to_string()),
                interface: None,
            }),
        }
    }

    fn non_usb_port(name: &str) -> serialport::SerialPortInfo {
        serialport::SerialPortInfo {
            port_name: name.to_string(),
            port_type: SerialPortType::PciPort,
        }
    }

    fn encode_response(response: DeviceResponse) -> Vec<u8> {
        let payload = encode_device_response(&response).expect("encode response");
        let mut cursor = Cursor::new(Vec::new());
        let command = command_for_response(&response);
        write_framed_message(&mut cursor, command, &payload).expect("write frame");
        cursor.into_inner()
    }

    #[test]
    fn detect_cardputer_by_vid_pid() {
        let ports = vec![
            non_usb_port("/dev/ttyS0"),
            usb_port(
                "/dev/ttyUSB0",
                CARDPUTER_USB_VID,
                CARDPUTER_USB_PID,
                None,
                Some("M5Stack"),
                None,
            ),
        ];

        let detected = select_serial_port(&ports, false).expect("cardputer port");
        assert_eq!(detected.port_name, "/dev/ttyUSB0");
    }

    #[test]
    fn detect_cardputer_prefers_identity_keywords() {
        let ports = vec![
            usb_port(
                "/dev/ttyUSB0",
                CARDPUTER_USB_VID,
                CARDPUTER_USB_PID,
                None,
                None,
                Some("Generic CDC"),
            ),
            usb_port(
                "/dev/ttyUSB1",
                CARDPUTER_USB_VID,
                CARDPUTER_USB_PID,
                None,
                Some("M5Stack"),
                Some("Cardputer CDC"),
            ),
        ];

        let detected = select_serial_port(&ports, false).expect("cardputer port");
        assert_eq!(detected.port_name, "/dev/ttyUSB1");
    }

    #[test]
    fn detect_cardputer_none_without_match() {
        let ports = vec![
            non_usb_port("/dev/ttyS0"),
            usb_port(
                "/dev/ttyUSB0",
                0x10C4,
                0xEA60,
                None,
                Some("Silicon Labs"),
                Some("CP210x"),
            ),
        ];

        assert!(select_serial_port(&ports, false).is_none());
    }

    #[test]
    fn detect_cardputer_allows_any_port_override() {
        let ports = vec![
            usb_port(
                "/dev/ttyUSB0",
                0x10C4,
                0xEA60,
                None,
                Some("Silicon Labs"),
                Some("CP210x"),
            ),
            usb_port(
                "/dev/ttyUSB1",
                CARDPUTER_USB_VID,
                CARDPUTER_USB_PID,
                None,
                Some("M5Stack"),
                Some("Cardputer CDC"),
            ),
        ];

        let detected = select_serial_port(&ports, true).expect("usb port");
        assert_eq!(detected.port_name, "/dev/ttyUSB0");
    }

    #[test]
    fn framing_roundtrip() {
        let request = HostRequest::PullVault(PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: HOST_BUFFER_SIZE,
            max_chunk_size: MAX_CHUNK_SIZE,
            known_generation: Some(7),
        });

        let payload = encode_host_request(&request).expect("encode request");
        let mut writer = Cursor::new(Vec::new());
        let command = command_for_request(&request);
        write_framed_message(&mut writer, command, &payload).expect("write frame");

        let data = writer.into_inner();
        let mut reader = Cursor::new(data);
        let (decoded_command, decoded) = read_framed_message(&mut reader).expect("read frame");

        assert_eq!(decoded_command, command);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn cli_header_matches_shared_encoding() {
        let request = HostRequest::Status(StatusRequest {
            protocol_version: PROTOCOL_VERSION,
        });
        let payload = encode_host_request(&request).expect("encode request");
        let command = command_for_request(&request);

        let mut writer = Cursor::new(Vec::new());
        write_framed_message(&mut writer, command, &payload).expect("write frame");
        let frame = writer.into_inner();

        let expected =
            encode_frame(PROTOCOL_VERSION, command, &payload, usize::MAX).expect("encode header");
        assert_eq!(&frame[..FRAME_HEADER_SIZE], &expected);
    }

    #[test]
    fn framing_detects_checksum_mismatch() {
        let payload = vec![1u8, 2, 3, 4];
        let mut frame = Vec::new();
        let header = FrameHeader::new(
            PROTOCOL_VERSION,
            CdcCommand::PullVault,
            payload.len() as u32,
            0xDEADBEEFu32,
        );
        frame.extend_from_slice(&header.to_bytes());
        frame.extend_from_slice(&payload);

        let mut reader = Cursor::new(frame);
        let err = read_framed_message(&mut reader).expect_err("expected checksum error");
        match err {
            SharedError::Transport(message) => {
                assert!(message.contains("checksum mismatch"));
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn framing_rejects_payload_exceeding_limit() {
        let mut frame = Vec::new();
        let header = FrameHeader::new(
            PROTOCOL_VERSION,
            CdcCommand::PullVault,
            HOST_BUFFER_SIZE + 1,
            0,
        );
        frame.extend_from_slice(&header.to_bytes());

        let mut reader = Cursor::new(frame);
        let err = read_framed_message(&mut reader).expect_err("expected length error");
        match err {
            SharedError::Transport(message) => {
                assert!(message.contains("frame payload") && message.contains("exceeds limit"));
            }
            other => panic!("unexpected error variant: {:?}", other),
        }
    }

    #[test]
    fn response_command_mismatch_is_reported() {
        let response = DeviceResponse::Nack(NackResponse {
            protocol_version: PROTOCOL_VERSION,
            code: DeviceErrorCode::InternalFailure,
            message: "failure".into(),
        });
        let payload = encode_device_response(&response).expect("encode response");
        let mut frame = Vec::new();
        let checksum = compute_crc32(&payload);
        let wrong_command = FrameHeader::new(
            PROTOCOL_VERSION,
            CdcCommand::PullVault,
            payload.len() as u32,
            checksum,
        );
        frame.extend_from_slice(&wrong_command.to_bytes());
        frame.extend_from_slice(&payload);

        let mut reader = Cursor::new(frame);
        let err = read_device_response(&mut reader).expect_err("expected command error");
        match err {
            SharedError::Transport(message) => {
                assert!(message.contains("unexpected command"));
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn pull_reissues_request_until_completion() {
        let responses = [
            encode_response(DeviceResponse::Head(PullHeadResponse {
                protocol_version: PROTOCOL_VERSION,
                vault_generation: 1,
                vault_hash: [0u8; 32],
                recipients_hash: [0u8; 32],
                signature_hash: [0u8; 32],
            })),
            encode_response(DeviceResponse::VaultChunk(VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: 1,
                total_size: 1024,
                remaining_bytes: 512,
                device_chunk_size: MAX_CHUNK_SIZE,
                data: vec![0; 8],
                checksum: 0x1234ABCD,
                is_last: false,
                artifact: VaultArtifact::Vault,
            })),
            encode_response(DeviceResponse::VaultChunk(VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: 2,
                total_size: 1024,
                remaining_bytes: 0,
                device_chunk_size: MAX_CHUNK_SIZE,
                data: vec![0; 8],
                checksum: 0xCAFEBABE,
                is_last: true,
                artifact: VaultArtifact::Vault,
            })),
        ]
        .concat();

        let mut port = MockPort::new(responses);
        let temp = tempdir().expect("tempdir");
        let args = RepoArgs {
            repo: temp.path().to_path_buf(),
            credentials: temp.path().join("creds"),
            signing_pubkey: None,
        };

        write_empty_credentials(&args.credentials);
        execute_pull(&mut port, &args).expect("pull succeeds");

        let mut reader = Cursor::new(port.writes);
        let (command_one, payload_one) =
            read_framed_message(&mut reader).expect("decode first written frame");
        assert_eq!(command_one, CdcCommand::PullHead);
        let decoded_one: HostRequest =
            decode_host_request(&payload_one).expect("decode first request");
        assert!(matches!(decoded_one, HostRequest::PullHead(_)));

        let (command_two, payload_two) =
            read_framed_message(&mut reader).expect("decode second written frame");
        assert_eq!(command_two, CdcCommand::PullVault);
        let decoded_two: HostRequest =
            decode_host_request(&payload_two).expect("decode second request");
        assert!(matches!(decoded_two, HostRequest::PullVault(_)));

        let (command_three, payload_three) =
            read_framed_message(&mut reader).expect("decode third written frame");
        assert_eq!(command_three, CdcCommand::PullVault);
        let decoded_three: HostRequest =
            decode_host_request(&payload_three).expect("decode third request");
        assert!(matches!(decoded_three, HostRequest::PullVault(_)));

        assert_eq!(
            reader.position(),
            reader.get_ref().len() as u64,
            "expected head request followed by two pull requests"
        );
    }

    #[test]
    fn pull_persists_vault_chunks_to_file() {
        let responses = [
            encode_response(DeviceResponse::Head(PullHeadResponse {
                protocol_version: PROTOCOL_VERSION,
                vault_generation: 3,
                vault_hash: [0xAA; 32],
                recipients_hash: [0u8; 32],
                signature_hash: [0u8; 32],
            })),
            encode_response(DeviceResponse::VaultChunk(VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: 1,
                total_size: 5,
                remaining_bytes: 2,
                device_chunk_size: MAX_CHUNK_SIZE,
                data: vec![1, 2, 3],
                checksum: 0xDEAD_BEEF,
                is_last: false,
                artifact: VaultArtifact::Vault,
            })),
            encode_response(DeviceResponse::VaultChunk(VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: 2,
                total_size: 5,
                remaining_bytes: 0,
                device_chunk_size: MAX_CHUNK_SIZE,
                data: vec![4, 5],
                checksum: 0xC0FF_EE00,
                is_last: true,
                artifact: VaultArtifact::Vault,
            })),
        ]
        .concat();

        let mut port = MockPort::new(responses);
        let temp = tempdir().expect("tempdir");
        let args = RepoArgs {
            repo: temp.path().join("nested/repo"),
            credentials: temp.path().join("creds"),
            signing_pubkey: None,
        };

        write_empty_credentials(&args.credentials);
        execute_pull(&mut port, &args).expect("pull succeeds");

        let vault_path = args.repo.join("vault.enc");
        let content = fs::read(&vault_path).expect("vault file");
        assert_eq!(content, vec![1, 2, 3, 4, 5]);

        let recipients_path = args.repo.join("recips.json");
        assert!(!recipients_path.exists(), "unexpected recipients manifest");
        let signature_path = args.repo.join("vault.sig");
        assert!(!signature_path.exists(), "unexpected signature artifact");
    }

    #[test]
    fn pull_persists_vault_and_recipients_chunks_to_files() {
        let temp = tempdir().expect("tempdir");
        let args = RepoArgs {
            repo: temp.path().join("combined/repo"),
            credentials: temp.path().join("creds"),
            signing_pubkey: None,
        };

        let signing = write_credentials_with_keys(&args.credentials, false, false);
        let vault_payload = vec![9, 8, 7, 6, 5];
        let recipients_payload = br#"{"recipients":[]}"#.to_vec();
        let signature = sign_artifacts(&signing, &vault_payload, Some(&recipients_payload), None);

        let responses = [
            encode_response(DeviceResponse::Head(PullHeadResponse {
                protocol_version: PROTOCOL_VERSION,
                vault_generation: 7,
                vault_hash: [0x11; 32],
                recipients_hash: [0x22; 32],
                signature_hash: [0x33; 32],
            })),
            encode_response(DeviceResponse::VaultChunk(VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: 1,
                total_size: vault_payload.len() as u64,
                remaining_bytes: 0,
                device_chunk_size: MAX_CHUNK_SIZE,
                data: vault_payload.clone(),
                checksum: 0x0BAD_F00D,
                is_last: true,
                artifact: VaultArtifact::Vault,
            })),
            encode_response(DeviceResponse::VaultChunk(VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: 2,
                total_size: recipients_payload.len() as u64,
                remaining_bytes: 0,
                device_chunk_size: MAX_CHUNK_SIZE,
                data: recipients_payload.clone(),
                checksum: 0x0D15_EA5E,
                is_last: true,
                artifact: VaultArtifact::Recipients,
            })),
            encode_response(DeviceResponse::VaultChunk(VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: 3,
                total_size: SIGNATURE_SIZE as u64,
                remaining_bytes: 0,
                device_chunk_size: MAX_CHUNK_SIZE,
                data: signature.clone(),
                checksum: 0x1234_5678,
                is_last: true,
                artifact: VaultArtifact::Signature,
            })),
        ]
        .concat();

        let mut port = MockPort::new(responses);

        execute_pull(&mut port, &args).expect("pull succeeds");

        let mut reader = Cursor::new(port.writes);
        let (first_command, first_payload) =
            read_framed_message(&mut reader).expect("decode head request frame");
        assert_eq!(first_command, CdcCommand::PullHead);
        let decoded_head: HostRequest =
            decode_host_request(&first_payload).expect("decode head request");
        assert!(matches!(decoded_head, HostRequest::PullHead(_)));

        let (second_command, _) =
            read_framed_message(&mut reader).expect("decode first pull request frame");
        assert_eq!(second_command, CdcCommand::PullVault);

        let (third_command, _) =
            read_framed_message(&mut reader).expect("decode second pull request frame");
        assert_eq!(third_command, CdcCommand::PullVault);

        let (fourth_command, _) =
            read_framed_message(&mut reader).expect("decode third pull request frame");
        assert_eq!(fourth_command, CdcCommand::PullVault);

        assert_eq!(
            reader.position(),
            reader.get_ref().len() as u64,
            "expected head request followed by three pull requests",
        );

        let vault_path = args.repo.join("vault.enc");
        let vault_content = fs::read(&vault_path).expect("vault file");
        assert_eq!(vault_content, vault_payload);

        let recipients_path = args.repo.join("recips.json");
        let recipients_content = fs::read(&recipients_path).expect("recipients file");
        assert_eq!(recipients_content, recipients_payload);
        let signature_path = args.repo.join("vault.sig");
        let signature_content = fs::read(&signature_path).expect("signature file");
        assert_eq!(signature_content, signature);
    }

    #[test]
    fn pull_errors_when_signature_expected_without_verifying_key() {
        let temp = tempdir().expect("tempdir");
        let args = RepoArgs {
            repo: temp.path().join("missing-key/repo"),
            credentials: temp.path().join("creds"),
            signing_pubkey: None,
        };

        write_empty_credentials(&args.credentials);
        let signing = SigningKey::from_bytes(&TEST_SIGNING_SEED);
        let vault_payload = vec![1, 2, 3, 4];
        let signature = sign_artifacts(&signing, &vault_payload, None, None);

        let responses = [
            encode_response(DeviceResponse::Head(PullHeadResponse {
                protocol_version: PROTOCOL_VERSION,
                vault_generation: 4,
                vault_hash: [0x55; 32],
                recipients_hash: [0u8; 32],
                signature_hash: [0x77; 32],
            })),
            encode_response(DeviceResponse::VaultChunk(VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: 1,
                total_size: vault_payload.len() as u64,
                remaining_bytes: 0,
                device_chunk_size: MAX_CHUNK_SIZE,
                data: vault_payload.clone(),
                checksum: 0x0BAD_F00D,
                is_last: true,
                artifact: VaultArtifact::Vault,
            })),
            encode_response(DeviceResponse::VaultChunk(VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: 2,
                total_size: SIGNATURE_SIZE as u64,
                remaining_bytes: 0,
                device_chunk_size: MAX_CHUNK_SIZE,
                data: signature,
                checksum: 0x1234_5678,
                is_last: true,
                artifact: VaultArtifact::Signature,
            })),
        ]
        .concat();

        let mut port = MockPort::new(responses);
        let err = execute_pull(&mut port, &args).expect_err("pull should fail");

        match err {
            SharedError::Transport(message) => {
                assert!(message.contains("verifying key is missing"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }

        assert!(
            !args.repo.join(VAULT_FILE).exists(),
            "vault should not be persisted on failure",
        );
    }

    #[test]
    fn pull_errors_when_signature_verification_fails() {
        let temp = tempdir().expect("tempdir");
        let args = RepoArgs {
            repo: temp.path().join("bad-signature/repo"),
            credentials: temp.path().join("creds"),
            signing_pubkey: None,
        };

        let signing = write_credentials_with_keys(&args.credentials, false, false);
        let vault_payload = vec![4, 3, 2, 1];
        let mut signature = sign_artifacts(&signing, &vault_payload, None, None);
        signature[0] ^= 0xFF;

        let responses = [
            encode_response(DeviceResponse::Head(PullHeadResponse {
                protocol_version: PROTOCOL_VERSION,
                vault_generation: 9,
                vault_hash: [0x66; 32],
                recipients_hash: [0u8; 32],
                signature_hash: [0x88; 32],
            })),
            encode_response(DeviceResponse::VaultChunk(VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: 1,
                total_size: vault_payload.len() as u64,
                remaining_bytes: 0,
                device_chunk_size: MAX_CHUNK_SIZE,
                data: vault_payload.clone(),
                checksum: 0xFACE_CAFE,
                is_last: true,
                artifact: VaultArtifact::Vault,
            })),
            encode_response(DeviceResponse::VaultChunk(VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: 2,
                total_size: SIGNATURE_SIZE as u64,
                remaining_bytes: 0,
                device_chunk_size: MAX_CHUNK_SIZE,
                data: signature,
                checksum: 0x1357_9BDF,
                is_last: true,
                artifact: VaultArtifact::Signature,
            })),
        ]
        .concat();

        let mut port = MockPort::new(responses);
        let err = execute_pull(&mut port, &args).expect_err("pull should fail");

        match err {
            SharedError::Transport(message) => {
                assert!(message.contains("vault signature verification failed"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }

        assert!(
            !args.repo.join(VAULT_FILE).exists(),
            "vault should not be persisted on failure",
        );
    }

    #[test]
    fn pull_persists_multi_chunk_recipients_manifest() {
        let first_fragment = br#"{"recipients":[{"#.to_vec();
        let second_fragment = br#"address":"deadbeef"}]}"#.to_vec();
        let responses = [
            encode_response(DeviceResponse::Head(PullHeadResponse {
                protocol_version: PROTOCOL_VERSION,
                vault_generation: 11,
                vault_hash: [0x33; 32],
                recipients_hash: [0x44; 32],
                signature_hash: [0u8; 32],
            })),
            encode_response(DeviceResponse::VaultChunk(VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: 1,
                total_size: 4096,
                remaining_bytes: 0,
                device_chunk_size: MAX_CHUNK_SIZE,
                data: vec![1, 3, 3, 7],
                checksum: 0x0123_4567,
                is_last: true,
                artifact: VaultArtifact::Vault,
            })),
            encode_response(DeviceResponse::VaultChunk(VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: 2,
                total_size: (first_fragment.len() + second_fragment.len()) as u64,
                remaining_bytes: second_fragment.len() as u64,
                device_chunk_size: MAX_CHUNK_SIZE,
                data: first_fragment.clone(),
                checksum: 0x89AB_CDEF,
                is_last: false,
                artifact: VaultArtifact::Recipients,
            })),
            encode_response(DeviceResponse::VaultChunk(VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: 3,
                total_size: (first_fragment.len() + second_fragment.len()) as u64,
                remaining_bytes: 0,
                device_chunk_size: MAX_CHUNK_SIZE,
                data: second_fragment.clone(),
                checksum: 0x7654_3210,
                is_last: true,
                artifact: VaultArtifact::Recipients,
            })),
        ]
        .concat();

        let mut port = MockPort::new(responses);
        let temp = tempdir().expect("tempdir");
        let args = RepoArgs {
            repo: temp.path().join("multi/recipients"),
            credentials: temp.path().join("creds"),
            signing_pubkey: None,
        };

        write_empty_credentials(&args.credentials);
        execute_pull(&mut port, &args).expect("pull succeeds");

        let mut reader = Cursor::new(port.writes);
        let (first_command, first_payload) =
            read_framed_message(&mut reader).expect("decode head request frame");
        assert_eq!(first_command, CdcCommand::PullHead);
        let decoded_head: HostRequest =
            decode_host_request(&first_payload).expect("decode head request");
        assert!(matches!(decoded_head, HostRequest::PullHead(_)));

        for index in 0..3 {
            let (command, payload) =
                read_framed_message(&mut reader).expect("decode pull request frame");
            assert_eq!(
                command,
                CdcCommand::PullVault,
                "expected pull request #{index}"
            );
            let decoded: HostRequest = decode_host_request(&payload).expect("decode pull request");
            assert!(matches!(decoded, HostRequest::PullVault(_)));
        }

        assert_eq!(
            reader.position(),
            reader.get_ref().len() as u64,
            "expected one head request followed by three pull requests",
        );

        let recipients_path = args.repo.join("recips.json");
        let recipients_content = fs::read(&recipients_path).expect("recipients file");
        let mut expected = first_fragment;
        expected.extend_from_slice(&second_fragment);
        assert_eq!(recipients_content, expected);
        let signature_path = args.repo.join("vault.sig");
        assert!(!signature_path.exists(), "unexpected signature artifact");
    }

    #[test]
    fn status_sends_status_command() {
        let responses = encode_response(DeviceResponse::Status(StatusResponse {
            protocol_version: PROTOCOL_VERSION,
            vault_generation: 2,
            pending_operations: 1,
            current_time_ms: 42,
        }));

        let mut port = MockPort::new(responses);

        execute_status(&mut port).expect("status succeeds");

        let mut reader = Cursor::new(port.writes);
        let (command, payload) = read_framed_message(&mut reader).expect("decode written frame");
        assert_eq!(command, CdcCommand::Status);
        let decoded = decode_host_request(&payload).expect("decode request");
        assert!(matches!(decoded, HostRequest::Status(_)));
    }

    #[test]
    fn push_serializes_local_operations() {
        let temp = tempdir().expect("tempdir");
        let args = RepoArgs {
            repo: temp.path().to_path_buf(),
            credentials: temp.path().join("creds"),
            signing_pubkey: None,
        };

        let signing = write_credentials_with_keys(&args.credentials, true, true);

        let base_entry = sample_entry(Uuid::new_v4(), "existing");
        let initial_snapshot = sample_snapshot(vec![base_entry.clone()]);
        write_encrypted_vault(&args.repo, &initial_snapshot);

        let new_entry = sample_entry(Uuid::new_v4(), "added");
        let host_operations = vec![
            VaultJournalOperation::Add {
                entry: new_entry.clone(),
            },
            VaultJournalOperation::Update {
                id: base_entry.id,
                changes: EntryUpdate {
                    username: Some("updated".into()),
                    ..EntryUpdate::default()
                },
            },
        ];
        let encoded_ops = postcard_to_allocvec(&host_operations).expect("encode operations");
        fs::write(operations_log_path(&args.repo), &encoded_ops).expect("write operations");

        let ack_response = encode_response(DeviceResponse::Ack(AckResponse {
            protocol_version: PROTOCOL_VERSION,
            message: String::from("acknowledged"),
        }));

        let mut port = MockPort::new(ack_response.repeat(3));
        execute_push(&mut port, &args).expect("push succeeds");

        let mut reader = Cursor::new(port.writes);
        let payload = loop {
            let (command, payload) =
                read_framed_message(&mut reader).expect("decode written frame");
            if command == CdcCommand::PushOps {
                break payload;
            }

            assert_eq!(command, CdcCommand::PushVault);
        };
        let decoded = decode_host_request(&payload).expect("decode push request");

        match decoded {
            HostRequest::PushOps(frame) => {
                assert_eq!(frame.sequence, 1);
                assert!(frame.is_last);
                let mut expected = Vec::new();
                for op in &host_operations {
                    expected.extend(operations_for_device(op).expect("flatten host ops"));
                }
                assert_eq!(frame.operations, expected);
                assert_eq!(
                    frame.checksum,
                    compute_local_journal_checksum(&frame.operations)
                );
            }
            other => panic!("unexpected request written: {:?}", other),
        }

        assert_eq!(reader.position(), reader.get_ref().len() as u64);

        assert!(
            !operations_log_path(&args.repo).exists(),
            "operations file should be cleared after push",
        );

        let vault_path = args.repo.join(VAULT_FILE);
        let encrypted_vault = fs::read(&vault_path).expect("encrypted vault");
        let snapshot = decrypt_vault(&encrypted_vault, &TEST_VAULT_KEY).expect("decrypt vault");

        let added = snapshot
            .entries
            .iter()
            .find(|entry| entry.id == new_entry.id)
            .expect("added entry persisted");
        assert_eq!(added.title, new_entry.title);
        assert_eq!(added.username, new_entry.username);

        let updated = snapshot
            .entries
            .iter()
            .find(|entry| entry.id == base_entry.id)
            .expect("updated entry present");
        assert_eq!(updated.username, "updated");

        let signature_path = args.repo.join(SIGNATURE_FILE);
        let signature_bytes = fs::read(&signature_path).expect("signature file");
        assert_eq!(signature_bytes.len(), SIGNATURE_SIZE);
        let signature_array: [u8; SIGNATURE_SIZE] = signature_bytes
            .as_slice()
            .try_into()
            .expect("signature length");
        let signature = Signature::from_bytes(&signature_array);
        let message = compute_signature_message(&encrypted_vault, None, None);
        signing
            .verifying_key()
            .verify(&message, &signature)
            .expect("signature verifies");
    }

    #[test]
    fn load_local_operations_migrates_device_format() {
        let temp = tempdir().expect("tempdir");
        let repo = temp.path();
        let credentials = repo.join("creds.json");
        write_credentials_with_keys(&credentials, true, true);

        let existing_id = Uuid::new_v4();
        let mut updated_entry = sample_entry(existing_id, "existing");
        updated_entry.username = "updated-user".into();
        updated_entry.tags = vec!["tag".into()];
        updated_entry.updated_at = "2024-02-01T00:00:00Z".into();

        let new_entry = sample_entry(Uuid::new_v4(), "added");
        let snapshot = sample_snapshot(vec![updated_entry.clone(), new_entry.clone()]);
        write_encrypted_vault(repo, &snapshot);

        let host_operations = vec![
            VaultJournalOperation::Update {
                id: existing_id,
                changes: EntryUpdate {
                    username: Some(updated_entry.username.clone()),
                    tags: Some(updated_entry.tags.clone()),
                    updated_at: Some(updated_entry.updated_at.clone()),
                    ..EntryUpdate::default()
                },
            },
            VaultJournalOperation::Add {
                entry: new_entry.clone(),
            },
        ];

        let mut device_operations = Vec::new();
        for operation in &host_operations {
            device_operations.extend(operations_for_device(operation).expect("flatten host ops"));
        }

        let encoded_device =
            encode_journal_operations(&device_operations).expect("encode device ops");
        fs::write(operations_log_path(repo), &encoded_device).expect("write legacy operations");

        let config = HostConfig::load(&credentials).expect("load config");
        let loaded = load_local_operations(repo, &config).expect("load migrated operations");
        assert_eq!(loaded, host_operations);

        let rewritten = fs::read(operations_log_path(repo)).expect("read rewritten operations");
        let decoded: Vec<VaultJournalOperation> =
            postcard_from_bytes(&rewritten).expect("decode rewritten operations");
        assert_eq!(decoded, host_operations);
    }

    #[test]
    fn confirm_sends_ack_request_with_saved_state() {
        let sequence = 7;
        let frame_checksum = 0xAABBCCDD;
        let pull_responses = [
            encode_response(DeviceResponse::Head(PullHeadResponse {
                protocol_version: PROTOCOL_VERSION,
                vault_generation: 5,
                vault_hash: [0x44; 32],
                recipients_hash: [0u8; 32],
                signature_hash: [0u8; 32],
            })),
            encode_response(DeviceResponse::JournalFrame(JournalFrame {
                protocol_version: PROTOCOL_VERSION,
                sequence,
                remaining_operations: 0,
                operations: Vec::new(),
                checksum: frame_checksum,
            })),
        ]
        .concat();

        let temp = tempdir().expect("tempdir");
        let args = RepoArgs {
            repo: temp.path().to_path_buf(),
            credentials: temp.path().join("creds"),
            signing_pubkey: None,
        };

        write_empty_credentials(&args.credentials);
        {
            let mut port = MockPort::new(pull_responses);
            execute_pull(&mut port, &args).expect("pull succeeds");
        }

        let push_responses = encode_response(DeviceResponse::Ack(AckResponse {
            protocol_version: PROTOCOL_VERSION,
            message: String::from("acknowledged"),
        }));

        let mut push_port = MockPort::new(push_responses);
        execute_confirm(&mut push_port, &args).expect("confirm succeeds");

        let mut reader = Cursor::new(push_port.writes);
        let (command, payload) = read_framed_message(&mut reader).expect("decode written frame");
        assert_eq!(command, CdcCommand::Ack);
        let decoded = decode_host_request(&payload).expect("decode request");

        match decoded {
            HostRequest::Ack(ack) => {
                assert_eq!(ack.last_frame_sequence, sequence);
                assert_eq!(ack.journal_checksum, frame_checksum);
            }
            other => panic!("unexpected request written: {:?}", other),
        }
    }

    struct MockPort {
        read_cursor: Cursor<Vec<u8>>,
        writes: Vec<u8>,
    }

    impl MockPort {
        fn new(read_data: Vec<u8>) -> Self {
            Self {
                read_cursor: Cursor::new(read_data),
                writes: Vec::new(),
            }
        }
    }

    impl Read for MockPort {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_cursor.read(buf)
        }
    }

    impl Write for MockPort {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
