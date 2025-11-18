use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ed25519_dalek::Signer;
use postcard::{from_bytes as postcard_from_bytes, to_allocvec as postcard_to_allocvec};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde_cbor::{from_slice as cbor_from_slice, to_vec as cbor_to_vec};
use shared::cdc::compute_crc32;
use shared::checksum::accumulate_checksum;
use shared::error::SharedError;
use shared::journal::JournalHasher;
use shared::schema::{
    DeviceResponse, HostRequest, JournalOperation as DeviceJournalOperation, PROTOCOL_VERSION,
    PushOperationsFrame, PushVaultFrame, VaultArtifact, decode_journal_operations,
    encode_journal_operations,
};
use shared::vault::{
    EntryUpdate, JournalOperation as VaultJournalOperation, LegacyField, PageCipher, VaultEntry,
};
use uuid::Uuid;

use crate::RepoArgs;
use crate::commands::host_config::{HostConfig, VaultSnapshot};
use crate::commands::signature::compute_signature_message;
use crate::commands::{DeviceTransport, RepoArtifactStore, print_repo_banner};
use crate::constants::{
    CONFIG_FILE, LEGACY_LOCAL_OPERATIONS_FILE, LOCAL_OPERATIONS_FILE, MAX_CHUNK_SIZE,
    PUSH_FRAME_MAX_PAYLOAD, RECIPIENTS_FILE, SIGNATURE_FILE, SIGNATURE_SIZE, VAULT_AAD, VAULT_FILE,
    VAULT_NONCE_SIZE,
};
use crate::transport::{
    CliResponseAdapter, DeviceResponseAdapter, RecordingResponseAdapter, handle_device_response,
    print_ack, read_device_response, send_host_request,
};

pub fn run<T, S>(transport: &mut T, store: &mut S, args: &RepoArgs) -> Result<(), SharedError>
where
    T: DeviceTransport + ?Sized,
    S: RepoArtifactStore + ?Sized,
{
    print_repo_banner(args);

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

    push_vault_artifacts(transport, store)?;

    let mut cli_adapter = CliResponseAdapter;
    let mut recording_adapter = RecordingResponseAdapter::new(None, None);

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
        send_host_request(transport, &request)?;

        let response = read_device_response(transport)?;
        let DeviceResponse::Ack(message) = response else {
            let description = format!("{response:?}");
            handle_device_response(
                response,
                &mut [
                    &mut cli_adapter as &mut dyn DeviceResponseAdapter,
                    &mut recording_adapter,
                ],
            )?;
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

fn push_vault_artifacts<T, S>(transport: &mut T, store: &S) -> Result<(), SharedError>
where
    T: DeviceTransport + ?Sized,
    S: RepoArtifactStore + ?Sized,
{
    let descriptors = [
        (VaultArtifact::Vault, "vault image"),
        (VaultArtifact::Recipients, "recipients manifest"),
        (VaultArtifact::Signature, "vault signature"),
    ];

    let mut cli_adapter = CliResponseAdapter;
    let mut recording_adapter = RecordingResponseAdapter::new(None, None);

    let mut sequence = 1u32;

    for (artifact, label) in descriptors.into_iter() {
        let Some(data) = store.load(artifact)? else {
            continue;
        };

        if matches!(artifact, VaultArtifact::Signature) && data.len() != SIGNATURE_SIZE {
            return Err(SharedError::Transport(format!(
                "signature artifact must be exactly {} bytes (found {})",
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
            send_host_request(transport, &request)?;
            let response = read_device_response(transport)?;
            let DeviceResponse::Ack(message) = response else {
                if let DeviceResponse::Nack(nack) = response {
                    return Err(SharedError::Transport(format!(
                        "device rejected {label}: {}",
                        nack.message
                    )));
                }
                let description = format!("{response:?}");
                handle_device_response(
                    response,
                    &mut [
                        &mut cli_adapter as &mut dyn DeviceResponseAdapter,
                        &mut recording_adapter,
                    ],
                )?;
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

pub(crate) fn load_local_operations(
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

pub(crate) fn operations_for_device(
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

pub(crate) fn operations_log_path(repo_path: &Path) -> PathBuf {
    repo_path.join(LOCAL_OPERATIONS_FILE)
}

fn legacy_operations_log_path(repo_path: &Path) -> PathBuf {
    repo_path.join(LEGACY_LOCAL_OPERATIONS_FILE)
}

pub(crate) fn compute_local_journal_checksum(operations: &[DeviceJournalOperation]) -> u32 {
    JournalHasher::digest(operations)
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

pub(crate) fn decrypt_vault(data: &[u8], key: &[u8; 32]) -> Result<VaultSnapshot, SharedError> {
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

pub(crate) fn encrypt_vault_with_rng<R>(
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
