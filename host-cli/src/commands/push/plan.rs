use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_cbor::{from_slice as cbor_from_slice, to_vec as cbor_to_vec};
use shared::cdc::compute_crc32;
use shared::error::SharedError;
use shared::journal::JournalHasher;
use shared::schema::{
    JournalOperation as DeviceJournalOperation, PROTOCOL_VERSION, PushOperationsFrame,
    decode_journal_operations, encode_journal_operations,
};
use shared::vault::{
    EntryUpdate, JournalOperation as VaultJournalOperation, LegacyField, VaultEntry,
};
use uuid::Uuid;

use crate::commands::host_config::HostConfig;
use crate::constants::{
    LEGACY_LOCAL_OPERATIONS_FILE, LOCAL_OPERATIONS_FILE, PUSH_FRAME_MAX_PAYLOAD, VAULT_FILE,
};

use super::artifacts::decrypt_vault;

pub(crate) struct PushPlan {
    pub(crate) frames: Vec<PushOperationsFrame>,
    pub(crate) total_operations: usize,
}

impl PushPlan {
    pub(crate) fn from_operations(
        operations: &[VaultJournalOperation],
    ) -> Result<Self, SharedError> {
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
    postcard::from_bytes(data)
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

    let encoded = postcard::to_allocvec(&operations).map_err(|err| {
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
                    && !sequence
                        .iter()
                        .any(|item| matches!(item, LegacyConvertedOp::Update(existing) if existing == &id))
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
                    && !sequence
                        .iter()
                        .any(|item| matches!(item, LegacyConvertedOp::Update(existing) if existing == &id))
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
    let encoded = postcard::to_allocvec(operations).map_err(|err| {
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

pub(crate) fn clear_local_operations(repo_path: &Path) -> Result<(), SharedError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use shared::schema::PushOperationsFrame;
    use shared::vault::JournalOperation as VaultJournalOperation;
    use uuid::Uuid;

    #[test]
    fn push_plan_builds_single_frame_for_small_updates() {
        let id = Uuid::new_v4();
        let operations = vec![VaultJournalOperation::Update {
            id,
            changes: EntryUpdate {
                username: Some("user".into()),
                ..EntryUpdate::default()
            },
        }];

        let plan = PushPlan::from_operations(&operations).expect("build plan");
        assert_eq!(plan.total_operations, 1);
        assert_eq!(plan.frames.len(), 1);
        let PushOperationsFrame {
            sequence, is_last, ..
        } = plan.frames[0];
        assert_eq!(sequence, 1);
        assert!(is_last);
    }

    #[test]
    fn build_push_frames_splits_large_payloads() {
        let mut operations = Vec::new();
        let mut device_ops = Vec::new();

        while encode_journal_operations(&device_ops)
            .expect("encode device operations")
            .len()
            <= PUSH_FRAME_MAX_PAYLOAD
        {
            let op = VaultJournalOperation::Delete { id: Uuid::new_v4() };
            device_ops.extend(operations_for_device(&op).expect("flatten operation"));
            operations.push(op);
        }

        let frames = build_push_frames(&operations).expect("build frames");
        assert!(frames.len() >= 2, "expected payload split across frames");
        assert!(frames.last().expect("last frame").is_last);
        assert_eq!(
            frames
                .iter()
                .map(|frame| frame.operations.len())
                .sum::<usize>(),
            device_ops.len()
        );
    }

    #[test]
    fn operations_for_device_encodes_updates() {
        let id = Uuid::new_v4();
        let operations = operations_for_device(&VaultJournalOperation::Update {
            id,
            changes: EntryUpdate {
                username: Some("demo-user".into()),
                password: Some("secret".into()),
                ..EntryUpdate::default()
            },
        })
        .expect("encode updates");

        assert_eq!(operations.len(), 2);
        assert!(operations.iter().any(|op| matches!(
            op,
            DeviceJournalOperation::UpdateField { field, .. } if field == "username"
        )));
        assert!(operations.iter().any(|op| matches!(
            op,
            DeviceJournalOperation::UpdateField { field, .. } if field == "password"
        )));
    }
}
