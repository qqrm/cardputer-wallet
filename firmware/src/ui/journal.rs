use alloc::string::ToString;
use alloc::{format, string::String};

use shared::{schema::JournalOperation, vault::VaultEntry};

use super::{JournalAction, JournalEntryView};

/// Converts wire-level journal operations into UI-friendly entries.
///
/// Update entries always carry a short `update <field>` description so hint bars can surface
/// the touched field, even as the schema evolves. Delete entries intentionally leave the
/// description empty because the referenced record may already be gone.
pub trait JournalOperationViewExt {
    /// Render a journal entry view for the given operation using vault metadata for hints.
    fn into_view(self, entries: &[VaultEntry]) -> JournalEntryView;
}

impl JournalOperationViewExt for JournalOperation {
    fn into_view(self, entries: &[VaultEntry]) -> JournalEntryView {
        match self {
            JournalOperation::Add { entry_id } => JournalEntryView::new(
                entry_id.clone(),
                JournalAction::Add,
                find_entry_title(entries, &entry_id),
                None,
            ),
            JournalOperation::UpdateField {
                entry_id, field, ..
            } => JournalEntryView::new(
                entry_id.clone(),
                JournalAction::Update,
                Some(describe_update_field(&field)),
                None,
            ),
            JournalOperation::Delete { entry_id } => {
                JournalEntryView::new(entry_id, JournalAction::Delete, None, None)
            }
        }
    }
}

fn describe_update_field(field: &str) -> String {
    format!("update {field}")
}

fn find_entry_title(entries: &[VaultEntry], entry_id: &str) -> Option<String> {
    entries
        .iter()
        .find(|entry| entry.id.to_string() == entry_id)
        .map(entry_title)
}

fn entry_title(entry: &VaultEntry) -> String {
    entry.title.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use shared::vault::{SecretString, VaultEntry};
    use uuid::Uuid;

    #[test]
    fn add_operations_use_entry_titles() {
        let entries = vec![mock_entry(
            "2b30f286-8ad6-4687-b4bd-1fa5458a8c5c",
            "Example",
        )];
        let operation = JournalOperation::Add {
            entry_id: entries[0].id.to_string(),
        };

        let view = operation.into_view(&entries);

        assert_eq!(view.entry_id, entries[0].id.to_string());
        assert_eq!(view.action, JournalAction::Add);
        assert_eq!(view.description, Some(String::from("Example")));
    }

    #[test]
    fn update_operations_emit_field_hints() {
        let entries = vec![mock_entry(
            "f09cfb78-c2c7-4a3b-83af-30573faba8f0",
            "Service",
        )];
        let operation = JournalOperation::UpdateField {
            entry_id: entries[0].id.to_string(),
            field: String::from("username"),
            value_checksum: 0,
        };

        let view = operation.into_view(&entries);

        assert_eq!(view.entry_id, entries[0].id.to_string());
        assert_eq!(view.action, JournalAction::Update);
        assert_eq!(view.description, Some(String::from("update username")));
    }

    #[test]
    fn delete_operations_omit_descriptions() {
        let entries = vec![mock_entry(
            "2e6df3c7-2a31-4d0e-bad3-c3c67b943f63",
            "To Remove",
        )];
        let operation = JournalOperation::Delete {
            entry_id: entries[0].id.to_string(),
        };

        let view = operation.into_view(&entries);

        assert_eq!(view.entry_id, entries[0].id.to_string());
        assert_eq!(view.action, JournalAction::Delete);
        assert_eq!(view.description, None);
    }

    fn mock_entry(id: &str, title: &str) -> VaultEntry {
        VaultEntry {
            id: Uuid::parse_str(id).expect("uuid"),
            title: title.to_owned(),
            service: String::from("service"),
            domains: vec![],
            username: String::from("user"),
            password: SecretString::from("password"),
            totp: None,
            tags: vec![],
            r#macro: None,
            updated_at: String::from("2024-01-01T00:00:00Z"),
            used_at: None,
        }
    }
}
