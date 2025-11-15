use blake3::Hasher;

use crate::constants::{CONFIG_FILE, RECIPIENTS_FILE, SIGNATURE_DOMAIN, VAULT_FILE};

pub fn compute_signature_message(
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
