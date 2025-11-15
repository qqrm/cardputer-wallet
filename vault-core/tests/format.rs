use uuid::Uuid;
use vault_core::{
    EncryptedJournalPage, EntryUpdate, JOURNAL_AAD, JOURNAL_PAGE_VERSION, JournalOperation,
    JournalPage, JournalRecord, PageCipher, SecretString, TotpAlgorithm, TotpConfig, VaultEntry,
};

fn sample_entry(id: Uuid, title: &str) -> VaultEntry {
    VaultEntry {
        id,
        title: title.into(),
        service: "mail".into(),
        domains: vec!["example.com".into()],
        username: "alice".into(),
        password: SecretString::from("hunter2"),
        totp: Some(TotpConfig {
            secret: SecretString::from("JBSWY3DPEHPK3PXP"),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
        }),
        tags: vec!["prod".into()],
        r#macro: Some("{{username}}\t{{password}}".into()),
        updated_at: "2024-01-01T00:00:00Z".into(),
        used_at: Some("2024-01-01T00:00:00Z".into()),
    }
}

const PAGE_FIXTURE: &[u8] = include_bytes!("data/page.bin");
const ENVELOPE_FIXTURE: &[u8] = include_bytes!("data/envelope.bin");

#[test]
fn postcard_layout_matches_fixture() {
    let entry = sample_entry(Uuid::from_bytes([1; 16]), "Example");
    let update = EntryUpdate {
        password: Some(SecretString::from("rotated")),
        tags: Some(vec!["prod".into(), "rotated".into()]),
        updated_at: Some("2024-01-02T00:00:00Z".into()),
        ..EntryUpdate::default()
    };

    let records = vec![
        JournalRecord {
            operation: JournalOperation::Add {
                entry: entry.clone(),
            },
            timestamp: "2024-01-01T00:00:00Z".into(),
        },
        JournalRecord {
            operation: JournalOperation::Update {
                id: entry.id,
                changes: update,
            },
            timestamp: "2024-01-02T00:00:00Z".into(),
        },
    ];

    let page = JournalPage {
        version: JOURNAL_PAGE_VERSION,
        counter: 7,
        records,
    };

    let page_bytes = postcard::to_allocvec(&page).expect("encode page");
    assert_eq!(page_bytes.as_slice(), PAGE_FIXTURE);

    let cipher = PageCipher::chacha20_poly1305([0x11; 32]);
    let nonce = [0xAB; 12];
    let ciphertext = cipher
        .encrypt(&nonce, JOURNAL_AAD, page_bytes.as_slice())
        .expect("encrypt page");
    let envelope = EncryptedJournalPage {
        counter: page.counter,
        nonce,
        ciphertext: ciphertext.clone(),
    };

    let encoded_envelope = postcard::to_allocvec(&envelope).expect("encode envelope");
    assert_eq!(encoded_envelope.as_slice(), ENVELOPE_FIXTURE);

    let decrypted = cipher
        .decrypt(&nonce, JOURNAL_AAD, &ciphertext)
        .expect("decrypt page");
    assert_eq!(decrypted, page_bytes);
}
