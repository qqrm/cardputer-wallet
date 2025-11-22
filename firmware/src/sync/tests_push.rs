use alloc::{string::String, vec::Vec};

use super::{protocol, *};
use crate::sync::test_helpers::{checksum, fresh_context};
use ed25519_dalek::{Signer, SigningKey};
use shared::cdc::CdcCommand;
use shared::journal::{FrameState, JournalHasher};
use shared::schema::{
    AckRequest, DeviceResponse, HostRequest, JournalOperation, PROTOCOL_VERSION, PullVaultRequest,
    PushOperationsFrame, PushVaultFrame, VaultArtifact, decode_device_response,
    encode_host_request,
};

#[test]
fn acknowledgement_clears_pending_sequence() {
    let mut ctx = fresh_context();
    ctx.record_operation(JournalOperation::Delete {
        entry_id: String::from("obsolete"),
    });

    let pull_request = HostRequest::PullVault(PullVaultRequest {
        protocol_version: PROTOCOL_VERSION,
        host_buffer_size: 64 * 1024,
        max_chunk_size: 1024,
        known_generation: None,
    });
    let encoded_pull = encode_host_request(&pull_request).unwrap();
    let (response_command, response_bytes) =
        process_host_frame(CdcCommand::PullVault, &encoded_pull, &mut ctx).unwrap();
    assert_eq!(response_command, CdcCommand::PushOps);
    let frame = decode_device_response(&response_bytes).unwrap();
    let (sequence, checksum) = match frame {
        DeviceResponse::JournalFrame(frame) => (frame.sequence, frame.checksum),
        other => panic!("unexpected response: {other:?}"),
    };

    let ack = HostRequest::Ack(AckRequest {
        protocol_version: PROTOCOL_VERSION,
        last_frame_sequence: sequence,
        journal_checksum: checksum,
    });
    let encoded_ack = encode_host_request(&ack).unwrap();
    let (command, response_bytes) =
        process_host_frame(CdcCommand::Ack, &encoded_ack, &mut ctx).unwrap();
    assert_eq!(command, CdcCommand::Ack);
    let response = decode_device_response(&response_bytes).unwrap();
    match response {
        DeviceResponse::Ack(message) => {
            assert!(message.message.contains(&sequence.to_string()));
            assert!(ctx.frame_tracker.state().is_none());
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn ack_enqueues_session_end_action() {
    let mut ctx = fresh_context();
    ctx.record_operation(JournalOperation::Delete {
        entry_id: String::from("obsolete"),
    });

    let pull_request = HostRequest::PullVault(PullVaultRequest {
        protocol_version: PROTOCOL_VERSION,
        host_buffer_size: 64 * 1024,
        max_chunk_size: 1024,
        known_generation: None,
    });
    let encoded_pull = encode_host_request(&pull_request).unwrap();
    let (_, response_bytes) =
        process_host_frame(CdcCommand::PullVault, &encoded_pull, &mut ctx).unwrap();
    let frame = decode_device_response(&response_bytes).unwrap();
    let (sequence, checksum) = match frame {
        DeviceResponse::JournalFrame(frame) => (frame.sequence, frame.checksum),
        other => panic!("unexpected response: {other:?}"),
    };

    let ack = AckRequest {
        protocol_version: PROTOCOL_VERSION,
        last_frame_sequence: sequence,
        journal_checksum: checksum,
    };
    protocol::handle_ack(&ack, &mut ctx).expect("ack should succeed");

    let actions = crate::hid::core::actions::drain();
    assert!(actions.iter().any(|action| matches!(
        action,
        crate::hid::core::actions::DeviceAction::EndSession { .. }
    )));
}

#[test]
fn acknowledgement_keeps_vault_generation() {
    let mut ctx = fresh_context();
    ctx.vault_generation = 7;
    let expected_generation = ctx.vault_generation;
    let pending = FrameState {
        sequence: 12,
        checksum: 0xABCD_1234,
    };
    ctx.frame_tracker.record_state(pending);

    let ack = AckRequest {
        protocol_version: PROTOCOL_VERSION,
        last_frame_sequence: pending.sequence,
        journal_checksum: pending.checksum,
    };

    let response = protocol::handle_ack(&ack, &mut ctx).expect("ack should succeed");

    match response {
        DeviceResponse::Ack(message) => {
            assert_eq!(message.protocol_version, PROTOCOL_VERSION);
            assert!(message.message.contains(&pending.sequence.to_string()));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    assert!(!ctx.frame_tracker.is_pending());
    assert_eq!(ctx.vault_generation, expected_generation);
}

#[test]
fn push_operations_are_acknowledged() {
    let mut ctx = fresh_context();
    let operations = vec![JournalOperation::Add {
        entry_id: String::from("pushed"),
    }];
    let checksum = JournalHasher::digest(&operations);

    let request = HostRequest::PushOps(PushOperationsFrame {
        protocol_version: PROTOCOL_VERSION,
        sequence: 3,
        operations,
        checksum,
        is_last: true,
    });

    let encoded = encode_host_request(&request).expect("encode push frame");
    let (command, response_bytes) =
        process_host_frame(CdcCommand::PushOps, &encoded, &mut ctx).expect("process push");
    assert_eq!(command, CdcCommand::Ack);
    let response = decode_device_response(&response_bytes).expect("decode ack response");

    match response {
        DeviceResponse::Ack(message) => {
            assert!(message.message.contains("frame #3"));
            assert!(message.message.contains("0x"));
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn push_vault_with_valid_signature_applies_changes() {
    let mut ctx = fresh_context();
    let vault = b"vault-bytes".to_vec();
    let recipients = b"{\"recipients\":[]}".to_vec();

    let signing_key = SigningKey::from_bytes(&[
        0x9D, 0x61, 0xB1, 0x9D, 0xEF, 0xFD, 0x5A, 0x60, 0xBA, 0x84, 0x4A, 0xF4, 0x92, 0xEC, 0x2C,
        0xC4, 0x44, 0x49, 0xC5, 0x69, 0x7B, 0x32, 0x69, 0x19, 0x70, 0x3B, 0xAC, 0x03, 0x1C, 0xAE,
        0x7F, 0x60,
    ]);
    let mut signed_payload = Vec::new();
    signed_payload.extend_from_slice(&vault);
    signed_payload.extend_from_slice(&recipients);
    let signature = signing_key.sign(&signed_payload);
    let signature_bytes = signature.to_bytes();

    let vault_request = HostRequest::PushVault(PushVaultFrame {
        protocol_version: PROTOCOL_VERSION,
        sequence: 1,
        artifact: VaultArtifact::Vault,
        total_size: vault.len() as u64,
        remaining_bytes: 0,
        data: vault.clone(),
        checksum: checksum(&vault),
        is_last: true,
    });
    let encoded_vault = encode_host_request(&vault_request).expect("encode vault frame");
    let (command_vault, response_vault) =
        process_host_frame(CdcCommand::PushVault, &encoded_vault, &mut ctx)
            .expect("process vault chunk");
    assert_eq!(command_vault, CdcCommand::Ack);
    match decode_device_response(&response_vault).expect("decode vault ack") {
        DeviceResponse::Ack(message) => {
            assert!(message.message.contains("Vault"));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let recipients_request = HostRequest::PushVault(PushVaultFrame {
        protocol_version: PROTOCOL_VERSION,
        sequence: 2,
        artifact: VaultArtifact::Recipients,
        total_size: recipients.len() as u64,
        remaining_bytes: 0,
        data: recipients.clone(),
        checksum: checksum(&recipients),
        is_last: true,
    });
    let encoded_recipients =
        encode_host_request(&recipients_request).expect("encode recipients frame");
    let (command_recips, response_recips) =
        process_host_frame(CdcCommand::PushVault, &encoded_recipients, &mut ctx)
            .expect("process recipients chunk");
    assert_eq!(command_recips, CdcCommand::Ack);
    match decode_device_response(&response_recips).expect("decode recipients ack") {
        DeviceResponse::Ack(message) => {
            assert!(message.message.contains("Recipients"));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let signature_vec = signature_bytes.to_vec();
    let signature_request = HostRequest::PushVault(PushVaultFrame {
        protocol_version: PROTOCOL_VERSION,
        sequence: 3,
        artifact: VaultArtifact::Signature,
        total_size: SIGNATURE_BUFFER_CAPACITY as u64,
        remaining_bytes: 0,
        data: signature_vec.clone(),
        checksum: checksum(&signature_vec),
        is_last: true,
    });
    let encoded_signature =
        encode_host_request(&signature_request).expect("encode signature frame");
    let (command_sig, response_sig) =
        process_host_frame(CdcCommand::PushVault, &encoded_signature, &mut ctx)
            .expect("process signature chunk");
    assert_eq!(command_sig, CdcCommand::Ack);
    match decode_device_response(&response_sig).expect("decode signature ack") {
        DeviceResponse::Ack(message) => {
            assert!(message.message.contains("updated vault artifacts"));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    assert_eq!(ctx.vault_image.as_slice(), vault.as_slice());
    assert_eq!(ctx.recipients_manifest.as_slice(), recipients.as_slice());
    assert_eq!(ctx.signature.as_slice(), signature_vec.as_slice());
    assert_eq!(ctx.expected_signature, Some(signature_bytes));
    assert_eq!(ctx.vault_generation, 1);
    assert!(ctx.incoming_vault.is_empty());
    assert!(ctx.incoming_recipients.is_empty());
    assert!(ctx.incoming_signature.is_empty());
}

#[test]
fn push_vault_with_invalid_signature_is_rejected() {
    let mut ctx = fresh_context();
    let vault = b"vault".to_vec();
    let recipients = b"recipients".to_vec();

    let signing_key = SigningKey::from_bytes(&[
        0x9D, 0x61, 0xB1, 0x9D, 0xEF, 0xFD, 0x5A, 0x60, 0xBA, 0x84, 0x4A, 0xF4, 0x92, 0xEC, 0x2C,
        0xC4, 0x44, 0x49, 0xC5, 0x69, 0x7B, 0x32, 0x69, 0x19, 0x70, 0x3B, 0xAC, 0x03, 0x1C, 0xAE,
        0x7F, 0x60,
    ]);
    let mut signed_payload = Vec::new();
    signed_payload.extend_from_slice(&vault);
    signed_payload.extend_from_slice(&recipients);
    let mut signature = signing_key.sign(&signed_payload).to_bytes();
    signature[0] ^= 0xFF;

    let frames = [
        HostRequest::PushVault(PushVaultFrame {
            protocol_version: PROTOCOL_VERSION,
            sequence: 1,
            artifact: VaultArtifact::Vault,
            total_size: vault.len() as u64,
            remaining_bytes: 0,
            data: vault.clone(),
            checksum: checksum(&vault),
            is_last: true,
        }),
        HostRequest::PushVault(PushVaultFrame {
            protocol_version: PROTOCOL_VERSION,
            sequence: 2,
            artifact: VaultArtifact::Recipients,
            total_size: recipients.len() as u64,
            remaining_bytes: 0,
            data: recipients.clone(),
            checksum: checksum(&recipients),
            is_last: true,
        }),
        HostRequest::PushVault(PushVaultFrame {
            protocol_version: PROTOCOL_VERSION,
            sequence: 3,
            artifact: VaultArtifact::Signature,
            total_size: SIGNATURE_BUFFER_CAPACITY as u64,
            remaining_bytes: 0,
            data: signature.to_vec(),
            checksum: checksum(&signature),
            is_last: true,
        }),
    ];

    for frame in frames {
        let encoded = encode_host_request(&frame).expect("encode frame");
        let result = process_host_frame(CdcCommand::PushVault, &encoded, &mut ctx);
        match frame {
            HostRequest::PushVault(PushVaultFrame {
                artifact: VaultArtifact::Signature,
                ..
            }) => {
                let (command, response) = result.expect("signature chunk");
                assert_eq!(command, CdcCommand::Nack);
                match decode_device_response(&response).expect("decode nack") {
                    DeviceResponse::Nack(nack) => {
                        assert!(nack.message.contains("signature"));
                    }
                    other => panic!("unexpected response: {other:?}"),
                }
            }
            _ => {
                let (command, _) = result.expect("chunk ack");
                assert_eq!(command, CdcCommand::Ack);
            }
        }
    }

    assert!(ctx.vault_image.is_empty());
    assert!(ctx.recipients_manifest.is_empty());
    assert!(ctx.signature.is_empty());
}
