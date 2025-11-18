use super::*;
use crate::sync::context::fresh_context;
use ed25519_dalek::{Signer, SigningKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use shared::cdc::FrameHeader;
use shared::cdc::transport::{decode_frame, encode_frame};
use shared::journal::FrameState;
use shared::schema::{
    AckRequest, DeviceResponse, decode_device_response, encode_host_request,
    encode_journal_operations,
};

#[test]
fn pull_request_with_matching_generation_returns_placeholder_chunk() {
    let mut ctx = fresh_context();
    ctx.vault_generation = 7;

    let request = PullVaultRequest {
        protocol_version: PROTOCOL_VERSION,
        host_buffer_size: 64 * 1024,
        max_chunk_size: 1024,
        known_generation: Some(7),
    };

    let response = handle_pull(&request, &mut ctx).expect("pull chunk");
    match response {
        DeviceResponse::VaultChunk(chunk) => {
            assert_eq!(chunk.protocol_version, PROTOCOL_VERSION);
            assert_eq!(chunk.sequence, 1);
            assert!(chunk.data.is_empty());
            assert_eq!(chunk.total_size, 0);
            assert_eq!(chunk.remaining_bytes, 0);
            assert!(chunk.is_last);
            assert_eq!(
                ctx.frame_tracker.state(),
                Some(FrameState {
                    sequence: chunk.sequence,
                    checksum: chunk.checksum,
                })
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    assert!(ctx.journal_ops.is_empty());
    assert_eq!(ctx.next_sequence, 2);
}

#[test]
fn pull_request_emits_journal_frame() {
    let mut ctx = fresh_context();
    ctx.record_operation(JournalOperation::Add {
        entry_id: String::from("entry-42"),
    });

    let request = HostRequest::PullVault(PullVaultRequest {
        protocol_version: PROTOCOL_VERSION,
        host_buffer_size: 64 * 1024,
        max_chunk_size: 1024,
        known_generation: None,
    });

    let encoded = encode_host_request(&request).expect("encode request");
    let (command, response_bytes) =
        process_host_frame(CdcCommand::PullVault, &encoded, &mut ctx).expect("process pull");
    assert_eq!(command, CdcCommand::PushOps);
    let response = decode_device_response(&response_bytes).expect("decode response");

    match response {
        DeviceResponse::JournalFrame(frame) => {
            assert_eq!(frame.protocol_version, PROTOCOL_VERSION);
            assert_eq!(frame.sequence, 1);
            assert_eq!(frame.operations.len(), 1);
            assert_eq!(
                ctx.frame_tracker.state(),
                Some(FrameState {
                    sequence: frame.sequence,
                    checksum: frame.checksum,
                })
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn pull_request_streams_vault_then_recipients() {
    let mut ctx = fresh_context();
    ctx.vault_image.extend_from_slice(b"vault-data");
    ctx.recipients_manifest.extend_from_slice(b"rec");
    ctx.reset_transfer_state();

    let request = PullVaultRequest {
        protocol_version: PROTOCOL_VERSION,
        host_buffer_size: 64 * 1024,
        max_chunk_size: 4,
        known_generation: None,
    };

    let mut chunks = Vec::new();
    for _ in 0..6 {
        let response = handle_pull(&request, &mut ctx).expect("pull chunk");
        match response {
            DeviceResponse::VaultChunk(chunk) => chunks.push(chunk),
            other => panic!("unexpected response: {other:?}"),
        }

        if let Some(last) = chunks.last()
            && last.artifact == VaultArtifact::Recipients
            && last.is_last
        {
            break;
        }
    }

    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.artifact == VaultArtifact::Vault)
    );
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.artifact == VaultArtifact::Vault && chunk.is_last)
    );
    let last = chunks.last().expect("at least one chunk");
    assert_eq!(last.artifact, VaultArtifact::Recipients);
    assert!(last.is_last);
    assert_eq!(last.data, b"rec");
    assert_eq!(
        ctx.frame_tracker.state(),
        Some(FrameState {
            sequence: last.sequence,
            checksum: last.checksum,
        })
    );
}

#[test]
fn pull_request_respects_host_buffer_limit() {
    let mut ctx = fresh_context();
    ctx.vault_image.extend_from_slice(&[0xAA; 64]);
    ctx.reset_transfer_state();

    let request = PullVaultRequest {
        protocol_version: PROTOCOL_VERSION,
        host_buffer_size: 96,
        max_chunk_size: 256,
        known_generation: None,
    };

    let response = handle_pull(&request, &mut ctx).expect("pull chunk");
    let chunk = match response {
        DeviceResponse::VaultChunk(chunk) => chunk,
        other => panic!("unexpected response: {other:?}"),
    };

    assert!(chunk.data.len() as u32 <= request.max_chunk_size);

    let encoded =
        encode_device_response(&DeviceResponse::VaultChunk(chunk.clone())).expect("encode");
    assert!(encoded.len() as u32 <= request.host_buffer_size);
}

#[test]
fn pull_request_rejects_tiny_host_buffer() {
    let mut ctx = fresh_context();
    ctx.vault_image.extend_from_slice(b"payload");
    ctx.reset_transfer_state();

    let request = PullVaultRequest {
        protocol_version: PROTOCOL_VERSION,
        host_buffer_size: 24,
        max_chunk_size: 1024,
        known_generation: None,
    };

    let error = handle_pull(&request, &mut ctx).expect_err("expected buffer error");
    assert!(matches!(
        error,
        ProtocolError::HostBufferTooSmall {
            required: _,
            provided: 24
        }
    ));
}

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
    let (command, _response_bytes) =
        process_host_frame(CdcCommand::Ack, &encoded_ack, &mut ctx).unwrap();

    assert_eq!(command, CdcCommand::Ack);
    assert!(!ctx.frame_tracker.is_pending());
}

#[test]
fn push_vault_applies_signed_payload() {
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
    let signature = signing_key.sign(&signed_payload);
    let signature_bytes = signature.to_bytes();

    let vault_request = HostRequest::PushVault(PushVaultFrame {
        protocol_version: PROTOCOL_VERSION,
        sequence: 1,
        artifact: VaultArtifact::Vault,
        total_size: vault.len() as u64,
        remaining_bytes: 0,
        data: vault.clone(),
        checksum: accumulate_checksum(0, &vault),
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
        checksum: accumulate_checksum(0, &recipients),
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
        checksum: accumulate_checksum(0, &signature_vec),
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
            checksum: accumulate_checksum(0, &vault),
            is_last: true,
        }),
        HostRequest::PushVault(PushVaultFrame {
            protocol_version: PROTOCOL_VERSION,
            sequence: 2,
            artifact: VaultArtifact::Recipients,
            total_size: recipients.len() as u64,
            remaining_bytes: 0,
            data: recipients.clone(),
            checksum: accumulate_checksum(0, &recipients),
            is_last: true,
        }),
        HostRequest::PushVault(PushVaultFrame {
            protocol_version: PROTOCOL_VERSION,
            sequence: 3,
            artifact: VaultArtifact::Signature,
            total_size: SIGNATURE_BUFFER_CAPACITY as u64,
            remaining_bytes: 0,
            data: signature.to_vec(),
            checksum: accumulate_checksum(0, &signature),
            is_last: true,
        }),
    ];

    for request in frames.into_iter() {
        let encoded = encode_host_request(&request).expect("encode frame");
        let (command, response_bytes) =
            process_host_frame(CdcCommand::PushVault, &encoded, &mut ctx).expect("process frame");

        let response = decode_device_response(&response_bytes).expect("decode response");
        match request {
            HostRequest::PushVault(ref push)
                if matches!(push.artifact, VaultArtifact::Signature) =>
            {
                assert_eq!(command, CdcCommand::Nack);
                match response {
                    DeviceResponse::Nack(nack) => {
                        assert!(nack.message.contains("vault signature verification failed"));
                    }
                    other => panic!("unexpected response: {other:?}"),
                }
            }
            _ => {
                assert_eq!(command, CdcCommand::Ack);
                assert!(matches!(response, DeviceResponse::Ack(_)));
            }
        }
    }

    assert!(ctx.vault_image.is_empty());
    assert!(ctx.recipients_manifest.is_empty());
    assert!(ctx.signature.is_empty());
    assert!(ctx.expected_signature.is_none());
    assert_eq!(ctx.vault_generation, 0);
    assert!(ctx.incoming_vault.is_empty());
    assert!(ctx.incoming_recipients.is_empty());
    assert!(ctx.incoming_signature.is_empty());
}

#[test]
fn unsupported_protocol_is_rejected() {
    let mut ctx = fresh_context();
    let request = HostRequest::PullVault(PullVaultRequest {
        protocol_version: PROTOCOL_VERSION + 1,
        host_buffer_size: 1,
        max_chunk_size: 1,
        known_generation: None,
    });
    let encoded = encode_host_request(&request).unwrap();
    let error = process_host_frame(CdcCommand::PullVault, &encoded, &mut ctx)
        .expect_err("expected rejection");
    assert!(matches!(error, ProtocolError::UnsupportedProtocol(_)));
}

#[test]
fn mismatched_command_is_rejected() {
    let mut ctx = fresh_context();
    let request = HostRequest::PullVault(PullVaultRequest {
        protocol_version: PROTOCOL_VERSION,
        host_buffer_size: 1,
        max_chunk_size: 1,
        known_generation: None,
    });
    let encoded = encode_host_request(&request).unwrap();
    let error = process_host_frame(CdcCommand::Ack, &encoded, &mut ctx)
        .expect_err("expected command mismatch");
    assert_eq!(error, ProtocolError::InvalidCommand);
}

#[test]
fn checksum_validation_detects_corruption() {
    let payload = b"payload".to_vec();
    let mut header = FrameHeader::new(
        PROTOCOL_VERSION,
        CdcCommand::PullVault,
        payload.len() as u32,
        compute_crc32(&payload),
    );

    decode_frame(&header, &payload).expect("valid checksum");

    header.checksum ^= 0xFFFF_FFFF;
    let error = decode_frame(&header, &payload).expect_err("expected checksum error");
    assert_eq!(ProtocolError::from(error), ProtocolError::ChecksumMismatch);
}

#[test]
fn transport_limit_matches_firmware_max_size() {
    let payload = vec![0u8; FRAME_MAX_SIZE + 1];
    let err = encode_frame(
        PROTOCOL_VERSION,
        CdcCommand::Hello,
        &payload,
        FRAME_MAX_SIZE,
    )
    .expect_err("frame too large");
    assert!(matches!(
        ProtocolError::from(err),
        ProtocolError::FrameTooLarge(_)
    ));
}

#[test]
fn hello_establishes_session() {
    let mut ctx = fresh_context();
    let request = HostRequest::Hello(HelloRequest {
        protocol_version: PROTOCOL_VERSION,
        client_name: "cli".into(),
        client_version: "0.1.0".into(),
    });

    let encoded = encode_host_request(&request).unwrap();
    let (command, response_bytes) =
        process_host_frame(CdcCommand::Hello, &encoded, &mut ctx).unwrap();
    assert_eq!(command, CdcCommand::Hello);

    let response = decode_device_response(&response_bytes).unwrap();
    match response {
        DeviceResponse::Hello(hello) => {
            assert_eq!(hello.protocol_version, PROTOCOL_VERSION);
            assert_eq!(hello.session_id, ctx.session_id);
            assert_eq!(ctx.next_sequence, 1);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn pull_request_streaming_respects_sequence() {
    let mut ctx = fresh_context();
    ctx.vault_image.extend_from_slice(&[0xAA; 64]);
    ctx.reset_transfer_state();

    let request = PullVaultRequest {
        protocol_version: PROTOCOL_VERSION,
        host_buffer_size: 256,
        max_chunk_size: 8,
        known_generation: None,
    };

    for expected_sequence in 1..5 {
        let response = handle_pull(&request, &mut ctx).expect("pull chunk");
        let chunk = match response {
            DeviceResponse::VaultChunk(chunk) => chunk,
            other => panic!("unexpected response: {other:?}"),
        };

        assert_eq!(chunk.sequence, expected_sequence);
        assert_eq!(
            ctx.frame_tracker.state(),
            Some(FrameState {
                sequence: chunk.sequence,
                checksum: chunk.checksum,
            })
        );
    }
}
