use alloc::{string::String, vec::Vec};

use super::{protocol, *};
use crate::sync::ProtocolError;
use crate::sync::test_helpers::fresh_context;
use shared::cdc::CdcCommand;
use shared::journal::FrameState;
use shared::schema::{
    DeviceResponse, HostRequest, PROTOCOL_VERSION, PullHeadRequest, PullVaultRequest,
    VaultArtifact, decode_device_response, encode_device_response, encode_host_request,
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

    let response = protocol::handle_pull(&request, &mut ctx).expect("pull chunk");
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
        let response = protocol::handle_pull(&request, &mut ctx).expect("pull chunk");
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

    let response = protocol::handle_pull(&request, &mut ctx).expect("pull chunk");
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

    let error = protocol::handle_pull(&request, &mut ctx).expect_err("expected buffer error");
    assert!(matches!(
        error,
        ProtocolError::HostBufferTooSmall {
            required: _,
            provided: 24
        }
    ));
}

#[test]
fn pull_head_reports_hashes() {
    let mut ctx = fresh_context();
    ctx.vault_image.extend_from_slice(b"encrypted");
    ctx.recipients_manifest
        .extend_from_slice(b"{\"recipients\":[\"device\"]}");
    ctx.signature
        .extend_from_slice(&[0x99; SIGNATURE_BUFFER_CAPACITY]);
    ctx.vault_generation = 2;

    let request = HostRequest::PullHead(PullHeadRequest {
        protocol_version: PROTOCOL_VERSION,
    });
    let encoded = encode_host_request(&request).unwrap();
    let (command, response_bytes) =
        process_host_frame(CdcCommand::PullHead, &encoded, &mut ctx).unwrap();
    assert_eq!(command, CdcCommand::PullHead);
    let response = decode_device_response(&response_bytes).unwrap();

    match response {
        DeviceResponse::Head(head) => {
            assert_eq!(head.vault_generation, ctx.vault_generation);
            assert_ne!(head.vault_hash, [0u8; 32]);
            assert_ne!(head.signature_hash, [0u8; 32]);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}
