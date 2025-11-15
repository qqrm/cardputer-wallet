# Duplication Audit and Refactor Opportunities

## Tooling snapshot
- `cargo machete` confirms that every crate in the workspace uses only the dependencies it declares; no unused crates were reported.【89c1cf†L1-L3】
- `cargo +nightly udeps` rebuilt the workspace (with the nightly toolchain and freshly installed `cargo-udeps`) and likewise found no unused dependencies, aside from a warning already emitted by `shared::vault::cipher` about `EnvelopeAlgorithm` being only partially read.【3c1bcf†L1-L4】【1a2e14†L1-L23】
- `cargo +nightly fmt -- --unstable-features --skip-children` ran once `rustfmt` was added to the nightly toolchain, matching the formatting check requested in the task.【4d3ce0†L1-L3】【c0e62a†L1-L2】
- `rg` searches such as `rg -n "command_for_request"` and `rg -n "accumulate_checksum"` were used to pinpoint duplicated helpers across `host-cli` and `firmware`.【55d351†L1-L8】【941595†L1-L23】

## Protocol layer overlaps
### CDC framing helpers
- `shared::cdc` already defines the frame header structure and CRC helper but leaves I/O helpers to each binary.【F:shared/src/cdc.rs†L1-L69】【F:shared/src/cdc.rs†L70-L105】 Both the device (`firmware`) and the CLI implement near-identical functions for encoding and decoding CDC frames, including header validation and CRC checks. The device-side versions (`read_frame`/`write_frame`) appear at `firmware/src/lib.rs` lines 2110‑2170, while the CLI versions (`write_framed_message`/`read_framed_message`) live at `host-cli/src/main.rs` lines 1533‑1621.【F:firmware/src/lib.rs†L2110-L2170】【F:host-cli/src/main.rs†L1533-L1621】
- Both crates also mirror the same `command_for_request`/`command_for_response` tables and validation logic before dispatching or acknowledging payloads.【F:firmware/src/lib.rs†L1534-L1595】【F:host-cli/src/main.rs†L1624-L1660】 Centralizing these helpers in `shared::cdc` (or a `shared-transport` crate) would shrink each binary substantially while guaranteeing parity.

### Journal checksums and sequencing
- `SyncContext::compute_journal_checksum` folds each outgoing `JournalOperation` with `accumulate_checksum`, matching the host’s `compute_local_journal_checksum` that works over `DeviceJournalOperation` when staging pushes.【F:firmware/src/lib.rs†L1219-L1238】【F:host-cli/src/main.rs†L1007-L1024】 Sharing a `JournalHasher` helper would eliminate the duplicated folding logic and prevent checksum skew between host/device.
- The ack/sequencing state machines also share concepts: the device stores `(sequence, checksum)` pairs in `SyncContext` while the CLI keeps the same tuple inside `FrameTracker` (see `host-cli/src/main.rs` lines 1116‑1172). Exposing this pattern as a reusable struct would simplify testing and improve error messaging consistency.

### Artifact streaming state
- `SyncContext` tracks outgoing vault, recipients, and signature buffers plus offsets for chunking responses, while also tracking pending uploads and session metadata.【F:firmware/src/lib.rs†L887-L950】 Its `next_transfer_chunk` method shapes each `VaultChunk`, calculates checksums, and respects the host buffer budget, tying directly into `handle_pull` when the host fetches artifacts.【F:firmware/src/lib.rs†L1370-L1424】【F:firmware/src/lib.rs†L1694-L1765】
- The CLI mirrors this concept in `PullArtifacts`, which buffers incoming `VaultChunk`s per artifact, records metadata, and ensures recipients/signature payloads arrive when expected before persisting to disk.【F:host-cli/src/main.rs†L1188-L1309】 Extracting a shared “artifact transfer” module would reduce coupling between protocol handling and persistence, making it easier to add new artifact types (e.g., audit logs) in both binaries.

## Vault storage and crypto
- The shared crate already offers `PageCipher` and `VaultJournal` abstractions for encrypting/decrypting journal pages and writing to sequential flash.【F:shared/src/vault/cipher.rs†L1-L84】【F:shared/src/vault/storage.rs†L250-L365】 Only the CLI currently consumes these types when encrypting/decrypting the repository snapshot (`decrypt_vault`/`encrypt_vault_with_rng`); the firmware reimplements AEAD logic directly with `chacha20poly1305` and hand-written buffers instead of reusing `PageCipher`.【F:host-cli/src/main.rs†L1851-L2046】【F:firmware/src/lib.rs†L13-L27】
- Aligning firmware storage with `shared::vault::VaultJournal` (or moving those types into a dedicated `vault-core` crate) would tighten parity with the host’s repository logic and reduce the chance of format drift.

## Module size inventory (target: <300 LOC)
| File | Lines | Notes |
| --- | --- | --- |
| `firmware/src/lib.rs` | 3,285 | Monolithic; mixes protocol handlers, cryptography, storage, and sync orchestration.【10322b†L1-L8】 |
| `host-cli/src/main.rs` | 3,194 | One file implements CLI parsing, serial transport, repo management, crypto, and tests.【cf22c1†L1-L2】 |
| `firmware/src/ui/state.rs` | 820 | UI view-model logic plus effect plumbing lives in one file, making it hard to reuse in tests or future UI shells.【10322b†L1-L8】 |
| `shared/src/vault/storage.rs` | 412 | Contains both error types and the entire `VaultJournal` implementation; splitting persistence helpers from flash glue would ease reuse.【148270†L1-L5】 |
| `shared/src/vault/model.rs` | 277 | Close to the 300 LOC target; separating TOTP helpers from entry structs could keep it smaller as fields grow.【148270†L1-L5】 |

## Refactor candidates
| Candidate | Scope | Effort | Impact | Notes |
| --- | --- | --- | --- | --- |
| Shared CDC transport module | Move frame encode/decode, header validation, and command mapping into `shared::cdc`, exposing async/blocking adapters for host and firmware. | Medium | High | Removes duplicated logic shown in both binaries and guarantees identical framing semantics.【F:firmware/src/lib.rs†L2110-L2170】【F:host-cli/src/main.rs†L1533-L1660】 |
| Journal checksum/ack helper | Provide a `JournalHasher` + `FrameTracker` struct under `shared` to replace the duplicated checksum folds and `(sequence, checksum)` tuples. | Low | Medium | Simplifies push/pull handlers on both sides and keeps checksum salt changes centralized.【F:firmware/src/lib.rs†L1219-L1238】【F:host-cli/src/main.rs†L1007-L1172】 |
| Artifact streaming abstraction | Extract the overlapping buffer/offset logic from `SyncContext::next_transfer_chunk` and `PullArtifacts` into a shared module or crate. | Medium | High | Reduces risk of host/device chunking mismatches and makes it easier to test artifact ordering logic independently.【F:firmware/src/lib.rs†L1370-L1765】【F:host-cli/src/main.rs†L1188-L1309】 |
| Vault core crate | Promote `PageCipher`, `VaultJournal`, and snapshot serialization into a dedicated crate consumed by both host and firmware, replacing the firmware’s bespoke AEAD handling. | High | High | Aligns on-disk formats and crypto across components, simplifies audits, and enables fuzz testing in one place.【F:shared/src/vault/cipher.rs†L1-L84】【F:host-cli/src/main.rs†L1851-L2046】 |
| Modularize host CLI | Split `host-cli/src/main.rs` into modules for CLI/UX, transport, repository sync, and tests, keeping each under ~300 LOC. | Medium | Medium | Improves readability, LLM compatibility, and targeted testing while preparing for future commands. Line count makes this urgent.【cf22c1†L1-L2】 |
| Slice firmware core | Break `firmware/src/lib.rs` into submodules (e.g., protocol handlers, crypto, storage, BLE transport) and move UI runtime into its own crate if needed. | High | High | Reduces compile times and makes on-device logic testable; also shrinks the no_std surface per module.【10322b†L1-L8】【F:firmware/src/lib.rs†L887-L1765】 |
| UI state modules | Split `firmware/src/ui/state.rs` into separate view-models (Lock/Home, Entry/Edit, Sync) and shared widgets to meet the <300 LOC guidance. | Medium | Medium | Enables independent UI testing and simplifies future UI platforms.【F:firmware/src/ui/state.rs†L1-L82】 |
| Vault journal surface | Separate `shared/src/vault/storage.rs` into error definitions, nonce/cipher helpers, and flash adapters to keep each unit compact. | Low | Medium | Makes it easier for firmware to adopt the shared persistence layer without dragging in flash-specific glue. | 
