# Cardputer Wallet Delivery Roadmap

This roadmap keeps the embedded password device focused on the minimum set of deliverables required for a reliable BLE/USB credential typer.

> **Project status:** The firmware, host tooling, and shared libraries are under active greenfield development. No releases have shipped, no builds have been distributed to users, and no backward-compatibility guarantees are currently required.

## Phase 0 – Minimal foundation
- Generate a fresh ESP32-S3 workspace with [`esp-generate`](https://github.com/esp-rs/esp-generate) and move existing firmware code into the scaffold (SPEC §3).
- Lock in the embedded stack: `esp-hal`, `embassy-executor`, `trouble`, `sequential-storage`, and shared codecs derived with `ergot` (SPEC §3).
- Document the toolchain bootstrap using [`espup`](https://github.com/esp-rs/espup) and verify cross-compilation on CI runners.
- Trim the repository to the three active crates (`firmware`, `shared`, `host-cli`) and delete unused prototypes or placeholder assets.

## Phase 1 – Secure vault core
- Implement the sequential flash log for encrypted entry storage and cover it with unit tests on the host (`shared`, SPEC §4, §6).
- Wire the PIN-based key hierarchy and AEAD envelope encryption for vault entries, ensuring zeroization of sensitive buffers (`firmware`, SPEC §4).
- Replace manual CBOR message structs with `ergot` definitions that compile to both firmware and host codecs (`shared`, SPEC §3, §7).
- Add continuous integration jobs for `cargo fmt`, `cargo clippy --all-targets`, and `cargo test` across all crates.

## Phase 2 – Transport and interaction loop
- Integrate the `trouble` BLE HID profile alongside USB HID with a shared action queue (`firmware`, SPEC §8).
- Expose the sync journal over USB CDC (BLE GATT transport is explicitly deferred to a later milestone so we stay focused on the credential-typing loop).
- Build the minimal Cardputer UI: lock screen, entry list, entry detail with TOTP timer, and sync status indicator (SPEC §9, §10).
- Extend the host CLI with `pull`, `push`, and diagnostics flows backed by the shared schema definitions (`host-cli`, SPEC §7).
- Document the removable-storage vault flow so operators can move the encrypted blob between SD card, workstation, and CLI without depending on Git remotes.

## Phase 3 – Hardening and release readiness
- Exercise long-running storage scenarios to validate flash wear levelling and recovery from unexpected resets (`firmware`, SPEC §4, §6).
- Conduct end-to-end security review covering PIN policy, key derivation, and transport resilience (SPEC §4, §5).
- Publish comprehensive developer and operator documentation: setup, flashing, troubleshooting, and security posture (SPEC §9).
- Tag the v0.1 release once all blocking issues are resolved and CI remains green for a full iteration.

## Continuous activities
- Keep dependencies on the latest compatible releases and audit changelogs before upgrading (`firmware`, `shared`, `host-cli`).
- Capture feedback from hardware dry runs and adjust UX or timing parameters accordingly (SPEC §8, §9).
- Monitor CI stability; treat regressions as release blockers.
- Run `./scripts/dev-check.sh` before committing to keep the workspace aligned with the standard validation suite.
- Use the updated `./scripts/dev-check.sh` to lint and test the firmware on the host `x86_64-unknown-linux-gnu` target before the optional Xtensa check so that both contexts stay green without redundant builds.
