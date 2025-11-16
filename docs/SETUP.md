# Development environment setup

Follow these steps to prepare a development workstation for the Cardputer wallet project.

## Prerequisites

Install the following tools before proceeding:

- [Rust](https://www.rust-lang.org/tools/install)
- [Git](https://git-scm.com/downloads)
- [`just`](https://github.com/casey/just) (optional helper for running recurring commands)

Ensure the `cargo` binary directory is available on your `PATH`:

```bash
source "$HOME/.cargo/env"
```

## Installing the Espressif Rust toolchain with `espup`

The firmware crate targets the ESP32-S3 and requires the custom Xtensa-enabled Rust toolchain provided by Espressif. Install and activate it with [`espup`](https://github.com/esp-rs/espup):

```bash
cargo install espup
espup install --targets esp32s3
source "$HOME/.cargo/env"
source "$HOME/export-esp.sh"
```

The `espup install` command downloads the LLVM-based Xtensa toolchain and generates the `export-esp.sh` script. Sourcing the script exports `PATH`, `LIBRARY_PATH`, and `RUSTFLAGS` so that subsequent `cargo` invocations pick up the correct linker and build configuration.

## Firmware build prerequisites

Once the toolchain is active, install the Espressif flashing utility:

```bash
cargo install espflash
```

You can now build and flash the firmware:

```bash
cargo build --release -p firmware --target xtensa-esp32s3-none-elf
espflash flash target/xtensa-esp32s3-none-elf/release/firmware
```

## Host tooling

The host-side crates (`host-cli` and `shared`) target the standard Rust toolchain. The consolidated `./scripts/dev-check.sh` helper now runs the fast host-target firmware checks (`cargo clippy -p firmware --all-targets --features firmware-bin` and `cargo test -p firmware --lib --target x86_64-unknown-linux-gnu --features firmware-bin`) before touching the Xtensa environment, so you can still catch most regressions even if the Espressif toolchain is not yet installed.

To add the Xtensa coverage, install the Espressif toolchain and source the generated environment script before invoking the helper:

```bash
source "$HOME/export-esp.sh"
./scripts/dev-check.sh
```

Running `cardputer pull` after these steps now persists three artifacts inside the chosen repository or SD-card mirror (remote Git hosting is not part of the v0.1 scope):

- `vault.enc` – the encrypted vault image.
- `recips.json` – the recipients manifest.
- `vault.sig` – the detached Ed25519 signature covering the vault and manifest.

During a push the firmware verifies the detached signature against its built-in Ed25519 public key before accepting the new
vault or recipients manifest.
## Host CLI credentials and signatures

The host CLI validates every signed vault snapshot before writing it to disk. When the device advertises a signature but no verifying key is available locally, `cardputer pull` aborts rather than persisting unverifiable data. Provide the verifying key either in the credentials JSON or via the `--signing-pubkey` flag before invoking pull operations.

### Creating a credentials file

Create a JSON file (referenced by the `--credentials` flag) that contains the host-side secrets encoded as base64 (hex encoding is also accepted):

```json
{
  "signing_public_key": "<base64 Ed25519 verifying key>",
  "signing_secret_key": "<base64 Ed25519 seed>",
  "vault_key": "<base64 32-byte ChaCha20 key>"
}
```

- `signing_public_key` (32 bytes) allows the CLI to verify signatures during `cardputer pull`.
- `signing_secret_key` (32-byte seed) is required for `cardputer push` so the host can mint a fresh signature after rewriting the vault. Omit this field on pull-only hosts.
- `vault_key` (32 bytes) is required for `cardputer push` to decrypt the existing vault, apply pending journal operations, and produce a re-encrypted image.

### Verifying vault signatures

After a pull completes, the CLI emits `vault.sig` alongside `vault.enc` (and `recips.json` if the device supplied one). To manually audit the signature:

1. Decode the verifying key from the credentials file (or the `--signing-pubkey` override).
2. Compute the BLAKE3 digest for the signature domain `cardputer.vault.signature.v1`, sequentially hashing the filenames (`vault.enc`, `recips.json`, `config.json`) together with their lengths and contents. This is the same message the CLI prepares via the internal `compute_signature_message` helper.
3. Verify the Ed25519 signature in `vault.sig` against the digest using the verifying key. Any Ed25519 tooling (`ed25519-dalek`, `age-plugin`, etc.) can perform this check.

`cardputer push` re-encrypts the vault with the supplied `vault_key`, applies local operations, and signs the resulting snapshot with `signing_secret_key` before uploading frames back to the device. Both keys must therefore be present whenever a push is attempted. Host operators can optionally commit these artifacts to Git, but that workflow is considered a future enhancement rather than a v0.1 requirement.

## Reproducing the CI workflow locally

The CI pipeline now validates the firmware crate with both the Espressif Xtensa toolchain and the host toolchain. To mirror the job locally, run the steps below in the specified order after installing `espup`:

```bash
source "$HOME/.cargo/env"
cargo install espup
espup install --targets esp32s3
rustup default esp
./scripts/dev-check.sh
cargo build --release -p firmware --features firmware-bin --target xtensa-esp32s3-none-elf
```

Running the helper after installing the Espressif toolchain sources `export-esp.sh`, executes `cargo fmt`, and covers both host and embedded validation steps: the firmware crate is linted and its library tests run against the host `x86_64-unknown-linux-gnu` target using the `firmware-bin` feature, and then re-checked for the Xtensa configuration. The final `cargo build` command above demonstrates a production release build once the suite is green.
