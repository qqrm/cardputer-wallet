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

The host-side crates (`host-cli` and `shared`) target the standard Rust toolchain. After installing the Espressif toolchain with `espup` and sourcing the generated environment script, you can run the consolidated validation flow:

```bash
source "$HOME/export-esp.sh"
./scripts/dev-check.sh
```

The helper script executes `cargo fmt`, `cargo clippy`, `cargo test`, and finally `cargo check` for the firmware target, ensuring both the host and embedded crates are validated with a single command.
