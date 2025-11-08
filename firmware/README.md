# Firmware crate

This crate contains the embedded firmware for the Cardputer wallet prototype targeting the **ESP32-S3** microcontroller.

## Features

- Initializes the ESP32-S3 clock tree, watchdogs, and USB Serial/JTAG peripheral.
- Boots the [Embassy](https://embassy.dev/) executor to manage asynchronous tasks.
- Implements a USB CDC control loop that exchanges CBOR-encoded frames with the host.
- Provides journalling buffers for vault operations and zeroizes sensitive state between sessions.
- Derives a key-encryption key with scrypt (`N = 16384`, `r = 8`, `p = 1`) to wrap the vault symmetric key and device X25519 keypair.
- Encrypts vault records with ChaCha20-Poly1305 using fresh nonces per record.
- Tracks PIN failures with exponential backoff and escalates to a device wipe trigger after too many attempts.

## Building

1. Install the official Espressif Rust toolchain for Xtensa devices by following the [xtensa setup guide](https://docs.espressif.com/projects/rust/book/getting-started/toolchain.html#xtensa-devices). The short version is:

   ```bash
   cargo install espup
   espup install --targets esp32s3
   source "$HOME/.cargo/env"
   source "$HOME/export-esp.sh"
   cargo install espflash
   ```

2. (Optional) Regenerate the firmware scaffold with [`esp-generate`](https://github.com/esp-rs/esp-generate) when creating a new board profile:

   ```bash
   cargo install esp-generate
   esp-generate generate cardputer-wallet
   ```

   The existing crate already follows the generated layout; run the command only when bootstrapping a fresh checkout.

3. Build the firmware in release mode:

   ```bash
   cargo build --release -p firmware --target xtensa-esp32s3-none-elf
   ```

4. Flash the resulting image using `espflash` (adjust the serial port as needed):

   ```bash
   espflash flash target/xtensa-esp32s3-none-elf/release/firmware
   ```

## Testing on the host

The command parser and protocol handling logic can be validated on the development machine without hardware:

```bash
cargo test -p firmware
```

The tests exercise CBOR frame parsing, journal acknowledgements, and protocol version validation.

## Sync protocol overview

The firmware consumes CBOR-encoded `HostRequest` frames (length-prefixed on the USB CDC link) and responds with `DeviceResponse` frames. Placeholders are in place for the encrypted `vault.enc` and `recips.json` buffers, and for the cryptographic keys that will back the secure channel. Both buffers and cryptographic material are zeroed when the session finishes to avoid information leakage.
