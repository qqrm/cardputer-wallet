# Firmware crate

This crate contains the embedded firmware for the Cardputer wallet prototype targeting the **ESP32-S3** microcontroller.

## Features

- Initializes the ESP32-S3 clock tree, watchdogs, and USB Serial/JTAG peripheral.
- Boots the [Embassy](https://embassy.dev/) executor to manage asynchronous tasks.
- Implements a USB CDC control loop that exchanges CBOR-encoded frames with the host.
- Provides journalling buffers for vault operations and placeholder cryptographic material that is securely wiped between sessions.

## Building

1. Install the Espressif Rust tooling and Xtensa target support:

   ```bash
   rustup target add xtensa-esp32s3-none-elf
   cargo install espflash
   ```

2. Build the firmware in release mode:

   ```bash
   cargo build --release -p firmware --target xtensa-esp32s3-none-elf
   ```

3. Flash the resulting image using `espflash` (adjust the serial port as needed):

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
