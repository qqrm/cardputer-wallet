# Host CLI

The host-side command line utility coordinates communication with the Cardputer over the USB CDC interface. It is responsible for:

- discovering the virtual serial port exposed by the firmware;
- encoding requests with the shared postcard schema and transmitting them to the device;
- decoding postcard responses and presenting status information to the user;
- providing troubleshooting commands for flashing, diagnostics, and state introspection.

This crate depends on `serialport` for the CDC transport and uses postcard codecs shared with the firmware.

## Usage

Four high-level subcommands are currently supported:

- `pull` – request the latest vault snapshot from the device;
- `push` – transmit locally prepared journal operations to the device;
- `confirm` – acknowledge that journal frames were persisted on the host;
- `status` – send a lightweight probe and report the next device response.

Each command accepts the repository path and credentials path so the host knows where to place received data or which secrets to use for future pushes.

A typical pull flow looks like this:

```bash
cargo run -p host-cli -- pull --repo ./vault-replica --credentials ./cardputer.json
```

The CLI opens the detected USB CDC port (or the path provided through `--port`), transmits the request using postcard framing, and then prints progress as vault chunks, journal frames, and completion records are received.

### Serial port detection

By default the CLI scans all local USB CDC ports and selects the first device that reports the Cardputer vendor/product pair (`VID 0x303A`, `PID 0x4001`). If multiple ports expose that identity it prefers the one whose USB metadata references `Cardputer` or `M5Stack` in the product, manufacturer, or serial fields.

Pass `--any-port` to disable the filter and open the first enumerated USB serial device. This is useful when testing against mock firmware or development boards that use a different USB descriptor. When no matching Cardputer is found the CLI reports the expected VID/PID and suggests using the override for debugging.

## Module layout

### `commands/`

Each subdirectory under `commands/` contains the logic for a single subcommand. Modules accept any transport handle that implements `std::io::Read + std::io::Write`, so the same code path can talk to a real USB CDC port or an in-memory mock. The shared `run` helper in `commands/mod.rs` resolves the transport (auto-detects or honors `--port`) and dispatches to the requested command module.

### `transport.rs`

`transport.rs` is the only place that knows how to frame CDC traffic. It serialises `HostRequest` structures, validates `DeviceResponse` values, and prints friendly status logs. Because the helpers are generic over `Read + Write`, the unit tests build `MockPort` handles that replay canned frames without opening a physical device. The file also defines helper printers (`print_head`, `print_status`, etc.) and exposes `detect_first_serial_port` so new transports can be swapped in behind a feature flag.

### `artifacts.rs`

Pull operations accumulate state inside `PullArtifacts`. This structure owns in-memory buffers for vault chunks, recipients manifests, and signatures, tracks which artifacts were expected, and finally persists them to the repository. The module also stores the `FrameState` sync marker (`sync_state.json`) so the host can continue incremental pushes.

## Feature flags

The crate enables the `transport-usb` feature by default, which selects the USB CDC backend implemented in `transport.rs`. Additional transport backends can be introduced under new features, and at least one transport feature must remain enabled at build time (the binary emits a compile error otherwise). This setup lets downstream projects create bespoke host binaries that swap in other transports without touching the command logic.

## Testing and mocking

Run the full suite with:

```bash
cargo test -p host-cli
```

Targeted checks (for example, verifying the pull flow only) can be launched with:

```bash
cargo test -p host-cli tests::pull_flow -- --nocapture
```

All command modules depend on `Read + Write` trait bounds, so tests construct a `MockPort` that implements those traits and replays deterministic postcard frames. This makes it straightforward to mock device responses for custom scenarios without hitting the hardware transport.
