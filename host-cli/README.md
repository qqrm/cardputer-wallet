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
