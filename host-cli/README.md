# Host CLI

The host-side command line utility coordinates communication with the Cardputer over the USB CDC interface. It is responsible for:

- discovering the virtual serial port exposed by the firmware;
- encoding requests with the shared CBOR schema and transmitting them to the device;
- decoding CBOR responses and presenting status information to the user;
- providing troubleshooting commands for flashing, diagnostics, and state introspection.

This crate depends on `serialport` for the CDC transport and `serde_cbor` for the binary message format shared with the firmware.

## Usage

Three high-level subcommands are currently supported:

- `pull` – request the latest vault snapshot from the device;
- `push` – acknowledge that journal frames were persisted on the host;
- `status` – send a lightweight probe and report the next device response.

Each command accepts the repository path and credentials path so the host knows where to place received data or which secrets to use for future pushes.

A typical pull flow looks like this:

```bash
cargo run -p host-cli -- pull --repo ./vault-replica --credentials ./cardputer.json
```

The CLI opens the detected USB CDC port (or the path provided through `--port`), transmits the request using CBOR framing, and then prints progress as vault chunks, journal frames, and completion records are received.
