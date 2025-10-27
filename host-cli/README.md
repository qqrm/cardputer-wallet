# Host CLI

The host-side command line utility coordinates communication with the Cardputer over the USB CDC interface. It is responsible for:

- discovering the virtual serial port exposed by the firmware;
- encoding requests with the shared CBOR schema and transmitting them to the device;
- decoding CBOR responses and presenting status information to the user;
- providing troubleshooting commands for flashing, diagnostics, and state introspection.

This crate depends on `serialport` for the CDC transport and `serde_cbor` for the binary message format shared with the firmware.
