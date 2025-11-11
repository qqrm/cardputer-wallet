# Cardputer Wallet

This repository contains the firmware and host tooling for the Cardputer password vault. The host CLI (`host-cli`) now supports
end-to-end signature validation for pulled vaults and signs the updated snapshot before every push.

## Host CLI quick start

1. Prepare a credentials file (JSON) that contains the following keys encoded as base64 or hexadecimal strings:
   - `signing_public_key` – the Ed25519 verifying key used to validate `vault.sig` during pulls.
   - `signing_secret_key` – the Ed25519 seed required to sign refreshed vault snapshots during pushes.
   - `vault_key` – the 32-byte ChaCha20 key that encrypts the vault payload.
2. Pull the latest vault from a repository:

   ```bash
   cargo run -p host-cli -- pull --repo <repo-path> --credentials <credentials.json>
   ```

   Add `--signing-pubkey <path>` when the verifying key is stored separately from the credentials JSON. The command aborts if the
   device advertises a signature and no verifying key is available.
3. Apply local operations and push them back to the device:

   ```bash
   cargo run -p host-cli -- push --repo <repo-path> --credentials <credentials.json>
   ```

   The CLI decrypts `vault.enc`, applies the staged operations, re-encrypts the vault, writes a fresh `vault.sig`, and then
   streams the frames to the device.

Refer to [`docs/SETUP.md`](docs/SETUP.md) for the full development environment instructions and signature-verification details.
