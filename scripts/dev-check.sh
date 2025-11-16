#!/usr/bin/env bash
set -euo pipefail

# Ensure the script runs from the repository root regardless of the current working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/.."

run() {
  echo "+ $*"
  "$@"
}

run cargo fmt --all -- --check
run cargo clippy --workspace --all-targets --exclude firmware -- -D warnings
run cargo test --workspace --exclude firmware
run cargo clippy -p firmware --all-targets --features firmware-bin -- -D warnings
run cargo test -p firmware --lib --target x86_64-unknown-linux-gnu --features firmware-bin

ESP_EXPORT_SCRIPT="${HOME}/export-esp.sh"

if [[ -f "${ESP_EXPORT_SCRIPT}" ]]; then
  # shellcheck disable=SC1090
  source "${ESP_EXPORT_SCRIPT}"

  run cargo check -p firmware --target xtensa-esp32s3-none-elf
else
  cat <<EOF
warning: ${ESP_EXPORT_SCRIPT} not found; skipping Xtensa firmware check.
Install the Espressif toolchain via 'espup install --targets esp32s3' and rerun the script
to validate the embedded target as well.
EOF
fi
