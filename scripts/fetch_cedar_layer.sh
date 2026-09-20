#!/usr/bin/env bash
# Fetches the official prebuilt cedar-policy-cli Linux x86_64 binary and places
# it where the SAM template's CedarCliLayer expects it (ship-it/layers/cedar-cli/bin/cedar).
#
# Run this BEFORE `sam build` / `sam deploy` for the Ship It stack — the
# binary is intentionally NOT committed to git (it's an 18MB platform-specific
# executable; committing it would bloat repo history for no benefit since
# anyone building the stack should fetch it fresh, pinned to a known version).
#
# Usage: ./scripts/fetch_cedar_layer.sh [version]
#   version defaults to CEDAR_CLI_VERSION below, matching the pinned version
#   in ship-it/infra.template.yaml's Cedar CLI documentation.
#
# Reference: docs/03-architecture.md §2.6, docs/06-engineering-rules.md §1.

set -euo pipefail

CEDAR_CLI_VERSION="${1:-4.12.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
LAYER_BIN_DIR="$REPO_ROOT/ship-it/layers/cedar-cli/bin"
ASSET_URL="https://github.com/cedar-policy/cedar/releases/download/cedar-policy-cli-v${CEDAR_CLI_VERSION}/cedar-policy-cli-x86_64-unknown-linux-gnu.tar.xz"

echo "Fetching cedar-policy-cli v${CEDAR_CLI_VERSION} (Linux x86_64) for the Lambda layer..."
mkdir -p "$LAYER_BIN_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl --proto '=https' --tlsv1.2 -fsSL -o "$TMP_DIR/cedar.tar.xz" "$ASSET_URL"
tar -xJf "$TMP_DIR/cedar.tar.xz" -C "$TMP_DIR"

BINARY_PATH=$(find "$TMP_DIR" -type f -name cedar | head -n1)
if [ -z "$BINARY_PATH" ]; then
  echo "ERROR: could not locate 'cedar' binary inside the downloaded archive." >&2
  exit 1
fi

cp "$BINARY_PATH" "$LAYER_BIN_DIR/cedar"
chmod +x "$LAYER_BIN_DIR/cedar"

echo "Installed: $LAYER_BIN_DIR/cedar"
"$LAYER_BIN_DIR/cedar" --version
echo "Ready. This directory is packaged as the CedarCliLayer by ship-it/infra.template.yaml."
