#!/usr/bin/env bash
# Set up a development or CI machine for this repository.
# Installs pinned tool versions and verifies downloaded binaries by checksum.
set -euo pipefail

CARGO_AUDIT_VERSION="0.22.2"
CARGO_DENY_VERSION="0.20.2"
GITLEAKS_VERSION="8.24.2"
GITLEAKS_SHA256="fa0500f6b7e41d28791ebc680f5dd9899cd42b58629218a5f041efa899151a8e"  # linux_x64
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

echo "== Rust toolchain (from rust-toolchain.toml)"
rustup show active-toolchain >/dev/null

echo "== cargo-audit ${CARGO_AUDIT_VERSION}, cargo-deny ${CARGO_DENY_VERSION}"
# Install when missing or when the installed version differs from the pin.
# Exact match on the first line of the version output (M0-11: "8.24.20" is not "8.24.2").
has_version() { command -v "$1" >/dev/null && [ "$("$@" 2>/dev/null | head -1 | tr -d '[:space:]')" = "$(printf %s "$VERSION_WANTED" | tr -d '[:space:]')" ]; }
VERSION_WANTED="cargo-audit ${CARGO_AUDIT_VERSION}"
has_version cargo-audit --version || cargo install --locked --force "cargo-audit@${CARGO_AUDIT_VERSION}"
VERSION_WANTED="cargo-deny ${CARGO_DENY_VERSION}"
has_version cargo-deny --version  || cargo install --locked --force "cargo-deny@${CARGO_DENY_VERSION}"

echo "== gitleaks ${GITLEAKS_VERSION} (checksum verified)"
VERSION_WANTED="${GITLEAKS_VERSION}"
if ! has_version gitleaks version; then
  mkdir -p "$BIN_DIR"
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  curl -fsSL -o "$tmp/gl.tgz" \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
  echo "${GITLEAKS_SHA256}  $tmp/gl.tgz" | sha256sum -c -
  tar -xzf "$tmp/gl.tgz" -C "$tmp" gitleaks
  install -m 0755 "$tmp/gitleaks" "$BIN_DIR/gitleaks"
fi

echo "== Node dependencies (lockfile only, no install scripts)"
corepack enable
pnpm install --frozen-lockfile

echo "== Git hooks"
git config core.hooksPath .githooks

echo "Setup complete. Run: make check && make security"
