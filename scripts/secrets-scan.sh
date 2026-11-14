#!/usr/bin/env bash
# The only entry point for secrets scanning (Makefile, pre-commit hook, CI, tests).
# Usage: scripts/secrets-scan.sh --staged | --history | --dir <path>
#
# Hardening over plain gitleaks (docs/audits/M0.md, M0-01 and M0-02):
#  - project rules for NEAR private keys (.gitleaks.toml)
#  - inline "allow" comments are ignored
#  - base64 and other encodings are decoded before scanning
#  - a .gitleaksignore file anywhere is refused (findings cannot be silenced)
#  - archives are refused, because gitleaks cannot look inside them
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$ROOT/.gitleaks.toml"
FLAGS=(--no-banner --redact --ignore-gitleaks-allow --max-decode-depth 3 -c "$CONFIG")
ARCHIVE_RE='\.(zip|tar|tgz|gz|bz2|xz|7z|rar|jar|war|whl|zst)$'

fail() { echo "secrets-scan: $*" >&2; exit 1; }
command -v gitleaks >/dev/null || fail "gitleaks not found; run scripts/setup-env.sh"

check_names() {  # stdin: one path per line
  local names; names="$(cat)"
  if grep -Eq '(^|/)\.gitleaksignore$' <<<"$names"; then fail ".gitleaksignore is not allowed; fix or remove the secret instead"; fi
  local arch; arch="$(grep -Ei "$ARCHIVE_RE" <<<"$names" || true)"
  if [ -n "$arch" ]; then fail "archives cannot be scanned for secrets and are not allowed:"$'\n'"$arch"; fi
}

# gitleaks reads .gitleaksignore from the scanned directory and the current directory,
# whether or not it is committed: refuse to run if one exists there at all.
for d in "." "${2:-.}"; do
  [ -e "$d/.gitleaksignore" ] && fail ".gitleaksignore found in $d; fix or remove the secret instead"
done

case "${1:-}" in
  --staged)
    git diff --cached --name-only --diff-filter=ACMR | check_names
    gitleaks protect --staged "${FLAGS[@]}"
    ;;
  --history)
    git log --all --name-only --pretty=format: | sed '/^$/d' | sort -u | check_names
    gitleaks detect --source . "${FLAGS[@]}"
    ;;
  --dir)
    dir="${2:?--dir needs a path}"
    (cd "$dir" && find . -path ./node_modules -prune -o -path ./target -prune -o -path ./.git -prune -o -type f -print) | check_names
    gitleaks detect --no-git --source "$dir" "${FLAGS[@]}"
    ;;
  *) fail "usage: $0 --staged | --history | --dir <path>" ;;
esac
