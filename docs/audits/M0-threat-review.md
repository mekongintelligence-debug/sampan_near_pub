# M0 threat review (author, step 1 of the security gate)

Milestone: M0, environment and scaffold. Date: 5 November 2026. Author: Claude Code session on `claude/practical-knuth-g21soa`.

## Goals touched (`docs/SECURITY.md` section 1)
- **S7, no secrets committed, logged or published.** M0 sets up the secrets scanner, the pre-commit hook and `.gitignore`.
- **Supply chain (section 3.6).** M0 chooses dependency managers, lockfiles, install-script policy, CI actions and tool versions.
- S1-S6 are not touched: M0 contains no contract logic, no payments and no checker.

## Threats considered
| Threat (section 2) | M0 control | Test |
|---|---|---|
| Secret committed by a person or a session | `gitleaks` in pre-commit and CI; `.gitignore` for keys, `.env`, credentials | `scripts/tests/security-baseline.test.mjs`: gitleaks finds a planted fake key; `.gitignore` covers key files |
| Compromised npm package runs code on install | pnpm 10 blocks dependency install scripts by default; `onlyBuiltDependencies` empty; lockfile committed; CI uses `--frozen-lockfile` | Test asserts `pnpm-workspace.yaml` allows no build scripts |
| Compromised crate or unexpected source | `cargo deny` (sources: crates.io only; licenses allow-list; advisories); `cargo audit`; `Cargo.lock` committed | `make security` |
| Compromised CI action | Actions pinned to full commit SHAs; `permissions: contents: read` | Test asserts every `uses:` is pinned to a 40-character SHA |
| Unsafe patterns creep in later (`innerHTML`, `eval`, `unwrap()` in the contract) | `scripts/lint-banned.mjs` in `make security`; clippy `unwrap_used` and `expect_used` denied outside tests | `scripts/tests/lint-banned.test.mjs` with planted violations |
| Banned wording in public docs ("firewall" in a title, "unstoppable", "x402" figures) | Same lint, on README, HACKATHON and `docs/` (not `docs/internal/`) | Planted violations in the test |
| Overflow in release builds | `overflow-checks = true` in the release profile | Test asserts the profile setting |

## Out of scope for M0
Contract, formats, payments, checker: covered from M2 onwards.
