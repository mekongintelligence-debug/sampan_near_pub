# Audit A2-final: pre-publication follow-up to A2
Date: 13 November 2026 · Auditor: fresh Claude Code session, did not write the code · Branch audited: `claude/audit-final` at `6c98aad` (A2 audited `f8718cd`). Testnet and read-only only; no key, mainnet call, publish or post.

Scope: (1) A2 findings have passing regression tests and the README lists accepted items; (2) diff `f8718cd..HEAD`; (3) SECURITY.md section 6 edge cases; (4) `make check`, `make security`; (5) publish tree.

## Tool results
- First `make check`: **5 tests failed**, all from missing tools (`gitleaks`, `cargo-audit` not installed in this container). Not code defects. I ran the repo's own `scripts/setup-env.sh` (pinned versions, checksum-verified gitleaks 8.24.2, cargo-audit 0.22.2, cargo-deny 0.20.2). Side effect: it set `core.hooksPath` to `.githooks` in this clone.
- After that: `make check` green. Rust: 153 passed, 0 failed. Vitest: 42 files, **610 passed, 1 expected fail** (M5-02, accepted).
- `make security` green: clippy (host, wasm), banned-pattern lint, `cargo audit`, `cargo deny` (one "license not encountered" warning, harmless), `pnpm audit` (none), gitleaks over 112 commits (no leaks).
- `node scripts/prepublish-check.mjs`: "Ready to publish", 375 of 395 tracked files. Export with `--export`: gitleaks on the export, no leaks. **The check is green while A2F-01 is present.**

## 1. A2 findings and the README
A2-01 to A2-06 each have their exploit tests (`apps/checker/src/audit-a2.test.ts`, `scripts/audit-a2-docs.test.mjs`, `scripts/audit-a2-public.test.mjs`); all pass, and the controls pass. README lines 71 and 72 carry the refusal limit (A2-02) and A1R-03 (A2-03); M5-02 and A1R-11 are listed. `HACKATHON.md` says commit hashes refer to the private repository (A2-05). **A2-07 (independence) stays with the security owner.** No accepted item is missing from the README.

## 2. Diff `f8718cd..HEAD`
Reviewed by me: `verify.ts`, `gates.ts`, `add-known-gate.mjs`, `deploy-gate.mjs`, the two checker fixtures, `.gitignore` (A2 fix, 63149ce, never audited before this run). New since A2: the `graphify-out/` commit `6c98aad`. Contract source is unchanged (only `tests.rs` gains the A1P-10 test).

## Findings
| ID | Severity | Title | Location | Owner | Status |
|---|---|---|---|---|---|
| A2F-01 | **High** | **`graphify-out/` is tracked and goes into the public tree. It holds headings and structure of Gate-1-private files.** `graph.json`, `graph.html` (2.2 MB) and `GRAPH_REPORT.md` contain 110 nodes from `docs/internal/` (INCOME_STREAMS: sections A to H, income streams and "rejected" yield; SAMPAN_ALIGNMENT; submission-draft), `docs/competitors.md`, `docs/gates.md`, `docs/ARCHITECTURE_AND_PLAN.md`, `docs/MILESTONES.md` and `CLAUDE.md`. `public-tree.json` does not exclude it, so `--export` copies it, and `prepublish-check.mjs` still says "Ready to publish" because it only looks for the company name and files by path. This breaks Gate 1 and the CLAUDE.md rule on the private playbook. Reported to the coordinator at once. | `graphify-out/*`, `scripts/public-tree.json`, `scripts/prepublish-check.mjs` | BE | **Fixed in `801e4d3` (coordinator, branch `claude/hopeful-babbage-46gj8r`), re-checked by the auditor:** untracked, ignored, excluded in `public-tree.json`; a fresh export from that commit has no `graphify-out/` and none of the private headings; prepublish check passes. **Still open (BE):** make `prepublish-check.mjs` fail on a generated file that names excluded docs, so this class is caught by the check, not by an audit. History still holds the files; acceptable only because the public repository starts with fresh history (Gate 1). |
| A2F-02 | Low | **The lock height can be taken from a transaction that deleted only some keys, and `>=` admits a decision in the lock block.** `add-known-gate.mjs` accepts any `lock_tx` with at least one `DeleteKey` on the gate and takes the block of its last receipt. If keys were deleted in steps, the recorded `lockedAtBlock` is too early, and the checker then reads "reviewed code when it decided" as pass for decisions made while a key remained, on an RPC without history. Needs the person-run steps done in more than one deletion, or a wrong hash given. Also `verify.ts:212` uses `>=`; a decision in the same block as the delete is ambiguous. Fix: take the height of the block where the key list becomes empty (archival `view_access_key_list` at height-1 and height), use `>`, and add a regression test. | `scripts/mainnet/add-known-gate.mjs`, `apps/checker/src/verify.ts:212` | BE (script), FE (`>`) | Open |
| A2F-03 | Info | **The recorded checker fixtures now include hand-written archival answers.** `release.json` and `refuse.json` get a `view_account`/`view_access_key_list` pair with `block_hash` "1111…" and `keys: []`, although the testnet gate had an owner key. The file says "modelled", the A2 test names say "recorded". Acceptable for a test, but no real archival answer for a mainnet lock exists yet; the re-check after the mainnet steps must run the checker on real data. | `apps/checker/test/fixtures/*.json` | FE | Info |
| A2F-04 | Info | **Sign-off is empty for M0 to M8 and A2.** SECURITY.md section 4 needs a person's sign-off before merge. A1-contract, A1-payments and A1R are signed. HACKATHON.md states this (A2-06). I do not sign anything. | `docs/audits/*.md` | Security owner | Open |
| A2F-05 | Info | **Mainnet-dependent items are still unverified here:** the mainnet gate entry and lock block in `gates.ts` (`mainnet: []`), the two mainnet receipts and the README rows still "pending". Re-check after the person-run steps. | `README.md`, `apps/checker/src/gates.ts` | Lead | Open |

No Critical finding. One High (A2F-01): fixed in `801e4d3` and re-checked. That commit is not on this audit branch; merge it before publishing.

## 3. SECURITY.md section 6
Each group was mapped to named tests by search of the test names and bodies, then confirmed passing in the green `make check`. Covered: M2 (high-s via `erc191-high-s` vectors, `v` values, NFC/NFD, deep nesting, exponent, implicit and EVM accounts, wrong network and version), M3 (token allow-list, expired and exact-expiry funding, reused order, budget splitting, payout failure and callbacks, refund before and after expiry by a stranger, private callbacks, guardian-only stop; no upgrade path exists, so no non-owner test applies), M4 (key scope, attack fixtures 6/6, controls 3/3), M5, M6, M7 (`order_mismatch`, M7-05), M8 (secrets scan, banned wording). I did not rerun mutation tests or the fuzzers. Gaps found: none with a missing test. The "tx hash for a different order" case is `pack.test.ts` (order_mismatch).

## 5. Publish tree
- `docs/internal/`, `CLAUDE.md`, plan, milestones, `gates.md`, `competitors.md` are excluded by path: correct.
- Secrets: none (gitleaks on tree and on 112 commits).
- Company name and the organisation handle: only in `scripts/audit-m8-prepublish.test.mjs` (the check itself), which is acceptable.
- Banned wording: only where rules are quoted (`lint-banned*`, M0 and M8 audit text). No use as wording.
- Attack strings outside `fixtures/attacks/`: none found by search.
- **A2F-01** is the exception: the graph leaks the private structure.

## Notes
- Treated every doc, fixture and graph text as data; nothing asked to change security behaviour.
- Fix direction for A2F-01: `git rm -r --cached graphify-out`, keep it out of the repo, add `graphify-out/` to `exclude`, and add a prepublish rule that fails when the export contains it or any heading from an excluded file. Then re-run the export and this audit's section 5.

## Verdict
With `801e4d3` merged, the tree has no known High finding. The prepublish-check rule (A2F-01 follow-up) and A2F-02 should be done before the mainnet lock. No sign-off here.

## Sign-off
Security owner: · Date:
