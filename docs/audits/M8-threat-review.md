# M8 threat review (author, step 1 of the security gate)

Milestone: M8, no-funds path, README and publishing preparation. Date: 7 November 2026. Written after audit M8 pointed out it was missing (M8-14); the controls below are what the fixes put in place.

## Design
- `scripts/dry-run.mjs` (`pnpm dry-run`): a dry 1Click quote, and every example receipt checked with the checker's own code against NEAR's archival RPC. It never signs and never creates a deposit address.
- `scripts/prepublish-check.mjs`: builds the would-be public tree (tracked files minus `scripts/public-tree.json`, the Gate 1 list). It checks internal material and the company name, banned wording (audit reports included), secrets, links and disclosures. It exports only a tree that passes.
- `scripts/build-site.mjs`: the static public site (landing page, checker, a dry mainnet shop preview, receipts, security headers).
- `scripts/mainnet-proof/agent-refusal.mjs` and `docs/mainnet-runbook.md`: the person-run mainnet steps.
- README and `HACKATHON.md`.

## Goals touched
S5 (the checker is never fooled into green), S7 (nothing secret or internal is published), and the hackathon's honesty and wording rules.

## Threats and controls
| Threat | Control | Test |
|---|---|---|
| A README claim does not reproduce, or overstates | Exact commands, expected output and evidence links per row; wording follows what exists today; a fresh-session cold test | `docs/audits/M8-cold-test.md`; `audit-m8-docs.test.mjs` |
| Example receipts stop verifying after a day (regular RPC forgets transactions) | Dry run uses the archival RPC; README tells checker users to pick it | `dry-run.test.mjs`, `audit-m8-dry-run.test.mjs` "M8-01 …" |
| The dry run signs, pays, or hides a failure | Only a dry quote; a deposit address or an unconfirmed receipt is FAIL and exit 1; 1Click text printed without control characters | `dry-run.test.mjs` |
| Internal material or the company name is published | Every text file scanned for the phrase in any spelling; `docs/internal/` and planning documents excluded in the draft Gate 1 list | `audit-m8-prepublish.test.mjs` "M8-02 …" |
| Banned wording in published audit reports | `lint-banned --public` covers `docs/audits/` | "M8-03 …" |
| A published link points at an excluded file | Inline, reference-style and HTML links checked, root-relative links resolved; code spans ignored | "M8-04 …" |
| A failing tree is exported anyway | `--export` only when every check passes | "M8-05 …" |
| The site build deletes a person's folder | Only an empty folder or a previous build (marker file) is replaced | `audit-m8-build-site.test.mjs` "M8-06 …" |
| The public shop shows an error, or reaches a local service | Dry preview against mainnet USDC, recipient the real gate or `near`; no relayer in its CSP | "M8-07 …" |
| The refusal example misreports, funds twice, or uses a key that can do more | Only "R8 alone failed" counts; funding once; the agent key must be a function-call key for `purchase` on the gate; a `refund` step | `agent-refusal.test.mjs`, `audit-m8-agent-refusal.test.mjs` |
| Mainnet checks read non-final data | Every provider read in the mainnet scripts passes final finality in the parameter the method reads (near-api-js defaults to optimistic) | `deploy-gate.test.mjs` "mainnet scripts read final data" |
| The runbook gives no "Verified" release, or the purchase scripts trust a file | A second release after the lock (7b); `verify` writes the gate record; the scripts compare with the reviewed hash constant | "M8-10 …", "M8-11 …", `proof.test.mjs` |

## Residual risk
- The checker page still defaults to the regular RPC (changing it would break the M6 browser tests' host allow-list); the README tells readers to choose the archival RPC for older receipts.
- `_headers` is read by some static hosts only (Netlify, Cloudflare Pages). On another host, `frame-ancestors` must be set as a header there; the live widget's own frame refusal remains.
- The final Gate 1 list is the lead's decision; the draft excludes planning documents.
