# M6 threat review (author, step 1 of the security gate)

Milestone: M6, receipt checker. Date: 6 November 2026.

## Design
A single static HTML file (`apps/checker/dist/index.html`, built by `apps/checker/build.mjs`) with the script and style inlined and allowed by hash in a strict CSP (`default-src 'none'`; `connect-src` only the NEAR RPC hosts in `src/rpc.ts`). It parses the receipt envelope with the shared `packages/receipt` code (format, hashes, signature, order against mandate, observed values), then asks the chosen RPC: chain ID, `get_receipt` (final), the decision transaction (`wait_until: FINAL`) and the block of the gate's step. A second RPC is optional and must agree.

## Goals touched
S4 (every decision anchored and checkable by a stranger), S5 (the checker cannot be fooled into green), S6 (no untrusted text changes a result or runs as code).

## Threats and controls
| Threat | Control | Test |
|---|---|---|
| Forged receipt with recomputed hashes | Chain checks: stored core hash, event in a final gate transaction, block height | `verify.test.ts` "sophisticated forgery …" |
| Swapped transaction hash, lookalike event from another contract, event from a failed receipt | Event must come from a successful receipt executed by the gate, with this core hash and order ID | "chain answers that must not count" |
| Non-final data, RPC errors, garbage, disagreeing second RPC, wrong network | All map to "Cannot verify", never green | same block of tests |
| XSS through any field | Grammar-checked fields; free text only in `untrusted.agent_note`, rendered with `textContent`; CSP blocks inline handlers | `page.test.ts` "XSS payloads …" |
| The page phones home or leaks the receipt | CSP `connect-src` allow-list; no CDN; link fragments are never sent; `no-referrer` | `page.test.ts` "network isolation", "the CSP blocks a host …" |
| Huge or malformed files | Size limits before parsing; 1 MB file limit in the page | "hostile files" |

## Edge cases (SECURITY.md section 6, M6)
Valid receipt all green; each field tampered (amount, payee, item, asset, rule result, decision, mandate hash, order hash, tx hash, block height) red with the failing check named; release-versus-refusal mismatch both ways; lookalike event, failed receipt, non-final block; RPC error, garbage, disagreement; XSS; huge file; malformed JSON; testnet receipt against a mainnet RPC; network log only to RPC hosts. Tests: `apps/checker/src/verify.test.ts` (36), `apps/checker/src/page.test.ts` (6, Chromium, built page opened from disk).

## Self-review (author, step 4: `/code-review high`, 6 Nov 2026)
| ID | Finding | Outcome | Regression test |
|---|---|---|---|
| M6-CR1 | The checker never checked that the gate runs the reviewed contract: a look-alike contract could answer every question with "release" | Fixed: `src/gates.ts` pins known gate accounts per network, their reviewed code hashes (reproducible from `make wasm-release`) and their settlement token, read from the gate's own config | "M6-CR1 …" (3 tests) |
| M6-CR2 | Hostile chain data (a number in the event core, a bad timestamp) could throw and leave no verdict | Fixed: every chain-derived step runs inside one guard that yields "Cannot verify" | "M6-CR2 …" |
| M6-CR3 | A refusal showed "The order stays inside what the buyer signed" as passed | Fixed: refusals show "The refusal matches the buyer's limits" with the failed rules in plain language | "M6-CR3 …" |
| M6-CR4 | An unexpected error left the page without a verdict | Fixed: the page shows "Cannot verify" | page tests |
| M6-CR5 | The facts said "Paid to" for refusals | Fixed: "Refused, no money moved", "Payee in the order", "Why refused" | "M6-CR8 … file" |
| M6-CR6 | Hand-written base58 decoding | Fixed: `@scure/base` | logic tests |
| M6-CR7 | The RPC size limit was applied after the whole answer was parsed | Fixed: streaming cap at 4 MB | "M6-CR7 …" |
| M6-CR8 | No browser test for file upload, the 1 MB limit or the mainnet RPC switch | Fixed | "M6-CR8 …" (2 tests) |
| M6-CR9 | Found in the screenshot review: a verified refusal was headed "Verified: this payment matches what the buyer approved", although no payment happened | Fixed: "Verified: the gate refused this order, and no money moved." | page test "a receipt link …" |
