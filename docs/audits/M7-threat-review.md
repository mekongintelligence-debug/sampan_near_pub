# M7 threat review (author, step 1 of the security gate)

Milestone: M7, end-to-end receipts. Date: 7 November 2026.

## Design
- `packages/receipt/src/pack.ts`: builds a receipt envelope from transaction hashes only. The decision transaction gives the gate's `receipt` event (core and core hash) and the order (`purchase` args, or the funding message of `ft_transfer_call` through the gate's token). The registration or funding transaction gives the signed mandate. The packer requires a final decision transaction, exactly one receipt event from the gate in a successful receipt, the order hashing to `core.order_hash`, the mandate to `core.mandate_hash`, and the result parsing with the checker's own envelope parser. A release whose payout completed in the same transaction records it as the payout transaction.
- `apps/checker/src/verify.ts`: the gate is now tried last as a sender hint for the RPC `tx` lookup, so a decision sent by 1Click's account (direct checkout) is found. Nothing is trusted from the hint; every check reads the transaction itself.
- `scripts/m7/e2e.mjs` (`pnpm e2e`): on testnet, a direct checkout, an agent release and an agent refusal each produce a receipt packed from chain data that the checker verifies. Negative cases run against the live chain.

## Goals touched
S4 (every decision anchored and checkable), S5 (the checker is never fooled into green), S6 (no untrusted text changes a result).

## Threats and controls
| Threat | Control | Test |
|---|---|---|
| A receipt built with another order's decision transaction | Packer: order must hash to `core.order_hash`; checker: the decision transaction must carry this exact receipt | `pack.test.ts` "a decision transaction for another order …"; e2e N2 (live: checker `tx:fail`, invalid) |
| A receipt built with another mandate | Packer: signed mandate must hash to `core.mandate_hash`; envelope parser checks the same | `pack.test.ts` "a mandate transaction for another mandate …"; e2e N1 (live) |
| Lookalike event from another contract, an event in a failed receipt, two events | Only events from the gate in successful receipts; exactly one | `pack.test.ts` "a lookalike event …", "non-final, missing, or failed steps …" |
| Non-final data | Packer requires FINAL; checker shows "Cannot verify" | `pack.test.ts` "non-final …" |
| A payout recorded that did not complete | Payout transaction set only for a `done` payout event for this order | `pack.test.ts` "a payout that did not complete …" |
| An order smuggled through a fake token's `ft_transfer_call` | Funding-message orders accepted only from the gate's configured token | `pack.test.ts` "an order inside a funding message …" |
| Cross-network replay (a mainnet mandate used on testnet, and the reverse) | Gate refuses `wrong_network` at registration; checker refuses a receipt for the wrong network's RPC (M6) | e2e N3 (live); `verify.test.ts` (M6) |
| The sender hint makes the checker trust a transaction | The hint only routes the RPC lookup; the checks read signer, receipts, executor and events from the transaction | existing M6 checker tests unchanged (79 pass) |
| An over-long or hostile note | Note at most 280 characters, shown as untrusted text (M6) | `pack.test.ts` "an over-long note …" |

## Residual risk
- **Assumption:** mainnet RPCs, like the testnet RPC, accept any sender for the `tx` lookup. Checked with the first mainnet receipt.
- The mainnet examples (one release, one refusal) need the person-run mainnet deploy and purchase, after the A1 sign-off.
- The test gate keeps its owner key (Q16), so on testnet "Nobody can change the gate" and the decision-block check are "Cannot verify".

## Self-review (author, step 4: `/code-review high`, 7 Nov 2026)
| ID | Finding | Outcome | Regression test |
|---|---|---|---|
| M7-CR1 | On mainnet the 1Click delivery's `ft_transfer_call` is a receipt created by 1Click's contracts, not an action of the transaction, so the packer could not find the order of a direct checkout | Fixed: the packer also searches the receipts' actions; callers fetch with `EXPERIMENTAL_tx_status` | "M7-CR1 …" |
| M7-CR2 | The e2e fetched with `tx`, which returns no receipt actions | Fixed: `EXPERIMENTAL_tx_status` | e2e re-run, 7 Nov 17:30 UTC: 12 of 12 |
| M7-CR3 | A failed or non-final registration could supply the mandate | Fixed: must be final and successful | "M7-CR3 …" |
| M7-CR4 | The e2e wrote results only at the end, so a mid-run error left stale results | Fixed: results are always written, with the error | (script) |
| M7-CR5 | Event parsing duplicated without the checker's length cap | Partly fixed: one shared `MAX_EVENT_LOG`; the two parsers stay separate (the checker also needs the block hash) | existing tests |
| M7-CR6 | A redundant `core_hash` recheck after the envelope parser | Fixed: removed; parser errors map to `envelope_invalid` | "an event whose core does not hash …" |
| M7-CR7 | `ft_transfer_call` to another receiver could supply the order | Fixed: `receiver_id` must be the gate | "M7-CR7 …" |
