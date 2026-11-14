# M3 threat review (author, step 1 of the security gate)

Milestone: M3, gate contract on testnet. Date: 6 November 2026.

## Design summary (from `docs/ARCHITECTURE_AND_PLAN.md` 3.4, decisions Q3, Q11-Q18, Q28)
- **Funding:** the buyer (or 1Click on their behalf) calls `ft_transfer_call` on the allow-listed token with `msg` = the signed mandate (canonical, `docs/FORMATS.md`). `ft_on_transfer` verifies it and credits the mandate's escrow, or returns the full amount (token refunds the sender). It never panics.
- **Purchase:** `purchase(order)` runs R1-R9, records a receipt core (hash stored, full core emitted as a NEP-297 event) and either releases (token transfer to the payee, with a `#[private]` callback) or refuses. Refusals return normally.
- **Refund:** after expiry anyone may trigger `refund(mandate_hash)`; funds go only to the mandate's `refund_to`.
- **Storage (deviation from Q17, for the owner to accept):** the agent's function-call key cannot attach NEAR, so the gate pays storage for mandates and receipts from its own balance, bounded by a minimum escrow per mandate, a cap on orders per mandate, a per-mandate escrow cap and a total escrow cap.

## Goals touched (`docs/SECURITY.md` section 1)
S1 (funds only to the signed payee within budget), S2 (refunds only to `refund_to`), S4 (every decision anchored), S6 (no off-chain text changes a decision).

## Threats and controls
| Threat | Control | Test (unit, mocked VM) |
|---|---|---|
| Fake token calls `ft_on_transfer` to credit escrow without real tokens | Predecessor must equal the configured token; otherwise the full amount is returned and no state changes | `abuse_fake_token_credit` |
| Mandate for another network, gate or token accepted | `network`, `gate`, `asset` checked at funding; mismatch refunds | `funding_rejects_*` |
| Replayed or reused mandate nonce / order ID | Mandate hash and order ID stored forever; reuse refused | `abuse_order_replay`, `funding_same_mandate_tops_up_only_when_unexpired` |
| Over-spend: one order above budget, or many small orders summing above it | `spent + amount <= max_amount` and `<= escrow`, checked arithmetic | `abuse_budget_split`, `rule_r7_*` |
| Agent pays a swapped payee or an item outside the mandate | R8, R9 | `rule_r8_*`, `rule_r9_*` |
| Someone other than the agent calls `purchase` | R5; strangers get a refusal value without any state change | `rule_r5_*`, `abuse_stranger_spam_no_state` |
| Re-entrancy / state after promise | Budget, escrow and order ID updated before the transfer promise; callback restores exactly on failure | `payout_failure_restores_state` |
| Callback forged by an outsider | `on_payout` / `on_refund` are `#[private]` | `abuse_callback_not_private` |
| Refund before expiry, twice, or to someone else | Expiry check; escrow zeroed before the promise; destination is the signed `refund_to` | `refund_*` |
| Storage griefing (many mandates or refusal receipts) | Min escrow per mandate; max orders per mandate; caps | `abuse_storage_caps` |
| Integer overflow | `u128` checked arithmetic; overflow-checks on | property test on invariants |
| Untrusted text in logs or state | Events contain only grammar-checked values (hex, accounts, decimals) | `event_contains_only_checked_values` |
| A decision without an anchored receipt | Every release and every authorised refusal stores the core hash and emits the event in the same call | `every_decision_has_receipt` |

## Invariants (SECURITY.md 6.0) checked by property tests
1. Sum of escrows <= tokens credited minus tokens sent. 2. spent + escrow = funded per mandate. 3. Transfers only to payee or refund_to. 4. A refusal changes no balance. 5. Order IDs and mandate nonces accepted once. 6. A failed payout restores the exact prior state.

## Self-review (author, step 4: `/code-review high`, 6 Nov 2026)
| ID | Finding | Outcome | Regression test |
|---|---|---|---|
| M3-CR1 | Mandate nonces were unique gate-wide: anyone could block a buyer's mandate by funding their own with the same nonce | Fixed: nonce key = buyer + nonce | `m3_cr1_other_buyer_cannot_squat_a_nonce` |
| M3-CR2 | Receipts were keyed by order ID gate-wide: another mandate could claim an order ID first | Fixed: key = mandate hash + order ID; `get_receipt(mandate_hash, order_id)` | `m3_cr2_order_id_cannot_be_claimed_by_another_mandate` |
| M3-CR3 | A refused funding transfer returns the tokens to `sender_id`, which for 1Click deliveries is 1Click's account, not the buyer | Open, **Assumption** to verify in M5 with a tiny amount (where 1Click sends a returned delivery) | none yet |
| M3-CR4 | `registration_deposit` was not validated, and the config is immutable: a low value breaks every first payout (as in testnet run 1) | Fixed: 0.00125 to 0.1 NEAR checked at init | `m3_cr4_init_rejects_registration_deposit_outside_bounds` |
| M3-CR5 | The gas check ran before the remaining work and its 20 Tgas margin did not cover receipt-creation fees: a release could abort with `GasExceeded` (reproduced at 66 Tgas) | Fixed: checked right before writing, margin 40 Tgas | `m3_cr5_gas_is_checked_after_the_work_and_never_aborts` (40 to 130 Tgas) |
| M3-CR6 | Unanchored refusals do not write state, against the CLAUDE.md rule "refusals must return normally and write state" | **Lead decision needed** (design: writing state for strangers enables storage griefing) | `abuse_stranger_spam_no_state` |
| M3-CR7 | An impossible restore in `on_payout` silently left the payout Pending | Fixed: shared `restore` emits an `internal` event | `m3_cr7_impossible_restore_is_flagged` |
| M3-CR8 | The registrations counter counts payees already registered on the token (their deposit is refunded) | Accepted: bounded (refunded deposits, failed payouts restore); set `max_registrations` with margin on mainnet | none |
| M3-CR9 | Duplicated restore logic in the two callbacks | Fixed (`restore`) | covered by payout and refund failure tests |
| M3-CR10 | Re-implemented hex and base58 helpers | Fixed (`sampan_formats::hex_lower`, `bs58` in tests) | n/a |

Also found by the testnet run and fixed: the receipt checker rejected genuine R6/R7 refusals because it required `observed` to equal the order on every receipt (**M3-X1**, `packages/receipt/src/index.ts`; tests "observed values on refusals (M3-X1)"; on chain: A9b in `docs/m3-testnet-results.json`).

## Edge cases (docs/SECURITY.md section 6, M3) and their tests
- `ft_on_transfer` from a non-allow-listed contract: `abuse_fake_token_credit` (and testnet A2). Unknown mandate in msg / malformed msg: `order_in_message_must_match_mandate`, `funding_rejects_malformed_msg`. Zero amount: `funding_rejects_zero_amount`. After expiry: `funding_rejects_expired_and_exact_expiry`, `funding_same_mandate_tops_up_only_when_unexpired`. Larger than `max_amount`: `funding_rejects_over_max_amount`.
- `purchase`: not agent/buyer `rule_r5_stranger_refused_without_state`; wrong asset `rule_r6_wrong_asset`; 1 above and exactly equal `rule_r7_one_above_remaining_budget`; zero amount: impossible by the order grammar (`amount` is positive, M2 vectors); wrong payee `rule_r8_wrong_payee`; wrong item `rule_r9_wrong_item`; reused order ID `rule_r4_order_replay_refused_without_state`, `abuse_order_replay`; expired and exact nanosecond `rule_r3_expired_refused_and_anchored`, `rules::tests::r3_exact_expiry_nanosecond_is_expired`; unknown mandate `purchase_unknown_mandate_and_invalid_order`.
- Budget splitting: `abuse_budget_split`.
- Payout failure (payee not registered, token panics): `payout_failure_restores_state` (and testnet run 1, real); callback gas: `m3_cr5_*`, `purchase_with_too_little_gas_is_refused_without_state`.
- Concurrency: `two_purchases_same_block`, `purchase_racing_refund`.
- `refund`: before expiry, after, twice, nothing left, by a stranger: `refund_before_expiry_refused`, `refund_after_expiry_by_stranger_goes_to_refund_to`, `refund_twice_and_nothing_left`, `refund_failure_restores_escrow`.
- Storage: many mandates without deposit `funding_rejects_mandate_cap_and_total_cap`, `funding_rejects_below_min`; order cap `abuse_storage_caps`. "Storage deposit refund on cleanup": no cleanup exists by design (records are kept forever for replay protection).
- Admin and upgrade methods from a non-owner: none exist (config fixed at init); `init_rejects_bad_config`.
- Events: `event_contains_only_checked_values`, `every_decision_has_receipt`.
- Callbacks forged: `abuse_callback_not_private`, `abuse_refund_callback_not_private`.
- Invariants 6.0: `invariants_hold` (proptest, 64 sequences of up to 40 operations).
