# Audit A1R: independent review of the A1 redesign (before mainnet)
Date: 7 November 2026 · Auditor session: fresh Claude Code subagent with no author context. It runs inside the cloud session `session_01CRNp9dXNNRsXBgwWH9ULTZ`, which also appears on the author's commits, as for A1-contract and A1-payments. The security owner should decide whether this run counts as the separate session `docs/MILESTONES.md` asks for. The independent check is this audit, not the merger. · Commit audited: `84fc11a` (branch `claude/practical-knuth-g21soa`).

Scope: what changed since `7267094` (`git diff 7267094 84fc11a`).
- `contracts/gate/src/lib.rs`: `register_mandate` with a storage deposit, `FundingMsg` by `mandate_hash` or `signed_mandate`, refund due, exact-price once-only orders in payments, `max_lifetime_ns`, the guardian and one-way `stop()`, `try_close` returning the deposit minus `kept_bytes` and the registrations used, two registrations per mandate, init checks.
- The adapted auditor tests in `contracts/gate/tests/` and `scripts/a1/audit-a1-payments.test.mjs` ("Author adaptation" markers).
- `scripts/mainnet/deploy-gate.mjs` and its test (person-run mainnet deploy, A1C-06).
- `scripts/a1/testnet-run.mjs` (read only; not run).

Goals: S1 (funds only to the signed payee within budget), S2 (refunds only to `refund_to`), S4 (decisions anchored, no lying receipt), S6 (no off-chain text changes a decision), and the storage rule Q17 (whoever creates gate state pays for it).

## Method
- Read `CLAUDE.md`, `docs/SECURITY.md` (sections 2, 3.1, 4, 6), `docs/audits/A1-contract.md` and `docs/audits/A1-payments.md` with their author responses, `docs/ARCHITECTURE_AND_PLAN.md` "Payment attribution after audit A1-payments" and "As built in M3", `docs/a1-testnet.md` and `docs/a1-testnet-results.json`. Every "Fixed" claim was treated as a claim to verify.
- Read `lib.rs` line by line. For each public method (`new`, `ft_on_transfer`, `register_mandate`, `stop`, `purchase`, `on_payout`, `refund`, `on_refund`, views) asked what a stranger, the registrant, a malicious buyer, an injected agent, a fake token, the token itself, 1Click's account and the guardian can do, in any order and between a transfer and its callback.
- Followed every token unit and every yoctoNEAR of deposit: in through `ft_on_transfer` and `register_mandate`, out through payouts, refunds, the registration surplus, refused registrations and `try_close`.
- Compared `kept_bytes` with the real storage left after close, measured on the mocked VM by flushing the whole contract state (`pc_a1r_kept_bytes_cover_everything_left_after_close_with_two_registrations`).
- Read every "Author adaptation" diff in the test files against the original assertion.
- Read the mainnet deploy script for wrong code or config, leftover keys, key leaks and unattended runs. Wrote an offline vitest for the script's checks.
- Rebuilt the release wasm (`make wasm-release`): 322,485 bytes, NEAR code hash `PgEuTpCVtCZ4xWEJ97Qa6wMYCqUspFd2VRVu2sNDGMj`, the hash `docs/a1-testnet.md` records for the testnet gate. The live testnet account was not queried.
- No network call to any NEAR network. No key was read, used or printed. `.secrets/` and environment secrets were not read. `scripts/a1/testnet-run.mjs` and the mainnet script were not run. `fixtures/attacks/` was not opened.
- No text in the files read asked the auditor to change security behaviour.

Exploit tests: `contracts/gate/tests/audit_a1r.rs` (mocked VM, public API only) and `scripts/mainnet/audit-a1r.test.mjs` (offline). Each `a1r_NN_*` / "A1R-NN …" test asserts the REQUIRED behaviour, so it **fails while its finding is open**. `pc_a1r_*` and "control: …" tests are positive controls and pass. No existing test, contract file or vector was changed.

## Tool results (at `84fc11a` plus the two audit files)
| Check | Result |
|---|---|
| `cargo test -p sampan-gate --offline` | Existing suites all pass: 84 unit, 2 attack fixtures, 11 audit A1, 11 audit A1-payments, 15 audit M3, 2 audit M4. `audit_a1r`: **4 fail by design** (A1R-01, 02, 04, 08), 5 controls pass |
| `pnpm exec vitest run scripts/a1 scripts/mainnet` | 22 pass; **1 fails by design** (A1R-06) |
| `PROPTEST_CASES=400 cargo test -p sampan-gate --release --lib invariants_hold` | Pass (400 cases, 30 s) |
| `make security` | Green: clippy, banned-pattern lint, `cargo audit` (292 crates, no advisories), `cargo deny` ok, `pnpm audit` no known vulnerabilities, gitleaks no leaks |
| `cargo clippy -p sampan-gate --tests -D warnings`, `rustfmt --check` on the new file | Clean |
| `make wasm-release` | Code hash `PgEuTpCV…MGMj`, equal to `docs/a1-testnet.md` |
| `make check` | Not run in full. It is red by design while the exploit tests above fail |

## Findings
| ID | Severity | Title | Location | Exploit test | Status |
|---|---|---|---|---|---|
| A1R-01 | High | **Anyone can block every new mandate for good, for about 1 NEAR, by naming the gate as `refund_to`.** `try_register` does not refuse `refund_to` = the gate account. NEP-141 refuses a transfer to the sender (the testnet run relies on this for payee = gate, `docs/a1-testnet.md` step F). The attacker registers `max_mandates` (10 on mainnet) one-hour mandates signed with their own key, with `refund_to` = the gate, and pays 1 base unit into each. After expiry every `refund` fails, `on_refund` puts the unit back as refund due, and `try_close` needs `refund_due == 0`. So the mandates never close and `open_mandates` stays at the cap. Every later registration is refused `mandate_cap`. The config is fixed, the account is locked and `stop()` cannot help. The same happens, without an attacker, to any mandate whose `refund_to` the token issuer blocks (**Assumption**: USDC on NEAR can block accounts, README trust statement). Cost on the mainnet config: 10 × 0.0985 NEAR of deposits (never returned) plus 10 × 0.000001 USDC and gas. This brings back A1C-01 (High) by another route. | `lib.rs:721-795` (no check on `refund_to`), `1097-1104` (close needs `refund_due == 0`), `756-758`, `633-656`, `1178-1190` | `a1r_01_unrefundable_mandates_cannot_hold_the_mandate_cap_for_good` | Open |
| A1R-02 | Medium | **A stranger can stop any direct checkout for 16 base units of USDC, and make the registrant pay for 16 receipts.** The relayer's `register_mandate` call (with the full signed mandate) and its `registered` event are public before the buyer pays. The stranger then sends `max_orders_per_mandate` payments of 1 base unit, each with an unsigned order at the exact price. Each payment puts 1 unit in escrow, so `fund` decides the order. R7 fails (escrow 1 < price) and the refusal is **anchored**: one receipt and one order slot each. The buyer's real 1Click payment then meets `order_cap`, is not decided and becomes refund due. The buyer gets USDC back on NEAR at `refund_to`, not the purchase. The 16 units go to the buyer, so the attack costs the stranger 0.000016 USDC plus 16 transactions of gas (**Assumption**: about 0.001 to 0.003 NEAR each). The registrant (the Sampan relayer) loses 16 × 336 bytes = 0.054 NEAR of its deposit per attacked mandate. The anchored receipts also show R5 passed for orders the buyer never made. It can be repeated on every checkout. | `lib.rs:865-883` (decided when `to_escrow > 0`, whatever its size), `920-936`, `996-1019` (anchored refusal) | `a1r_02_strangers_cannot_fill_a_direct_checkout_order_cap_for_pennies` | Open |
| A1R-03 | Medium | **The open-mandate and total-escrow caps can still be held for a day at a time, cheaply, and renewed.** Storage is now paid by deposits, but `max_mandates` stays small (10 on mainnet). Anyone can register 10 of their own 24-hour mandates with no payment at all. That locks 0.985 NEAR, which comes back in full at close because no receipt is stored. Every genuine registration is refused `mandate_cap` for that day. Renewing costs only gas, about 20 transactions a day (**Assumption** on gas prices). A variant fills `max_total_escrow` (50 USDC) with 5 own mandates, so every buyer payment goes to refund due instead of escrow. No funds are lost, since the relayer registers before the quote and refused payments become refund due. But the checkout stops for everyone. With A1R-01 the block becomes permanent. | `lib.rs:756-758`, `826-836`; mainnet config in `scripts/mainnet/deploy-gate.mjs:29-35` | none (config and design; see fix direction) | Open |
| A1R-04 | Low | **After a failed direct-checkout payout, the buyer's money waits for expiry.** `fund` moves all other escrow to refund due right after a release, before the callback. If the payout then fails, `restore` puts the price back into **escrow**, and `released` stays true. No later payment can buy (`already_paid`), and `refund` says `not_expired` until expiry (up to 24 hours on mainnet). An EVM buyer has no account that can call `purchase`. The money is safe, but it is held when A1P-02 says it should be payable now. Triggers: a payee the issuer froze, or no registration available. | `lib.rs:1011-1013`, `881-882`, `545`, `1165-1177`, `576-584` | `a1r_04_failed_direct_checkout_payout_is_payable_to_refund_to_at_once` | Open |
| A1R-05 | Low | **Refund due has no cap, so `max_total_escrow` no longer bounds what the gate holds.** Every payment to a registered mandate is kept: above the budget, after expiry, after a stop, or above the caps. It all becomes refund due, which no cap limits. Anyone, or a large mistaken 1Click delivery, can leave any amount in the gate until someone calls `refund`. A1-contract's reviewed config calls `max_total_escrow` "the most a contract bug can lose; disclosed in the README". That is no longer true. Arithmetic in `fund` also uses `saturating_add` on `funded`, `escrow`, `refund_due` and the totals instead of checked operations (`CLAUDE.md`). Overflow is not reachable with USDC's supply, but refund due is unbounded. | `lib.rs:838-846`, `887-895`; README "Trust and loss statements" | none (design and statement) | Open |
| A1R-06 | Low | **The deploy script's check of `registration_deposit` against USDC's storage minimum can never fail.** `main()` builds the config from `bounds.min` (`mainnetConfig({ registrationDeposit: bounds?.min })`) and `checkChain` then compares the config with the same `bounds.min`. If USDC's minimum changed, the script would deploy whatever it is (anything from 0.00125 to 0.1 NEAR passes `Config::validate`) into a config that can never change, without telling the person. A1-contract asked the script to stop on a mismatch. The script's own test passes a fixed config, so it does not show this. | `scripts/mainnet/deploy-gate.mjs:147-154`, `65-66` | `scripts/mainnet/audit-a1r.test.mjs` › "A1R-06 stops when USDC's storage minimum is not the reviewed 0.00125 NEAR" | Open |
| A1R-07 | Info | **`min_funding` is validated but never used.** `fund` takes any non-zero amount, and no minimum applies anywhere else. The reviewed config and the A1-contract readiness table still describe it as the cost of each squatted slot (1 USDC). This makes A1R-01 and A1R-02 cost 1 base unit instead of 1 USDC. | `lib.rs:118-119`, `143-146`, `800-838` | none | Open |
| A1R-08 | Info | **Init accepts `network: "mainnet"` on any account that does not end in `.testnet`, including implicit accounts.** The author response for A1C-09 says implicit accounts "end in neither suffix and are refused too". The code checks only the `.testnet` suffix. Replay is still bound by the gate account ID, and the deploy script requires a named `.near` account, so this is defence in depth only. | `lib.rs:406-410` | `a1r_08_init_refuses_mainnet_on_an_implicit_account` | Open |
| A1R-09 | Info | **The registrant is charged for a registration the token gave back.** When the payee or `refund_to` is already registered with the token by someone else, `storage_deposit` with `registration_only` refunds the deposit to the gate (**Assumption**: USDC behaves like near-contract-standards here). `settle` still counts the registration as used, so `try_close` keeps 0.00125 NEAR of the registrant's deposit that the gate did not spend. Two mandates paying the same new payee at once are both charged in the same way. The gate never loses; the registrant pays a little too much. | `lib.rs:1086-1092`, `1213-1229`, `1111-1120` | none | Open |
| A1R-10 | Info | **Two deploy-script reads fail open or rely on a typed key.** (a) `view_state` errors are caught as "no state" (`.catch(() => ({ values: [] }))`). The empty-code check on the same account limits this. (b) The key can only be typed into a hidden prompt. The script says "prefer a hardware wallet signer" but has no path for one. SECURITY.md 3.5 says mainnet keys ideally stay on a hardware wallet. Otherwise the script is sound (see "Deploy script" below). | `scripts/mainnet/deploy-gate.mjs:152`, `133`, `160` | none | Open |

### Notes and fix direction (not applied)
- **A1R-01:** do both of these.
  1. At registration, refuse a `refund_to` or `payee` equal to the gate account (`bad_refund_to`), and consider the token account too.
  2. Do not tie the slot count to a successful transfer. After expiry, free the slot (`open_mandates -= 1`) the first time the mandate is touched with no escrow and nothing pending, even if refund due remains. Keep the record (its storage is paid by the deposit) until refund due is paid. Then a frozen `refund_to` keeps only its own money waiting.
  A regression test should cover both the gate-as-`refund_to` case and a refund that fails for another reason.
- **A1R-02:** decide an order in a payment only when this payment alone covers the exact price (`to_escrow >= max_amount`). Otherwise, ignore the order (`order_ignored`) and keep the payment as refund due, with nothing anchored. Then each anchored receipt costs a stranger the full price, which goes to the buyer. Optionally anchor no refusal for an unsigned order at all. Run `a1r_02_*` unchanged as the regression test.
- **A1R-03:** storage is now paid by registrants, so `max_mandates` can be much larger, for example 1,000. That costs an attacker about 98.5 NEAR locked per day. Or charge a non-refundable fee per registration. Or accept in writing that `register_mandate` is open, and state the cost of blocking it. Keep `max_total_escrow` small and accept that a funded attacker can hold it for 24 hours (README).
- **A1R-04:** in `on_payout`, when an agentless mandate's payout fails, move the restored amount to refund due (or clear `released`), so the buyer can be paid back at once.
- **A1R-05:** state in the README that refund due is not capped and is paid only to `refund_to`. Optionally, cap refund due per mandate (for example at `max_escrow_per_mandate`) and return the rest to the sender. Use checked arithmetic in `fund` and `escrow_to_refund_due`, and refuse with `internal` on overflow.
- **A1R-06:** keep the reviewed deposit as a constant in `mainnetConfig` (0.00125 NEAR). Make `checkChain` compare it with the live `bounds.min`, and stop on any difference.
- **A1R-07:** remove `min_funding` from the config with a new contract version, or enforce it for the first escrow of a mandate. Correct the readiness table.
- **A1R-08:** require `network == "mainnet"` only when the account ends with `.near`, and refuse 64-hex implicit and `0x` accounts. Correct the author response.
- **A1R-09:** in `settle`, do not count a registration whose deposit was refunded. The gate can compare its balance, or call `storage_balance_of` first. Or accept and document it (it is at most 0.0025 NEAR per mandate).
- **A1R-10:** treat a failed `view_state` as a stop. Add a Ledger signer path, or document that the person types the key on an offline-reviewed machine and rotates nothing else on it.

## Author adaptations of earlier auditor tests, checked
| Test | Change | Verdict |
|---|---|---|
| Funding helpers in all files (`register_from_msg`) | Register the mandate from the message as `relayer.testnet` with the exact deposit, at `min(now, expiry - 1)`, before the payment. A failed registration is ignored | Keeps the intent. In `a1c_01*` the attacker's far-expiry mandates are now refused `lifetime_too_long` and the tests pass because of that, which is the A1C-01 fix. These tests no longer show what an attacker can hold within the lifetime; A1R-01 and A1R-03 cover that |
| `a1c_02_closed_attacker_mandate_costs_the_gate_no_near` | `near_cost == 0` became `near_cost <= kept` (kept = deposit − returned) | Equivalent intent under the new design: the gate's net cost is at most zero. Confirmed independently: kept equals the storage left exactly (2,232 bytes plus 2 registrations in `pc_a1r_kept_bytes…`) |
| `m3_05_init_rejects_caps_the_balance_cannot_cover` | No longer asserts that `new` refuses caps above the balance. Asserts that a registration without its deposit is refused and stores nothing | Changed intent, with reason. The gate no longer pays mandate storage, so the old check is moot. The new assertion covers Q17 |
| `m3_06_direct_checkout_unanchored_refusal_returns_the_payment` | "returned to sender" became "kept as refund due" | Follows the A1P-02 decision. It is not weaker: the money still never sits in escrow without an anchored decision |
| `pc_agent_mandate_rejects_order_in_message_and_strangers` | An order in a payment to an agent mandate is ignored and kept (0 returned), not bounced; a check was added that no receipt exists | Follows A1P-02. Strangers are still `not_authorised` |
| `a1p_04_refund_after_direct_release_registers_refund_to` | The order is now exactly 25 and the surplus comes from a delivery of 30 | Keeps the intent (the refund of a remainder registers `refund_to`) |
| `pc_wrong_network_or_gate_delivery_returned_without_state` | R2 reasons asserted at registration; the payment then gets `unknown_mandate` and is returned in full | Keeps the intent. The `funding_refused` reasons moved, and nothing is stored |
| `audit-a1-payments.test.mjs` A1P-01 | The message with an order is `{"mandate_hash","order"}` instead of `{"signed_mandate","order"}`; the 1,024 limit is unchanged | Matches the redesign. The message without an order still uses `signed_mandate` (714 characters), which is fine |

No assertion was weakened beyond what the redesign requires.

## Prior findings re-verified (own verdict)
| ID | Author status | Auditor verdict |
|---|---|---|
| A1C-01 | Fixed | **Not closed.** `max_lifetime_ns` works (tests pass, 1 hour to 30 days validated, 24 hours in the deploy script). But a mandate that cannot be refunded never closes (A1R-01, permanent), and the slots can be held cheaply for a day at a time (A1R-03) |
| A1C-02 | Fixed | **Fixed.** On the mocked VM the storage left after close (receipts and both registered-account entries) plus 2 registrations equals exactly what the gate keeps. The deposit returned is never more than paid, and it is paid once (the record is removed first). Close cannot happen while a transfer or registration is in flight (`pending`). Refused registrations return the whole deposit and store nothing. Minor overcharge to the registrant: A1R-09 |
| A1C-03 | Fixed (one-way stop) | **Fixed.** Only the guardian can stop. The stop cannot be undone and moves no funds. After it, registrations and purchases are refused, payments are kept as refund due, and refunds work (`pc_a1r_stop_is_guardian_only…`). On testnet the guardian is the shared parent account; on mainnet it must be a separate hardware wallet (the script refuses the gate as guardian, but cannot check the key) |
| A1C-04 | Fixed | **Fixed in substance.** A stranger must pay the full price to the signed payee, and only once. Residuals: the stranger chooses the item among the signed items, the receipt shows R5 by the buyer's signature, and A1R-02 |
| A1C-05 | Fixed | **Fixed.** `refund_to` is registered after the payee used the first registration (`pc_a1r_kept_bytes…`) |
| A1C-06 | Script written | **Mostly done, needs a person's review.** Chain id, named `.near` gate, typed code hash equal to the build, empty account, one deploy-and-init transaction, `get_config` deep equality, code hash and zero totals after deploy, USDC registration, and a lock that stops unless the key list at `final` is empty. Refuses CI, Claude Code variables, keys in the environment and no TTY. Errors redact long base58 strings. Open: A1R-06, A1R-10 |
| A1C-07 | Done on testnet | **Accepted on the record.** `docs/a1-testnet-results.json` shows 32 of 32 steps passing, with release, failing release and closing refund at 87, 87 and 76 Tgas. Not re-run here (no network) |
| A1C-08 | Fixed in M6 | Not re-verified (checker scope) |
| A1C-09 | Fixed | **Partly.** `.testnet` mismatches are refused. Mainnet on an implicit or other non-`.near` account is accepted (A1R-08, Info) |
| A1C-10 | Fixed | **Fixed.** `PROPTEST_CASES` sets the depth, and `make fuzz` runs 5,000 cases. The model includes refund due and failing refunds |
| A1C-11 | Fixed (statement) | **Fixed**, plus A1R-05 (refund due is uncapped) and the A1R-01 consequence of a blocked `refund_to` should be added to the README |
| A1P-01 | Fixed | **Fixed.** The hash form fits (435 characters in the smallest case; testnet step C2). The auditor's TS test passes |
| A1P-02 | Fixed | **Fixed for registered mandates.** Late, over-budget, low-gas and post-stop payments become refund due. Residual: a payment to an unknown or closed mandate goes back to the sender (**Assumption** on what 1Click does with it). A1R-02 can still turn a checkout into refund due |
| A1P-03 | Fixed | **Fixed for the bounce; open as A1R-02** (order-cap griefing) |
| A1P-04 | Fixed | **Fixed** |
| A1P-05, A1P-06 | Fixed earlier | **Fixed.** Tests pass in `scripts/a1` |
| A1P-07, A1P-08 | Decided | Decisions recorded; enforcement is in M5 (not built) |
| A1P-09 | Open (M5) | Open |
| A1P-10 | Open (M5) | `pc_a1_evm_buyer_mandate_funds_pays_and_refunds` now runs the EVM path through registration, a release and a refund. A direct checkout with an ERC-191 mandate is still untested |

## Other items checked with no finding
- **S1 and S2 destinations:** the only token calls go to the configured token, for the stored payee (release) or `refund_to` (refund). Both come from a verified signed mandate. Refund due is paid only to `refund_to` (`pc_a1r_stop…`, existing `pc_a1_every_transfer…`).
- **Accounting:** `funded = spent + escrow + refunded + refund_due` holds through over-delivery, a refused order, a release, a failed refund and a late payment (`pc_a1r_accounting_invariant…`). Totals move with each mandate. A failed payout returns to escrow, and a failed refund returns to refund due.
- **State before promises:** every write in `decide`, `refund` and `try_close` comes before the promise. The registration surplus and refused deposits are returned with plain transfers to the predecessor.
- **Callbacks:** `#[private]` plus a predecessor check in the body. Exactly one result is read. `pending` is decremented once per callback. A callback that fails to restore emits `internal` and leaves the receipt `Pending`.
- **Token origin:** `ft_on_transfer` checks the predecessor before anything else. `sender_id` is never stored or logged.
- **Untrusted text:** events carry static reasons, grammar-checked hex and decimals, and the canonical core. `register_mandate` logs only the hash or a static reason.
- **No panics:** no `unwrap`, `expect` or `panic!` outside tests in `lib.rs`. Refusals return normally. `register_mandate` and `stop` refusals write no state.
- **Re-registration after close:** impossible, because close needs expiry and registration refuses an expired mandate.
- **Front-running a registration:** costs the stranger its own deposit, which comes back. The buyer's payment still buys (`pc_a1r_refused_or_front_run_registration_harms_nobody`).
- **1 yoctoNEAR per `ft_transfer`:** paid by the gate and not charged to anyone. This is negligible and bounded by the number of transfers per mandate.
- **Deploy script:** atomic deploy and `new` in one transaction (a failed `new` reverts the deploy); the build hash must equal the typed hash; the gate must be a fresh named `.near` account; the guardian must exist and differ from the gate; the lock deletes every listed key and re-reads at `final`; the key is typed hidden and never written. It cannot run unattended without a TTY. **Assumption:** a determined operator could fake a TTY; the script is a guard for a careful person, not a sandbox.
- **Testnet script:** testnet-only guards (`assertTestnet`), the key from the environment kept in memory, redacted logs, and the agent key deleted in `finally`. `docs/a1-testnet-state.json` holds only mandate hashes and account names.

## Residual risk
- **Assumptions:** NEP-141 refusing a self-transfer on USDC mainnet (the testnet mock token does); USDC's blocklist and the refund of an already-registered `storage_deposit`; gas prices used in the cost estimates; what 1Click does with a payment returned for an unknown or closed mandate.
- The registrant (the relayer) can lose its deposit to receipts written by the mandate's agent or by strangers (A1R-02). The loss is bounded by the deposit.
- The gate enforces what was signed, not what was meant (M4-08). A stranger who sees a signed multi-item agentless mandate can still choose which signed item is bought, with their own money.
- The out-of-scope items of SECURITY.md section 2 were not tested.

## Verdict
**Mainnet steps may not proceed at `84fc11a`.** A1R-01 (High) lets anyone block the gate for good for about 1 NEAR. With a locked account and no admin, that can only be fixed by a new gate on a new account.

Mainnet steps may proceed once all of the following hold:
1. A1R-01 is fixed, with `a1r_01_*` passing unchanged as the regression test.
2. A1R-02 is fixed, or accepted in writing by the security owner with a README note, before the first direct checkout.
3. The lead has decided A1R-03 (cap size or registration policy) and A1R-05 (README statement).
4. A1R-06 is fixed in the deploy script, and a person has reviewed the script.
5. The code hash in the deploy command is the one from the reviewed fix commit, not `PgEuTpCV…MGMj`.
6. The security owner has signed this report.

No Critical issue was found. No attacker considered here can send tokens anywhere except the signed payee within budget, or `refund_to`. No attacker can make the gate pay storage or registrations that nobody paid for.

## Author response (7 November 2026)
Fixed after `6d728c8`. The auditor's exploit tests now pass unchanged as regression tests: `a1r_01`, `a1r_02`, `a1r_04` and `a1r_08` in `contracts/gate/tests/audit_a1r.rs`, and "A1R-06 …" in `scripts/mainnet/audit-a1r.test.mjs`. The positive controls also pass. One of them, `pc_a1r_kept_bytes_…`, caught an 8-byte leak in the first version of the A1R-01 fix; that leak was fixed before this response.

| ID | Status | Fix or decision |
|---|---|---|
| A1R-01 | Fixed | The gate keeps the expiry of every registered mandate (`live_expiries`). Only mandates that have not expired count against `max_mandates`. Expired entries are dropped at each registration and close. A mandate whose refund can never succeed (`refund_to` = the gate, or an account the issuer blocked) keeps its own record and refund due. It no longer holds a slot. `get_totals` adds `live_mandates`, which the relayer uses. The list is at most `max_mandates` entries of 8 bytes. |
| A1R-02 | Fixed | An unsigned order inside a payment is anchored only when it is released. A refused one is an event (`refused`, reason `order_refused`), uses no order slot and writes no receipt, and the payment becomes refund due. Refusal receipts for a mandate now come only from its authenticated agent or buyer (`purchase`). `direct_checkout_refused_order_is_refundable_at_once` and two A1 auditor controls were changed to the new required behaviour; each change is marked in the file. |
| A1R-03 | **Decided by the lead, 7 Nov 2026: mainnet `max_mandates` = 100** (in `scripts/mainnet/deploy-gate.mjs`) | The caps are held only while the attacker's own capital and deposits are locked, and everything returns to the attacker within 24 hours. A blocked payment is kept for the buyer as refund due and is never bounced. Recommendation: raise mainnet `max_mandates` from 10 to 100. Mandate storage is paid by deposits, so the gate's balance does not grow with it, and holding all slots then locks about 9.85 NEAR a day. Keep `max_total_escrow` at 50 USDC as the bug-loss bound. Until the lead decides, the deploy script keeps 10. |
| A1R-04 | Fixed | After a failed direct-checkout payout, the restored amount becomes refund due, payable to `refund_to` at once, and the single purchase may be tried again with a new payment. The auditor's test passes. |
| A1R-05 | Fixed (arithmetic) and stated | `fund` uses checked arithmetic before any write; an overflow hands the payment back (`a1r_05_fund_overflow_is_handed_back_without_state`). Refund due is the buyers' own money, payable to them at any time. The README states that `max_total_escrow` bounds only escrow. |
| A1R-06 | Fixed | The config takes the reviewed 0.00125 NEAR, never the chain's value, and the script stops if USDC's minimum differs. The auditor's test passes. |
| A1R-07 | Accepted | `min_funding` is kept in the config for format stability but not enforced since A1: a small payment is kept for the buyer, not bounced. Documented here. |
| A1R-08 | Fixed | `mainnet` requires a `.near` account and `testnet` a `.testnet` account, so implicit accounts are refused for both. The auditor's test passes. The A1C-09 response is now accurate. |
| A1R-09 | Accepted | The gate never loses. The registrant pays at most 0.00125 NEAR per mandate more than needed. |
| A1R-10 | (a) Fixed, (b) accepted | (a) A failed `view_state` read stops the script. (b) The key is typed at a hidden prompt by the key holder; a hardware-wallet signer is not built. The person may instead sign the same two transactions with a hardware-wallet CLI, using the script's `plan` output. No regression test: this path needs a live RPC and runs only in person-run code. |

The state layout changed (`live_expiries`), so the testnet gate is redeployed and the A1 testnet run repeated with the new code hash.

## Sign-off
Security owner: Jan Hanken (in the project chat) · Date: 7 November 2026
Signed with conditions, all decided the same day: (1) A1R-03, mainnet `max_mandates` raised to 100; (2) A1R-11 accepted as a stated limit on S4; (3) Jan Hanken reviews `scripts/mainnet/deploy-gate.mjs` (`plan` mode) before it is run. Recorded by the author at the security owner's instruction; the audit itself was independent.

## Re-verification of the fixes (at 5afc545)
Date: 7 November 2026 · Same auditor session. I read `git diff 6d728c8 5afc545` (contract, tests, deploy script, relayer, README) and checked each fix against its finding. The author did not change `audit_a1r.rs` or `audit-a1r.test.mjs`.

Tool results at `5afc545` plus one new test:
- `cargo test -p sampan-gate --offline`: all pass (85 unit, 2, 11, 11, 15, 2, and `audit_a1r` 10 of 10). The exploit tests `a1r_01`, `a1r_02`, `a1r_04` and `a1r_08` now pass unchanged as regression tests.
- `pnpm exec vitest run scripts/a1 scripts/mainnet`: 23 of 23 pass, including "A1R-06 …".
- `make security`: green.
- `make wasm-release`: 324,220 bytes, code hash `2ZCcVoRjrCmLcdmHd2B8cnzFJEyT88ozz1AnWa3pVQkA`. This is the hash a reviewed deploy at this commit must match. `PgEuTpCV…MGMj` is no longer current.
- New control `a1r_11_live_expiries_stay_bounded_and_leave_no_storage` passes. It runs 4 rounds of 8 registrations and closes, checks the cap refuses a ninth live mandate, checks the storage returns exactly to its starting size, and checks that a stuck mandate frees its slot at expiry.

### Focus questions
1. **`live_expiries` cap.**
   - **Bypass:** not possible. A registration first drops expired entries, then refuses if `max_mandates` live entries remain, and only then pushes one. Every new entry is live, because registration refuses an expired mandate.
   - **Unbounded growth:** not possible. The length never exceeds `max_mandates`. Expired entries are dropped at each registration and close. The work per call is O(`max_mandates`) (10, or 100 if A1R-03 raises it). Checked by `a1r_11`.
   - **Blocking:** an entry lasts at most `max_lifetime_ns` (24 hours), so the permanent block of A1R-01 is gone. Holding all slots for a day is A1R-03, which is still open.
   - **Storage:** at most 8 bytes per live mandate in the root state, inside the 2,400-byte record margin that the registrant's deposit pays. Nothing is left after close (`a1r_11` and `pc_a1r_kept_bytes…`).
   - **Side effect:** `open_mandates` (`get_totals().mandates`) now counts stored records with no cap. Mandates that never close stay stored. Each one is paid by its own deposit, which the gate keeps, so the gate does not pay. **Residual (Info):** a mandate with `refund_to` = the gate still holds its own refund due and deposit for good. My fix direction (1), refusing `refund_to` = gate at registration, was not taken. That harms only whoever signed it, but the widget and relayer should refuse it.
2. **Unanchored refusals of orders inside a payment (A1R-02).** The fix works. A stranger can no longer use order slots or the registrant's deposit. It does narrow S4: a direct-checkout order that is refused (R6 to R9, or R7 after under-delivery) now leaves only a `refused` event with reason `order_refused`, the mandate hash and the order ID. It leaves no receipt core, no per-rule result and no stored anchor. The trade is sound, because a receipt for an unsigned order that anyone can send proves little. But the docs do not state it. `docs/ARCHITECTURE_AND_PLAN.md` ("Unanchored refusals", line 157) still lists only unknown mandate, R5, R4, order cap, no escrow and gas, and says R3 and R6 to R9 "can fail in an anchored receipt". This is new finding **A1R-11** below.
3. **Changed tests.**
   - `direct_checkout_refused_order_is_refundable_at_once` (`src/tests.rs`): the assertion of an anchored "refuse" receipt is replaced by "no receipt, a `refused` event with `order_refused`, no order slot used". The money assertions are unchanged (escrow 0, refund due 25, refundable at once). This is justified by A1R-02 and is not a weakening of the money properties. It does encode the S4 change in A1R-11.
   - `pc_refused_order_keeps_funds_for_refund_to_only` (`audit_a1_payments.rs`): the receipt assertion is replaced by "no receipt, some `refused` event". It is justified, but it is slightly looser than the unit test, because it does not check the reason or the mandate hash. The checks that matter (nothing to the payee, the refund goes only to `refund_to`) are unchanged.
   - `pc_failed_payout_restores_and_cannot_double_pay` (`audit_a1_payments.rs`): "escrow = 25" became "escrow + refund due = 25", and the totals likewise. This is justified by A1R-04. The replay still proves there is no double restore: on the second call `spent` is already 0, `restore` fails, and the agentless branch does not run, so the held amount stays 25, not 50. Not a weakening.

### Verdict per ID
| ID | Verdict at `5afc545` |
|---|---|
| A1R-01 | **Fixed.** An expired mandate never holds a slot. `a1r_01` and `a1r_11` pass. Residual (Info): stuck mandates are not refused at registration (see above) |
| A1R-02 | **Fixed**, with the S4 change recorded as A1R-11 |
| A1R-03 | **Open (lead decision).** The deploy script still sets `max_mandates: 10`. Raising it to 100, as the author recommends, makes holding every slot cost about 9.85 NEAR locked per day; `a1r_11` shows the list stays small |
| A1R-04 | **Fixed.** The restored amount becomes refund due and `released` is cleared. Checked for double pay: a new purchase needs new escrow, and a replayed callback cannot restore twice |
| A1R-05 | **Fixed** (checked arithmetic before any write; `a1r_05_fund_overflow…` passes) and stated in the README. `escrow_to_refund_due` still saturates. It only moves money within bounds that are already checked, so this is acceptable |
| A1R-06 | **Fixed.** The reviewed 0.00125 NEAR is a constant, and the script stops if USDC's minimum differs |
| A1R-07 | **Accepted** in writing by the author. The A1-contract readiness table still calls `min_funding` the cost of a slot; correct it in the README or the config notes |
| A1R-08 | **Fixed.** `mainnet` needs `.near` and `testnet` needs `.testnet`, so implicit accounts are refused |
| A1R-09 | **Accepted** (at most 0.0025 NEAR per mandate, paid by the registrant) |
| A1R-10 | (a) **Fixed**: a failed `view_state` read now stops the script. (b) **Accepted**: the key is typed at a hidden prompt; the security owner should confirm this against SECURITY.md 3.5 |

### New finding
| ID | Severity | Title | Location | Exploit test | Status |
|---|---|---|---|---|---|
| A1R-11 | Low | **A refused direct-checkout order no longer gets a receipt, and the docs still say it does.** After the A1R-02 fix, the buyer of a refused direct checkout (under-delivery, a wrong item or payee from the widget) gets only a `refused` event, with no receipt core for the checker to verify. Their money is safe: it is refund due, payable to `refund_to` at once. ARCHITECTURE "Unanchored refusals" and the S4 wording ("every decision … leaves a receipt anchored on-chain") do not mention this case. The checker and README must not claim a verifiable refusal receipt for direct checkout. | `lib.rs` `decide` (`order_refused`); `docs/ARCHITECTURE_AND_PLAN.md:157`; `docs/SECURITY.md` S4 | none (documentation) | Open |

Fix direction for A1R-11: add "an order inside a payment that the rules refuse" to the "Unanchored refusals" decision. Say there that the refusal is an attributable event and that the payment becomes refund due. State it in the README claim table (M8), and get the security owner's written acceptance of the S4 change.

### Updated verdict
**No Critical or High finding remains open at `5afc545`.** Funds still go only to the signed payee within budget, or to `refund_to`. The gate still pays for no storage or registration that nobody paid for.

Mainnet steps may proceed once all of the following hold:
1. The lead has decided A1R-03 (the `max_mandates` value in the deploy script).
2. A1R-11 is documented and accepted by the security owner.
3. The testnet gate is redeployed with code hash `2ZCcVoRj…pVQkA` (or the hash of the final reviewed commit) and the A1 testnet run is repeated, as the author response says.
4. A person has reviewed `scripts/mainnet/deploy-gate.mjs`.
5. The security owner has signed this report.

## Author response to the re-verification (7 November 2026)
- **A1R-11:** documented. The stated limit on S4 is now in SECURITY.md section 1 and ARCHITECTURE 3.4. It awaits the security owner's acceptance.
- **`refund_to` = the gate (Info):** the relayer refuses it, and also a payee equal to the gate (relayer test "refuses the gate itself …"). The widget always sets `refund_to` to the buyer's own account.
- **`pc_refused_order_keeps_funds_for_refund_to_only`:** now checks the event's reason (`order_refused`).
- **Testnet:** redeploy with code hash `2ZCcVoRjrCmLcdmHd2B8cnzFJEyT88ozz1AnWa3pVQkA`, then repeat the A1 run, after mandates A and C of the first run are closed.

