# Sampan Trust checkout on NEAR

**A checkout that can prove every payment was what the buyer authorised.**

**The problem.** When a person or an AI agent pays a shop, the buyer's finance lead later has to answer one question: was this payment what the buyer actually agreed to? Today the answer is a screenshot, an email or a vendor's word.

**The reader.** This entry is built for the buyer's finance lead. They get a receipt file and open it in a static web page. With no wallet, no account and no server of ours, they see whether the payment matched what the buyer signed.

**NEAR's role.** The buyer pays from another chain through NEAR Intents (1Click; the checkout is built for USDC on Base, and its live path runs for the first time with the person-run mainnet purchase). A NEAR contract (the *gate*) holds the money and pays the shop only for an order inside the buyer's signed mandate. An AI agent buys with a NEAR function-call key that can call the gate and nothing else. Every release, and every refusal of an authenticated order by the rules R1 to R9, is anchored on NEAR, where anyone can check it (some refusals leave only an event; see the trust statements).

> Status: testnet works end to end. The mainnet deployment and the first mainnet purchase are scripts for a person to run (`scripts/mainnet/deploy-gate.mjs`, `scripts/mainnet-proof/`), after the security owner signs audit A1. Rows below say which is which.

---

## Try it (no wallet, no key, no money)
**Prerequisites:** Node 22.18 or newer (the scripts import TypeScript directly), pnpm 10 (`corepack enable`), and for the tests Rust (toolchain pinned in `rust-toolchain.toml`, with the `wasm32-unknown-unknown` target) and a Playwright Chromium (`pnpm exec playwright install chromium`).
```bash
pnpm install
pnpm dry-run
```
**You see (about 2 minutes):**
1. A *dry* 1Click quote for a 1 USDC purchase. It has no deposit address, so nothing can be paid. Until the mainnet gate is deployed, the dry quote names the existing account `near` as recipient, because 1Click refuses accounts that do not exist.
2. Every example receipt in `examples/` checked against NEAR's public archival RPC (a regular RPC forgets transactions after about a day): each check by name, and the checker's verdict. On testnet the verdict is "Cannot verify". All checks pass except two, which cannot be verified because the test gate keeps an owner key: "Nobody can change the gate" and "The gate ran reviewed code when it decided". These two can pass only for a receipt from the locked mainnet gate; no mainnet receipt exists yet.

Check a receipt in the browser:
```bash
node apps/checker/build.mjs
```
Then open `apps/checker/dist/index.html` from disk and load `examples/testnet/agent-refusal.json`. The check starts by itself and takes about 30 seconds. **You see:** every check listed: signature, order, gate, anchor, decision transaction and block. The page also names the rule the order broke: the payee was not the one signed. All checks pass except the same two as above, which read "Cannot verify" because the test gate keeps an owner key. The overall verdict is therefore "Cannot verify". For receipts older than about a day, choose the archival RPC (`archival-rpc.testnet.near.org`) in the page, because a regular RPC no longer has the transactions. A refusal receipt from the locked mainnet gate is designed to read "Verified: the gate refused this order, and no money moved." (no mainnet receipt exists yet). The page can contact only NEAR RPC hosts (strict CSP).

## How it works
1. **The buyer signs a mandate**: payee, item list, price or budget, asset, expiry, refund account and, optionally, an agent. It is signed with their wallet (NEAR NEP-413 or EVM ERC-191). Format: `docs/FORMATS.md`.
2. **The mandate is registered on the gate**, with a refundable deposit that pays its storage.
3. **The payment arrives** through 1Click (from Base, for example) or as a direct USDC transfer. The gate holds it.
4. **An order is decided by rules R1 to R9 in the contract**: signature, network and gate, expiry, replay, caller, asset, amount, payee and item. A model never decides. A release pays the signed payee; a refusal moves nothing.
5. **A receipt is anchored**: the gate emits the decision as an event and stores its hash. Any receipt can be rebuilt from chain data (`packages/receipt/src/pack.ts`) and checked by anyone (`apps/checker`).

The receipt's proof is the gate's transaction event and stored hash, read from NEAR. There is no separate signature by the contract and no key of ours.

## Claim table
| Claim | Where | Command | Expected | Evidence |
|---|---|---|---|---|
| The gate pays only the signed payee, within budget, for a listed item | `contracts/gate/src/lib.rs` | `cargo test -p sampan-gate` | all pass | [release](https://testnet.nearblocks.io/txns/9Vrpx1yrLNcXKcKZjtubxHj9pffYSUSH1rVNtp2Bc2QY), [swapped payee refused](https://testnet.nearblocks.io/txns/63cvtNUF2RasgvqgrfaBJcymEqUxsVjnp6SDSdwKc1wq) (`docs/m3-testnet.md`) |
| An agent's key can call `purchase` and nothing else | NEAR function-call key | `pnpm demo:direct` (testnet, needs the testnet key) | 9 of 9 other actions refused by the protocol; the allowed purchase works | `docs/m4-testnet.md`. These refusals happen before execution, so they leave no transaction to look up. |
| Prompt-injected agents are refused | `fixtures/attacks/agent-demo/`, `contracts/gate/tests/attack_fixtures.rs` | `cargo test -p sampan-gate --test attack_fixtures -- --nocapture` | the line "attacks refused: 6/6; known misses released: 2/2; controls released: 3/3; false positives: 0" | testnet transactions per attack in `docs/m4-testnet.md`. The test feeds the labelled orders to the contract; no model runs in it. |
| A refusal leaves a receipt as well as a release | gate events | `pnpm dry-run` | each receipt's checks listed; all pass but the two expected testnet unknowns | `examples/testnet/` |
| A stranger verifies a receipt with no wallet and no server of ours | `apps/checker` | `pnpm exec vitest run apps/checker/src/page.test.ts apps/checker/src/audit-m6-page.test.ts` | tamper and XSS tests red, valid green, only RPC hosts contacted (recorded RPC answers) | `docs/checker-release.png`, `docs/checker-refuse.png` |
| A person pays cross-chain through NEAR Intents | `packages/payments`, `apps/checkout-widget` | `pnpm dry-run` | dry quote: exactly the price delivered to the recipient | mainnet purchase: **pending, person-run** |
| Receipts are rebuilt from chain data alone | `packages/receipt/src/pack.ts` | `pnpm e2e` (testnet, needs the testnet key) | all 12 outcomes as expected (7 Nov 2026) | `docs/m7-e2e-results.json`; the three receipts in `examples/testnet/` were packed this way |
| Callbacks finish at the smallest gas the gate accepts | gate callbacks | `node scripts/a1/testnet-run.mjs` (testnet, needs the testnet key) | release 87 Tgas, release with a failing payout 87 Tgas, refund 76 Tgas | [release](https://testnet.nearblocks.io/txns/FUkTfGqA2pqYKkyQ7mm3vvhihKeVkSQoyJuKJm7Qj1o7), [failing payout](https://testnet.nearblocks.io/txns/4CRcTMGUDZpewuFTCFoCj84G3xHxR3RXUwW5LRHWkcpV), [refund](https://testnet.nearblocks.io/txns/548T3GoSwnUfqjzEC3BzbmxCC7BCp4nQpg6g3XBcPw7K) (`docs/a1-testnet.md`) |

## Built, stubbed, planned
- **Built and tested on testnet:**
  - the gate contract;
  - mandate and receipt formats (Rust and TypeScript, shared test vectors);
  - the agent demo with labelled attacks;
  - the payments client, relayer, checkout widget and test shop;
  - the receipt packer and the static checker.
- **Written, not yet run by a person:** the mainnet deploy, lock and first purchase scripts.
- **Planned after the hackathon:** an isolated checkout frame (see the trust statements); verifying 1Click's quote signature.

## The stated limit
The gate enforces what the buyer signed, not what they meant. If a buyer is misled into signing a bad mandate, for example the wrong payee, the gate pays that payee. Injections that stay inside the signed mandate are released by design: in the attack suite, a surcharge within budget and a swap to another approved item (2 of 2 "known misses", `docs/m4-testnet.md`).

## Trust and loss statements
- Tokens sent to the gate with a plain `ft_transfer` (no message) are never credited and cannot be recovered: the mainnet gate has no keys. The same holds for NEAR sent to it.
- The token contract is fully trusted. Its issuer can pause or block accounts, which would hold payouts and refunds until the issuer acts.
- A named guardian can stop the gate once, for good. After a stop, refunds keep working; the stop cannot move funds.
- The checkout widget runs inside the merchant's page. A script on that page (a compromised tag or dependency) can change what the widget shows, including the deposit address; the widget cannot detect this (audit M5-02). Check that a receipt exists for your mandate. Live widget payments stay on testnet until an isolated checkout frame exists.
- `max_total_escrow` bounds the money waiting for a purchase. Money owed back to buyers ("refund due") is not capped; anyone can trigger its refund at any time, and it goes only to each mandate's `refund_to`.
- Some refusals leave only an event, not an anchored receipt, so that nobody can fill the gate's storage with them: a refused order sent inside a payment (audit A1R-11; the payment is owed back to the buyer at once), and, for any caller, a repeated order ID, an unfunded mandate (no escrow), the order cap (16 orders per mandate), too little gas, a malformed order, and any order after the gate is stopped. Refusals by the rules R1 to R9 (payee, item, amount, expiry and so on) of an authenticated order are always anchored (audit A2-02).
- Anyone can hold all of the gate's open-mandate slots, or its total-escrow cap, for up to 24 hours, using their own refundable deposits and money. New checkouts are then refused until those mandates expire; no money is lost, and a blocked payment is kept for the buyer as refund due. The mainnet gate allows 100 open mandates, so holding all slots locks about 9.85 NEAR a day (audit A1R-03, accepted).
- The checker trusts the NEAR RPC it asks. Use a second, independent RPC in the page to cross-check.
- The test gate keeps an owner key, so on testnet the checker shows "Cannot verify" for "Nobody can change the gate". The mainnet gate is to be locked after deploy (no keys), by the person-run runbook (`docs/mainnet-runbook.md`).

## Security
Every milestone went through a threat review, abuse and edge-case tests, a self-review and an audit by a fresh Claude Code session with no part in writing the code, with a regression test for each finding (`docs/audits/`, `docs/SECURITY.md`). The security owner's sign-off is recorded at the end of each report; so far A1-contract, A1-payments and A1R are signed. A final audit (A2) runs before publishing.

## Develop
`scripts/setup-env.sh` installs the pinned tools and sets this checkout's git hooks (`core.hooksPath`); it runs `corepack enable`, which affects the whole machine.
```bash
scripts/setup-env.sh
make check
make security
```
User guide (buyers, shops, agent operators, anyone checking a receipt): `docs/USER-GUIDE.md` · Formats: `docs/FORMATS.md` · Security: `docs/SECURITY.md` · Audits: `docs/audits/` · Disclosures: `HACKATHON.md`
