# Mainnet, step by step (for Jan)

A checklist from an empty laptop to a locked mainnet gate with two example receipts (one release, one refusal). Follow it top to bottom and tick each box. The short reference version is `docs/mainnet-runbook.md`; the decisions behind it are in `docs/SECURITY.md` (Q40).

**Ground rules**
- You run every step. Claude Code only explains and checks results; it never sees a key or a seed phrase. Never paste a key, seed phrase or Ledger PIN into a chat, a file or this repository.
- Steps marked **READ-ONLY** cannot spend anything. Steps marked **SENDS** spend real money: stop and re-read before you confirm.
- If anything prints `STOP:` or looks different from what this file says, stop and ask in the chat. Do not try to work around it.
- Budget: about 6.5 NEAR plus about 3 USDC. Almost all of it stays on our own accounts.
- Time: about 2 hours for parts A to E, plus waiting time for the purchases.
- Wherever this file says `<team>`, use the team's top-level NEAR account, `sampantrust.near` (decided 8 Nov; keep the company name out of every account name). Check it is free first: `near account view-account-summary sampantrust.near network-config mainnet now` (READ-ONLY).

Fill in as you go (account names only, never keys):

| Item | Value |
|---|---|
| Team top-level account | `sampantrust.near` (suggested; check it is free) |
| Gate account | `gate.sampantrust.near` |
| Guardian account (second member, own Ledger) | `guardian-<name>.near` |
| Relayer account | `relayer.sampantrust.near` |
| Agent account | `agent.sampantrust.near` |
| Shop (payee) account | `shop.sampantrust.near` (our own; the 1 USDC comes back to us) |
| Buyer EVM address (EIP-55, mixed case) | `0x________` |

---

## Part A: prepare the laptop (once, READ-ONLY)

- [ ] **A1. Hardware wallet.** A Ledger with the NEAR app installed (Ledger Live → My Ledger → install "NEAR"). Unlock it and open the NEAR app whenever a step says "sign with Ledger". The second member needs their own Ledger for the guardian account.
- [ ] **A2. Node.js 22.18 or newer.** Check with:
  ```bash
  node --version
  ```
- [ ] **A3. Rust and the wasm target.** Install from https://rustup.rs if missing. The repository pins the version itself.
- [ ] **A4. NEAR CLI (near-cli-rs).** Install it from https://github.com/near/near-cli-rs (the README lists one-line installers). Check with:
  ```bash
  near --version
  ```
  The commands below follow the near-cli-rs guide (`docs/GUIDE.en.md` in its repository, checked 8 Nov 2026). **Assumption:** the signing option `sign-with-ledger` is spelled this way in your version. If a command is not accepted, run `near` on its own: it asks the same questions one at a time. Always read the summary the CLI shows before you confirm.
- [ ] **A5. Get the code and the tools:**
  ```bash
  git clone https://github.com/<org>/sampan_near.git && cd sampan_near
  git checkout main && git pull
  scripts/setup-env.sh
  pnpm install
  ```
  `setup-env.sh` installs the pinned tools and sets this checkout's git hooks.
- [ ] **A6. Build the gate exactly as reviewed:**
  ```bash
  make wasm-release
  ```
  The deploy script checks the hash of this build itself in step C1. The reviewed hash is `2ZCcVoRjrCmLcdmHd2B8cnzFJEyT88ozz1AnWa3pVQkA`.

---

## Part B: create the accounts (SENDS small amounts)

You need a funded top-level account (`<team>`.near) in a wallet you control. Each sub-account below is created from it.

- [ ] **B1. Gate account, with its key on your Ledger** (SENDS 5.5 NEAR). Unlock the Ledger and open the NEAR app, then run:
  ```bash
  near account create-account fund-myself gate.sampantrust.near '5.5 NEAR' use-ledger sign-as sampantrust.near network-config mainnet sign-with-ledger send
  ```
  `use-ledger` puts the new account's key on your Ledger. `sign-with-ledger` signs with the top-level account's Ledger key; if that account's key lives in the OS keychain instead, use `sign-with-keychain`.

  Check it (READ-ONLY):
  ```bash
  near account view-account-summary gate.sampantrust.near network-config mainnet now
  ```
  Expect: about 5.5 NEAR, **no contract**, one full-access key (your Ledger's).
- [ ] **B2. Guardian account** (done by the second member, on **their** Ledger). It needs only a little NEAR for gas, for example 0.1 NEAR. It must not be your account or use your Ledger.
- [ ] **B3. Relayer account** (SENDS 0.5 NEAR). Its key is a normal key on this laptop:
  ```bash
  near account create-account fund-myself relayer.sampantrust.near '0.5 NEAR' autogenerate-new-keypair save-to-keychain sign-as sampantrust.near network-config mainnet sign-with-ledger send
  ```
  The purchase scripts ask for this key at a hidden prompt. Read it from your OS keychain; near-cli-rs stores it under the account name. If it leaks, at most these 0.5 NEAR of refundable deposits are at risk.
- [ ] **B4. Agent account** (SENDS 0.5 NEAR). Used only in part E:
  ```bash
  near account create-account fund-myself agent.sampantrust.near '0.5 NEAR' autogenerate-new-keypair save-to-keychain sign-as sampantrust.near network-config mainnet sign-with-ledger send
  ```
- [ ] **B5. Shop (payee) account** (SENDS 0.1 NEAR). It receives the test payments, so the money comes back to us:
  ```bash
  near account create-account fund-myself shop.sampantrust.near '0.1 NEAR' autogenerate-new-keypair save-to-keychain sign-as sampantrust.near network-config mainnet sign-with-ledger send
  ```
  Check it exists:
  ```bash
  near account view-account-summary shop.sampantrust.near network-config mainnet now
  ```

---

## Part C: deploy, register, verify (the gate goes live, not yet locked)

- [ ] **C1. Review the plan** (READ-ONLY; this is your review of the deploy script):
  ```bash
  node scripts/mainnet/deploy-gate.mjs plan --gate gate.<team>.near --guardian <guardian>.near --code-hash 2ZCcVoRjrCmLcdmHd2B8cnzFJEyT88ozz1AnWa3pVQkA
  ```
  It must print "Plan (all checks passed)". Check:
  - `network: "mainnet"`;
  - `token` = `17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1`;
  - `min_funding` 1000000, `max_escrow_per_mandate` 10000000, `max_total_escrow` 50000000;
  - `max_mandates` 100, `max_orders_per_mandate` 16, `max_lifetime_ns` 86400000000000;
  - `guardian` = the guardian account.

  It also prints the two actions for the Ledger deploy. If you have time, read `scripts/mainnet/deploy-gate.mjs`; the checks are near the top.
- [ ] **C2. Deploy and initialise in ONE transaction** (SENDS gas only). C1 printed the exact command as its last block ("Or with near-cli-rs, as ONE command"). It looks like this, with the full config filled in:
  ```bash
  near contract deploy gate.sampantrust.near use-file target/wasm32-unknown-unknown/release/sampan_gate.wasm with-init-call new json-args '{"config":{…as printed…}}' prepaid-gas '30 Tgas' attached-deposit '0 NEAR' network-config mainnet sign-with-ledger send
  ```
  Copy it from the C1 output; do not retype the JSON. Confirm on the Ledger after checking that the screen shows `gate.sampantrust.near`. If the CLI cannot do the deploy and the init call in one transaction, stop and ask.
- [ ] **C3. Register the gate with USDC** (SENDS 0.00125 NEAR):
  ```bash
  near contract call-function as-transaction 17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1 storage_deposit json-args '{"account_id":"gate.sampantrust.near","registration_only":true}' prepaid-gas '30 Tgas' attached-deposit '0.00125 NEAR' sign-as sampantrust.near network-config mainnet sign-with-ledger send
  ```
- [ ] **C4. Verify** (READ-ONLY):
  ```bash
  node scripts/mainnet/deploy-gate.mjs verify --gate gate.<team>.near --guardian <guardian>.near --code-hash 2ZCcVoRjrCmLcdmHd2B8cnzFJEyT88ozz1AnWa3pVQkA
  ```
  Expect "Verified: reviewed code, intended config, registered with USDC. NOT locked yet". This also writes `examples/mainnet-gate.json`, which the purchase scripts need.

---

## Part D: smoke purchase, lock, then the release example

**Buyer setup, once.** The buyer is an EVM wallet (for example MetaMask) holding 2 to 3 USDC on **Base**, plus a little ETH on Base for gas. Use its address in EIP-55 form, mixed case, exactly as the wallet shows it.

- [ ] **D1. The buyer's NEAR refund account.** This is the buyer's address in lower case, used as a NEAR account (for example `0xabc…`). The gate refunds there. If it does not exist yet, send it 0.05 NEAR from `<team>.near` (SENDS 0.05 NEAR); NEAR creates it on that transfer. **Assumption:** NEAR Ethereum-style implicit accounts behave as documented for refunds. The purchase script checks the account exists.

- [ ] **D2. Smoke purchase on the unlocked gate** (SENDS at most about 1.02 USDC). Add `--before-lock yes` to every command in this step.
  1. Prepare the mandate:
     ```bash
     node scripts/mainnet-proof/proof.mjs prepare --buyer 0x<EIP-55> --payee <shop>.near --item report-002 --price 1 --before-lock yes
     ```
     It prints the mandate text. In the buyer's wallet, sign **exactly** that text as a plain message (personal_sign; in MetaMask, "Sign message"), and copy the signature (0x…, 132 characters).
  2. Register it; the relayer pays the refundable deposit, and its key is asked at a hidden prompt:
     ```bash
     node scripts/mainnet-proof/proof.mjs register --signature 0x<signature> --registrant relayer.<team>.near --before-lock yes
     ```
  3. Get the quote. The script gets a dry quote, then a live one, and checks every field. It asks you to type a confirmation phrase and only then shows the deposit address:
     ```bash
     node scripts/mainnet-proof/proof.mjs quote --before-lock yes
     ```
  4. From the buyer's wallet, send **exactly** the shown USDC amount on Base to the shown deposit address, before the shown deadline.
  5. Follow it to the end (it polls for up to 3 hours):
     ```bash
     node scripts/mainnet-proof/proof.mjs status --before-lock yes
     ```
     Expect "Settled: released and paid out". If it prints `STOP`, **do not buy again**; send the output to the chat.

- [ ] **D3. Lock the gate** (SENDS gas only, **cannot be undone**). Afterwards nobody, including you, can change the gate. First list its keys (READ-ONLY):
  ```bash
  near account list-keys gate.sampantrust.near network-config mainnet now
  ```
  Then delete **every** key listed, in one transaction. Separate several keys with commas:
  ```bash
  near account delete-keys gate.sampantrust.near public-keys ed25519:<key from the list> network-config mainnet sign-with-ledger send
  ```
  Then verify (READ-ONLY), giving the hash of that delete-keys transaction. The CLI prints it; the checker needs its block as the gate's lock height:
  ```bash
  node scripts/mainnet/deploy-gate.mjs verify --gate gate.sampantrust.near --guardian <guardian>.near --code-hash 2ZCcVoRjrCmLcdmHd2B8cnzFJEyT88ozz1AnWa3pVQkA --lock-tx <delete-keys transaction hash>
  ```
  Expect "Verified: … and locked (no keys)".

- [ ] **D4. The release example on the locked gate** (SENDS at most about 1.02 USDC). Repeat D2 **without** `--before-lock`:
  1. `prepare` again, which overwrites the old mandate file (type `replace`), then sign the new text;
  2. `register`, `quote`, pay, `status`.

  This receipt is the one that can read "Verified".

---

## Part E: the refusal example (SENDS 1 USDC, refunded)

- [ ] **E1. Give the agent a limited key** (purchase on the gate only, 0.25 NEAR allowance):
  ```bash
  near account add-key agent.sampantrust.near grant-function-call-access --allowance '0.25 NEAR' --contract-account-id gate.sampantrust.near --function-names 'purchase' autogenerate-new-keypair save-to-keychain network-config mainnet sign-with-keychain send
  ```
  The refusal script asks for this new function-call key in E5. It refuses any key that can do more than call `purchase` on the gate.
- [ ] **E2. Agent mandate.** Run:
  ```bash
  node scripts/mainnet-proof/agent-refusal.mjs prepare --buyer 0x<EIP-55> --agent agent.<team>.near --payee <shop>.near
  ```
  Then sign the printed text with the buyer's wallet.
- [ ] **E3. Register it:**
  ```bash
  node scripts/mainnet-proof/agent-refusal.mjs register --signature 0x<signature> --registrant relayer.<team>.near
  ```
- [ ] **E4. Fund it with 1 USDC on NEAR**, from a NEAR account that holds USDC, for example yours (it asks you to type "fund 1 USDC"):
  ```bash
  node scripts/mainnet-proof/agent-refusal.mjs fund --funder <your account>.near
  ```
- [ ] **E5. The agent tries to pay someone else.** It asks for the agent's **function-call** key from E1:
  ```bash
  node scripts/mainnet-proof/agent-refusal.mjs refuse --other <any other account>.near
  ```
  Expect "Refused and anchored (R8)".
- [ ] **E6. Delete the agent's function-call key:**
  ```bash
  near account delete-keys agent.sampantrust.near public-keys ed25519:<the function-call key from E1> network-config mainnet sign-with-keychain send
  ```
- [ ] **E7. After the mandate expires** (about 2 hours later), anyone may return the 1 USDC to the buyer's NEAR account:
  ```bash
  node scripts/mainnet-proof/agent-refusal.mjs refund --caller <your account>.near
  ```

---

## Part F: send to the chat (no keys)

- [ ] **F1.** The contents of `examples/mainnet-gate.json`, `examples/mainnet-proof/record.json` and `examples/mainnet-proof/refusal-mandate.json`. These hold account names and transaction hashes only.
- [ ] **F2.** Anything that printed `STOP`, unchanged.

Claude Code then adds the gate to the checker's known gates with `node scripts/mainnet/add-known-gate.mjs`, which first reads mainnet to confirm the reviewed code, no keys and USDC. It then packs both receipts into `examples/mainnet/`, checks them ("Verified"), and updates the README.

## If something goes wrong
| What you see | What to do |
|---|---|
| `STOP: the local build … is not the reviewed code` | Do not deploy. Run `git status` and `make wasm-release` again; tell the chat the hash it prints. |
| `STOP: gate account already has a contract` | Do not continue. Tell the chat. |
| The payment status is REFUNDED or FAILED | Do not buy again. Send the status output; 1Click refunds to the buyer's Base address. |
| Money owed back ("refund due") | Run `node scripts/mainnet-proof/proof.mjs refund --caller <your account>.near` (D2/D4) or the refusal script's `refund` (E7). It pays only the buyer's NEAR account; escrow becomes refundable after expiry. |
| A real problem after the lock | The guardian can stop the gate for good. Refunds keep working; ask in the chat first. |
