# Mainnet runbook (person-run)

Step-by-step checklist with every command: `docs/mainnet-steps.md`. For Jan Hanken, who runs every step below (decisions of 7 Nov 2026; `docs/SECURITY.md` Q40). Claude Code never runs these steps and never sees a key. Each step stops on the first problem. Take your time; nothing here is urgent once started, and every check is read-only except the steps marked **sends**.

**Before you start:** audits A1-contract, A1-payments and A1R are signed (done, 7 Nov). The reviewed code hash is `2ZCcVoRjrCmLcdmHd2B8cnzFJEyT88ozz1AnWa3pVQkA`. It must still match the merged commit: if the gate code changes, a new review gives a new hash.

**Budget:** about 6.5 NEAR (gate 5.5, relayer 0.5, agent 0.5) plus about 3 USDC. Almost all of it stays on our own accounts.

## 0. Accounts (in your wallet)
| Account | Holds | Key |
|---|---|---|
| `gate.<team>.near` | 5.5 NEAR | your hardware wallet; deleted at the lock |
| guardian, e.g. `guardian.<second member>.near` | a little NEAR for gas | the second member's hardware wallet, never yours |
| `relayer.<team>.near` | 0.5 NEAR | its own software key, on the machine that runs the relayer |
| `agent.<team>.near` | 0.5 NEAR | its own key, held offline by a person |
| buyer | 2 to 3 USDC on Base, and a NEAR `0x…` implicit account (step 6) | the buyer's EVM wallet |

No key is shared between two accounts.

## 1. Build and compare the code (read-only)
```bash
git checkout main && git pull
make wasm-release
```
The deploy script computes the build's hash and stops if it is not the reviewed hash.

## 2. Review the plan (read-only; this is your review of the deploy script)
```bash
node scripts/mainnet/deploy-gate.mjs plan --gate gate.<team>.near --guardian <guardian>.near --code-hash 2ZCcVoRjrCmLcdmHd2B8cnzFJEyT88ozz1AnWa3pVQkA
```
Check what it prints:
- the chain is mainnet;
- the gate account exists, with no contract and no state, and holds at least 5 NEAR;
- the token is native USDC with 6 decimals;
- the config: caps 1, 10 and 50 USDC, 100 mandates, 16 orders, 24-hour lifetime, and your guardian.

Read `scripts/mainnet/deploy-gate.mjs` alongside it; the checks are near the top of the file.

## 3. Deploy and initialise in ONE transaction (**sends**)
With your hardware wallet, send one transaction from the gate account with exactly the two actions the plan printed: DeployContract (`target/wasm32-unknown-unknown/release/sampan_gate.wasm`) and FunctionCall `new` with the printed args, 30 Tgas, no deposit. **Assumption:** near-cli-rs (`near` in interactive mode, "contract → deploy … with init call", "sign with Ledger") does this; check its prompts against the plan before confirming.

(Without a hardware wallet, `deploy` in the same script does the same and asks for the key at a hidden prompt.)

## 4. Register the gate with USDC (**sends**, 0.00125 NEAR)
From any of your accounts, call `storage_deposit` on `17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1` with `{"account_id": "gate.<team>.near", "registration_only": true}` and an attached deposit of exactly 0.00125 NEAR. The `deploy` command does this itself.

## 5. Verify (read-only)
```bash
node scripts/mainnet/deploy-gate.mjs verify --gate gate.<team>.near --guardian <guardian>.near --code-hash 2ZCcVoRjrCmLcdmHd2B8cnzFJEyT88ozz1AnWa3pVQkA
```
Expect "Verified: reviewed code, intended config, registered with USDC. NOT locked yet". Run the smoke test (step 6) before locking, because after the lock nothing can be changed.

`verify` also writes `examples/mainnet-gate.json` (gate account, code hash, guardian, whether locked), which the purchase scripts read. Write it first on every path, including the hardware-wallet path (audit M8-11).

## 6. First purchase (smoke test, **sends**, at most 2 USDC)
1. The buyer's NEAR refund account is their own `0x…` implicit account. If it does not exist yet, send it a little NEAR first; the script checks it.
2. Prepare the mandate and sign it with the buyer's EVM wallet:
   ```bash
   node scripts/mainnet-proof/proof.mjs prepare --buyer 0x<EIP-55 address> --payee <shop>.near --item report-002 --price 1
   ```
   Sign exactly the printed text (personal_sign).
3. Register it with the relayer account, which pays the refundable deposit:
   ```bash
   node scripts/mainnet-proof/proof.mjs register --signature 0x<signature> --registrant relayer.<team>.near
   ```
4. Get the dry quote, then the live quote. The script checks every field, then asks you to type a confirmation phrase before it shows the deposit address:
   ```bash
   node scripts/mainnet-proof/proof.mjs quote
   ```
5. Pay exactly the shown amount from the buyer's wallet on Base before the deadline. Then follow it to the end:
   ```bash
   node scripts/mainnet-proof/proof.mjs status
   ```
   It stops on anything other than a released, paid order with nothing owed back. If it stops, **do not buy again**: tell Claude Code what happened (A1P-02).

`scripts/mainnet-proof` checks that the gate is locked. For this smoke test before the lock, add `--before-lock yes` to each command; it prints a reminder to lock afterwards.

## 7. Lock (**sends**, cannot be undone)
With your hardware wallet, delete **every** access key of the gate account in one transaction. (Or run `node scripts/mainnet/deploy-gate.mjs lock …`, which asks for the key.) Then:
```bash
node scripts/mainnet/deploy-gate.mjs verify --gate gate.<team>.near --guardian <guardian>.near --code-hash 2ZCcVoRjrCmLcdmHd2B8cnzFJEyT88ozz1AnWa3pVQkA
```
Expect "Verified: … and locked (no keys)". `verify` updates `examples/mainnet-gate.json` (now `"locked": true`). Add the deploy and lock transaction hashes to it; the `deploy` and `lock` commands add them themselves.

## 7b. A release after the lock (**sends**, at most 2 USDC)
The smoke purchase in step 6 was decided while the gate still had its deploy key, so its receipt can never read "Verified" ("The gate ran reviewed code when it decided" stays unknown). Buy once more, now on the locked gate, without `--before-lock`:
```bash
node scripts/mainnet-proof/proof.mjs prepare --buyer 0x<EIP-55 address> --payee <shop>.near --item report-002 --price 1
node scripts/mainnet-proof/proof.mjs register --signature 0x<signature> --registrant relayer.<team>.near
node scripts/mainnet-proof/proof.mjs quote
node scripts/mainnet-proof/proof.mjs status
```
This receipt is the mainnet release example (audit M8-10).

## 8. After
- Tell Claude Code the gate account and the transactions from `examples/mainnet-proof/` (`record.json`, `refusal-mandate.json`). It adds the gate to the checker's known gates (`apps/checker/src/gates.ts`), packs the step 7b release and the refusal below into `examples/mainnet/` with `packages/receipt/src/pack.ts`, and checks them with `pnpm dry-run` ("Verified").
- **The refusal example** (`scripts/mainnet-proof/agent-refusal.mjs`, **sends**, 1 USDC refunded after expiry):
  1. In your wallet, add a function-call key to the agent account: receiver = the gate, method `purchase`, allowance 0.25 NEAR.
  2. Run `prepare --buyer 0x<EIP-55> --agent agent.<team>.near --payee <shop>.near`, then have the buyer sign the printed text.
  3. Run `register --signature 0x<sig> --registrant relayer.<team>.near`.
  4. Run `fund --funder <your USDC account>.near`. This sends 1 USDC; it is refunded to the buyer's NEAR account after expiry.
  5. Run `refuse --other <any other account>.near`. Expect "Refused and anchored (R8)".
  6. Delete the agent's function-call key.
- Delete the agent's function-call key when done. Keep the guardian's hardware wallet safe: it can only stop the gate.
