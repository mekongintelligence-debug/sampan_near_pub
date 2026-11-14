# Accounts: what we need and how to create them

Written 5 November 2026. Commands come from the NEAR docs and the near-cli-rs source; items marked **Assumption** must be checked against `near --help` on the installed version before use.

## Principle
- **Testnet only** in Claude Code sessions. One person creates **one** testnet parent account. Every other testnet account is created by a script from that parent, so the environment holds a single secret.
- **Mainnet accounts are created and held by a person**, never in a Claude Code session, CI or the repository (`CLAUDE.md`, `docs/SECURITY.md` 3.5).
- Keys never enter the repository. `.gitignore` and `scripts/secrets-scan.sh` block NEAR key files and `ed25519:` private keys (audit M0-01).

## Testnet accounts

| Account | Purpose | Created by | Keys |
|---|---|---|---|
| `<parent>.testnet` | Parent; pays for and owns the sub-accounts | A person, through the testnet faucet | Full-access key, stored as the environment secret |
| `gate.<parent>.testnet` | Gate contract (M3) | Script (M1/M3) | Parent's key, until the "lock keys" decision (Q16) |
| `token.<parent>.testnet` | Mock fungible token standing in for USDC (testnet has no 1Click) | Script (M3) | Parent's key |
| `buyer.<parent>.testnet` | Signs mandates, funds escrow | Script | Parent's key |
| `merchant.<parent>.testnet` | Payee | Script | Parent's key |
| `agent.<parent>.testnet` | The AI agent's account | Script | Parent's key plus a **function-call key** limited to `gate.<parent>.testnet`, method `purchase`, small gas allowance, created fresh by the M1/M4 script for each run |

Sub-accounts use the parent's public key as their full-access key, so one secret covers the whole testnet set. A name like `sampan-trust-01` is fine; avoid personal names.

### Step 1: a person creates the parent account (about 5 minutes)
1. Install near-cli-rs on your own computer (not in a cloud session): `cargo install --locked near-cli-rs`, or use `npx near-cli-rs`. The latest crate version seen on 5 Nov 2026 is 0.26.2 ([docs.rs](https://docs.rs/crate/near-cli-rs/latest/source/src/js_command_match/account/create.rs)).
2. Create a faucet-funded testnet account ([near-cli-rs source](https://docs.rs/crate/near-cli-rs/0.23.5/source/src/commands/account/create_account/mod.rs); [NEAR docs](https://docs.near.org/ko/build/smart-contracts/release/deploy)):
   ```bash
   near account create-account sponsor-by-faucet-service <parent>.testnet autogenerate-new-keypair save-to-legacy-keychain network-config testnet create
   ```
   The faucet pays for creation and pre-funds the account. It needs network access; testnet only.
   **Assumption:** `save-to-legacy-keychain` writes `~/.near-credentials/testnet/<parent>.testnet.json`; `save-to-keychain` uses the OS keychain instead.
3. Open that file and copy the `private_key` value (`ed25519:...`) **into the environment settings, not into chat or any file in the repository** (step 2).

### Step 2: a person adds the secret to the Claude Code environment
In the Claude Code app: the cloud environment menu in the session's title bar → **Edit** → **Network secrets** (or environment variables if that section is not offered). Add:

| Name | Value |
|---|---|
| `NEAR_TESTNET_ACCOUNT_ID` | `<parent>.testnet` |
| `NEAR_TESTNET_PRIVATE_KEY` | the `ed25519:...` private key |

A new session picks the values up. Scripts read only these two variable names and never print the key.

### Step 3: Claude Code creates the rest (M1, by script)
`scripts/testnet-accounts` (built in M1) will, from the parent key:
- create `gate`, `token`, `buyer`, `merchant` and `agent` sub-accounts with a small balance each (for example 3 NEAR from the parent);
- deploy the mock token from the official example ([near-examples/FT](https://github.com/near-examples/FT)), pinned to a commit, and initialise it (`new_default_meta`), then register storage for gate, buyer and merchant;
- add the agent's function-call key: receiver `gate.<parent>.testnet`, method `purchase`, allowance capped. Function-call keys can only call the named receiver and methods, and cannot attach deposits ([NEAR docs: access keys](https://docs.near.org/zh-CN/concepts/protocol/access-keys); [CLI `add-key`](https://docs.near.org/vi/tools/near-cli)). The allowance cannot be raised later; the key is deleted and recreated instead.

**Assumption to verify in M1:** the exact near-cli-rs sub-command for creating a sub-account funded by the parent (`account create-account fund-myself ...`). The script may use `near-api-js` or `near-api` (Rust) instead of the CLI, so it can read the key from the environment without writing a credentials file.

### If the testnet key leaks
Delete it from the parent and sub-accounts with the parent's other key or a new one, recreate the environment secret, and record it in `docs/audits/`. Testnet funds have no value, but the incident process should be practised.

## Mainnet accounts (M5, people only)

| Account | Purpose | Notes |
|---|---|---|
| `<gate>.near` (or a sub-account) | Mainnet gate contract | Deployed by a person after audit A1; escrow caps set (Q37) |
| Buyer wallet on another chain | The stranger's cross-chain purchase | Any EVM or other wallet supported by 1Click |
| Merchant account | Payee | Must be registered with the USDC token contract (storage deposit, Q17) |
| Prize account | Hackathon rules (Q4) | Can be the same as the merchant only if the team agrees |

- Create mainnet accounts in a wallet a person controls; prefer a hardware wallet for the account that deploys the gate. **Assumption:** wallet choice is the team's.
- Fund with team money only, in tiny amounts (`CLAUDE.md`, brief).
- Never paste a mainnet key into a Claude Code session, CI or the repository. Mainnet steps are scripts Claude Code writes and a person runs.

## Open questions this adds
53. ~~Who creates the testnet parent account?~~ **Decided 5 Nov 2026: Jan Hanken creates it and adds the environment secret.**
54. Who holds the mainnet keys, on what device (ties to Q25 and Q40)?
