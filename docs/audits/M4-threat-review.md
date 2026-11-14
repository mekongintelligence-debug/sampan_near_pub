# M4 threat review (author, step 1 of the security gate)

Milestone: M4, agent key, attack and direct call. Date: 6 November 2026.

## Design summary
- **Agent account:** `agent.<parent>` (from M1). Its full-access key is the operator's (environment secret, used only by `scripts/m4/setup.mjs` and `scripts/m4/edge-cases.mjs`), never given to the agent process, which is started with that secret removed from its environment and refuses to run if it can see it. The agent process receives only a function-call key: receiver = `gate-m3.<parent>`, methods = `["purchase"]`, small allowance (finding from M1: spike sub-accounts all hold the parent key; M4 must not).
- **`scripts/m4/setup.mjs`:** adds the function-call key and funds the demo mandate; `--teardown` deletes every gate-limited function-call key on the agent account. The private key is written to `.secrets/agent-fc.key` (git-ignored, mode 0600) and never logged (redacted).
- **`apps/agent-demo`:** a scripted agent (no model). It reads a product page fixture from `fixtures/attacks/agent-demo/`, which carries an injection asking it to buy another item from another payee; the script follows the injection on purpose and submits that order with its function-call key. The gate refuses (R8/R9) with an anchored receipt. A second run (`demo:direct`) tries `ft_transfer` on the token directly with the same key and fails at the protocol level. A control run buys the right item and is released.
- **Labelled suite:** each fixture has a label (attack or control) and the expected gate decision; the demo prints attack and false-positive counts (expected: every attack refused, every control released).

## Goals touched
S1 (only the signed payee within budget), S3 (the agent key can reach nothing but `gate.purchase`), S4 (both refusals anchored and reproducible), S6 (no text from a page changes a decision).

## Threats and controls
| Threat | Control | Test |
|---|---|---|
| The agent process holds a full-access key | Separate operator key; the demo checks the access key list of the agent account before running and stops if the agent's own key is full access | `agent_key_is_function_call_only` (script check) |
| The function-call key reaches another method, another contract, a deposit, a transfer, a key change, account deletion | NEAR access-key rules (Gate 2, M1); re-checked for every action in SECURITY.md section 6 (M4) with its stated protocol reason | `demo:direct` plus one step per forbidden action |
| The injected text changes what the gate accepts | Hard rules run in the contract only; the injection can make the agent submit a bad order, which the gate refuses | `demo:attack` anchored refusal |
| Attack strings leak into docs, README, logs or prompts of the coding session | Strings only in `fixtures/attacks/`, labelled; the demo prints fixture IDs, not their text; banned-pattern lint on docs | lint test |
| Gas allowance exhausted mid-demo; key removed mid-demo | Demo reports the protocol error and stops; nothing is half-written (refusals are atomic) | edge-case steps |
| Key material in logs or commits | `redact`, git-ignored key file, gitleaks with NEAR rules | secrets scan |
| Replay of the demo's orders | Fresh order IDs per run; replay refused (R4) | step in `demo:attack` |

## Edge cases (SECURITY.md section 6, M4) to test
Agent key calling `purchase` (allowed); any other gate method; the token's `ft_transfer`; `ft_transfer_call`; another contract; a transfer with attached deposit; adding a key; deleting the account (all must fail with their protocol reason). Gas allowance exhausted; key removed mid-demo. Every attack fixture refused and every control released (false-positive count published).

## Results (6 Nov 2026)
Testnet evidence: `docs/m4-testnet.md`. Attacks refused 6/6 with exactly the expected rules failing; controls released 3/3; false positives 0. Every forbidden action failed for its protocol reason. Allowance exhausted and key removal mid-demo behave as expected. Found on testnet: **M4-01** (the order cap counts refusals; sized to 16 on testnet, mainnet value for the lead) and the allowance sizing observation (0.1 NEAR refused, 0.2 to 0.25 NEAR accepted for a 150 Tgas purchase; the mechanism is an **Assumption**).

## Self-review (author, step 4: `/code-review high`, 6 Nov 2026)
| ID | Finding | Outcome | Test |
|---|---|---|---|
| M4-CR1 | `probe` mode acted without checking that its key is function-call only | Fixed: checked unless the key was removed | edge cases on testnet |
| M4-CR2 | A key without an allowance limit passed the safety check | Fixed | `agent-demo.test.ts` "accepts only a function-call key" |
| M4-CR3 | The secret check was a denylist of two names. On this cloud machine the agent would have inherited GitHub, cloud and deploy tokens | Fixed: the agent starts from an allow-listed environment (`scripts/m4/agent-env.mjs`) and itself refuses any credential-like variable name | `scripts/m4/agent-env.test.mjs`, `agent-demo.test.ts` |
| M4-CR4 | `docs/m3-testnet.md` still stated the old caps after the reset | Fixed: note added | n/a |
| M4-CR5 | Unverified allowance mechanics stated as fact | Fixed: marked **Assumption** | n/a |
| M4-CR6 | Edge-case keys stayed on chain if a step threw | Fixed: deleted in `finally` | n/a |
| M4-CR7 | Redaction re-implemented in the agent | Fixed: reuses `scripts/m1/safety.mjs` `redact` | n/a |
| M4-CR8 | Repeated or failed setup runs left orphaned live keys | Fixed: setup deletes earlier gate keys first; the key file is written only after funding | testnet re-run |
| M4-CR9 | Re-runs overwrite the results the docs were built from | Fixed: `scripts/m4/write-report.mjs` regenerates the page from the results | n/a |

## After the independent audit (docs/audits/M4.md)
The agent now runs as a separate OS user (`sampan-agent`) from an allow-listed environment (M4-02). Refusals count only when rejected before execution with the protocol's own error (M4-04). Releases count only when the payout completed (M4-05). Two labelled known misses show what the gate does not stop: injections inside the signed mandate (M4-08). Attack text is kept in `fixtures/attacks/` by the banned-pattern lint (M4-07).
