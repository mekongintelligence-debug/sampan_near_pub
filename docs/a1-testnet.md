# A1 fixes on testnet (7 November 2026)

The redesigned gate (audits A1-contract and A1-payments, author responses) runs on `gate-m3.sampan-trust-01.testnet`. Run with `scripts/a1/testnet-run.mjs`; results in `docs/a1-testnet-results.json`. Test token only, no real money.

- **Code:** `2ZCcVoRjrCmLcdmHd2B8cnzFJEyT88ozz1AnWa3pVQkA`, the build after the A1R fixes, deployed at about 08:52 UTC. The first run (07:40 UTC, code `PgEuTpCVtCZ4xWEJ97Qa6wMYCqUspFd2VRVu2sNDGMj`, before A1R) also passed every step; its table is in git history (commit `84fc11a`). The tables below are from the repeat run. The script stops unless the deployed code equals the local build.
- **Reset:** the earlier state (3 expired M4 mandates, 1.6 test tokens) was wiped with `scripts/m3/reset-testnet-gate.mjs` before the deploy, because the state layout changed. The test tokens stay in the gate's token balance, credited to no mandate. Receipts from M3 and M4 remain verifiable from their transactions; the checker keeps the M3 code hash for them.
- **Config:** as in M3/M4, plus `max_lifetime_ns` 24 hours and `guardian` = the parent account. **Testnet only:** on mainnet the guardian is a named person's hardware wallet, never the deploy key. `stop()` was not called on testnet (it cannot be undone); it is covered by unit tests.
- **Relayer:** the `merchant` account plays the Sampan relayer.

## A1C-07: callbacks at minimum gas, on a real runtime
The script stepped the prepaid gas up 1 Tgas at a time. Every call below the minimum was refused with `insufficient_gas` before any state was written.

| Call | Accepted from | Callback result |
|---|---|---|
| `purchase`, release (the gate also asked to register the payee with the token; the token answered that it was already registered) | 87 Tgas | payout `Done`, shop paid 2 tokens, nothing pending |
| `purchase`, release whose transfer fails (payee = the gate; NEP-141 refuses a transfer to the sender) | 87 Tgas | payout `Failed`, escrow and budget restored |
| `refund` after expiry, closing the mandate | 76 Tgas | buyer paid 0.5 tokens, mandate closed, registrant got 0.09514 of its 0.0985 NEAR deposit back |

## All steps (repeat run on the A1R build)
| Step | Result | Transaction |
|---|---|---|
| init gate (private: only the gate account may) | pass | [tx](https://testnet.nearblocks.io/txns/5djvfygqQhsxkNkvARyR3dJxBGpTMwFfcYaHfnDG3fLf) |
| add agent function-call key (gate.purchase only) | pass | [tx](https://testnet.nearblocks.io/txns/4Yi9TxzgpvFzjTHA3w2LiKzBwd57qGuCjQycGEVzLXUa) |
| R1. lifetime over 24 hours: refused (lifetime_too_long), nothing stored | pass | [tx](https://testnet.nearblocks.io/txns/2d8EcN6KQCXjXNnE9yrkWW13yTcm3bn5jiN2fqRCGxSE) |
| R2. mandate for mainnet (R2): refused (wrong_network) | pass | [tx](https://testnet.nearblocks.io/txns/DQNyd6LBoxaY21JLdawVPdFhCGMnNzGwLzAsapYt1SnB) |
| R3. tampered mandate (R1): refused (bad_signature or invalid) | pass | [tx](https://testnet.nearblocks.io/txns/7FniVNP1dyQsMmyAcWFRTfHqZWSa5H97AfX1qwmFNVKA) |
| R4. deposit below the reservation: refused (deposit_too_small) | pass | [tx](https://testnet.nearblocks.io/txns/GTHNGd76ay2i5oQB5dBDmYM4JyM7ZLqXZYuA7TiKndti) |
| R5. refused registrations returned their deposits (relayer paid gas only) | pass |  |
| R6. not the guardian: stop() is refused (not_guardian) | pass | [tx](https://testnet.nearblocks.io/txns/2HbMAhCQp46rAqyiha7iPHR9hPRjgKYzBPALyX37KTNV) |
| A1. relayer registers mandate A with the deposit (surplus returned) | pass | [tx](https://testnet.nearblocks.io/txns/DpbWZK7qxypiw2nvKYkEF1oySmFAjNcrYiaPoLvGLcV7) |
| A2. buyer pays 5 tokens naming A by hash (the 1Click form) | pass | [tx](https://testnet.nearblocks.io/txns/HVvwQE3XkoPjExs5LccMbNhWpgZkwjgHfmVwiZZhJGqg) |
| A3. a payment naming an unknown mandate is handed back in full (used 0) | pass | [tx](https://testnet.nearblocks.io/txns/6y33BJh3MUKEk6phJ4wYecqZXEfzD4c8BJycgBPyj8yZ) |
| A4. A1C-07: release accepted at the minimum gas | pass |  |
| A5. A1C-07: the callback ran at minimum gas: payout Done, shop paid 2, nothing pending | pass |  |
| A6. receipt event re-parses with the TS checker code and equals the anchor | pass |  |
| F1. buyer registers mandate F itself (payee: the gate) | pass | [tx](https://testnet.nearblocks.io/txns/7uaNXMRMHYmNfucnXFAPNCMEqk5w9wny5urfpgBsEjAZ) |
| F2. buyer pays 0.5 tokens with the signed mandate in the message | pass | [tx](https://testnet.nearblocks.io/txns/4VSZAtE3qCQwjMemF6FL8DAQaRYv2Q5vBerFe7x7Mk3b) |
| F3. A1C-07: release with a failing payout accepted at the minimum gas | pass |  |
| F4. A1C-07: callback at minimum gas marked the payout Failed and restored the budget | pass |  |
| C1. relayer registers the agentless mandate C | pass | [tx](https://testnet.nearblocks.io/txns/ERSmXoobtB4zmV6xuDQUQjPCMCYNRdtevZ8EfbNDPWLe) |
| C2. the payment message fits 1Click's 1,024-character limit (A1P-01) | pass |  |
| C3. an order below the exact price is not decided; the payment becomes refund due | pass | [tx](https://testnet.nearblocks.io/txns/BmRa2hXkyq8ttz86qvqVPKy65MJiQgndahysaZ12cjsS) |
| C4. over-delivery of 1.2 for the exact price 1: released, 0.2 more refund due | pass | [tx](https://testnet.nearblocks.io/txns/2iybbbkP323XnSU5qdT2x6CBR6tqgfwCLimARnFpLuWC) |
| C5. shop received exactly 1 token | pass |  |
| C6. a second exact-price order in a later payment is not paid (already_paid) | pass | [tx](https://testnet.nearblocks.io/txns/4gBcPtpoT5g4eHcNFwub4z8QsyZjypwxHaGiyKaFQ7mC) |
| C7. before expiry anyone may refund the refund due to refund_to | pass | [tx](https://testnet.nearblocks.io/txns/94qKzXhTdCJMLyM5KEu6eS42D2iEuFtD5vhQZXA36KmF) |
| C8. buyer got 1.7 tokens back, never 1Click's account (A1P-02) | pass |  |
| F5. A1C-07: refund accepted at the minimum gas | pass |  |
| F6. buyer got the 0.5 tokens back | pass |  |
| F7. the callback at minimum gas closed F | pass |  |
| F8. the registrant (buyer) got its deposit back, less what F leaves behind | pass |  |
| Z. gate totals | pass |  |
| delete agent function-call key | pass | [tx](https://testnet.nearblocks.io/txns/6snjQYgGd7Gm5emynWZ861AdaCR3KiU6jitvX1spwmDu) |

The repeat run left mandates A and C open until they expired. `--close` at 09:59 UTC closed both (all checks pass):

| Mandate | Refund | Closed | Deposit back to the relayer |
|---|---|---|---|
| A (agent, 3 tokens left) | 3 tokens to `refund_to` ([tx](https://testnet.nearblocks.io/txns/6ULXbcsmHsaMv3E7F5eYg8LtH2BrbCVKJNDHzs4Qttoa)) | yes | 0.09311 of 0.0985 NEAR |
| C (direct checkout, nothing owed) | none needed; closed by the call ([tx](https://testnet.nearblocks.io/txns/8dDPBwXRTpEqevATsazVkUPJvMppeh9FGvMhzyMpL8z6)) | yes | 0.09315 of 0.0985 NEAR |

Gate totals afterwards: no escrow, no refund due, no mandates, no live mandates.

## Closing A and C of the first run (`--close`, 08:48 UTC, after expiry)
| Mandate | Refund | Closed | Deposit back to the relayer |
|---|---|---|---|
| A (agent, 3 tokens left) | 3 tokens to `refund_to` ([tx](https://testnet.nearblocks.io/txns/3drmfDsRmKUbVx2PnNLW4mzZfyqv5h7DZHiMUpkyHviy)) | yes | 0.09311 of 0.0985 NEAR |
| C (direct checkout, nothing owed) | none needed; the call closed it ([tx](https://testnet.nearblocks.io/txns/BaBApY1C2cWDDQd9TDYyxzymJaLiwyWSv6N3mvaETXVR)) | yes | 0.09315 of 0.0985 NEAR |

Gate totals afterwards: no escrow, no refund due, no mandates. The script marked C "unexpected" because it expected `refund: "pending"`, while the gate correctly answered `refund: "closed"` for a mandate with nothing owed. The script's check was too narrow and now accepts both; the gate behaved as designed.

