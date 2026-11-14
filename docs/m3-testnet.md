# M3 on testnet: the gate contract, end to end

Date: 6 November 2026. Gate: `gate-m3.sampan-trust-01.testnet` (contract `0.1.0-m3`, after the audit M3 fixes), mock NEP-141 token from M1 (`token.sampan-trust-01.testnet`, 6 decimals), payee `payee2-m3.sampan-trust-01.testnet` (new, so the gate pays its token registration).
Script: `make testnet-m3` (`scripts/m3/testnet-run.mjs`). Every link below comes from the run recorded in `docs/m3-testnet-results.json` (2026-11-06T05:51:55.347Z, 34 of 34 outcomes as expected; audit M3-10). [Initialisation](https://testnet.nearblocks.io/txns/Hai8pSkoNFHNWbyRCx4D4q9FBdqfTvXPEDXcoUpDH3BU) by the gate account itself, with the config checked against the expected one (M3-04).

Every receipt event below was re-parsed with the TypeScript checker code (`parseReceiptCore` and the full `parseEnvelope`) and its hash compared with `get_receipt(mandate_hash, order_id)`.

| Rule | Pass on testnet | Fail on testnet |
|---|---|---|
| R1 signature | [mandate A funded](https://testnet.nearblocks.io/txns/8Q2JVkV5HrZ4q5wjFPfLfCigZaLUw5LbQe1kxNYwsHuA) | [tampered mandate returned in full](https://testnet.nearblocks.io/txns/C4mARGUTgPCmENWgAAqYhtYMenUUCyTDNJksjrAM9NRt) |
| R2 network, gate | [mandate A funded](https://testnet.nearblocks.io/txns/8Q2JVkV5HrZ4q5wjFPfLfCigZaLUw5LbQe1kxNYwsHuA) | [mainnet mandate](https://testnet.nearblocks.io/txns/8QMEvufsjpGysa4RyokEAezkxaJP6qvfmb6zDtGsX748), [other gate](https://testnet.nearblocks.io/txns/524GJmURA4HKXCpXjYAgyx44VtLwo7xgjwxjGcmLCRd4), both returned in full |
| R3 expiry | [release](https://testnet.nearblocks.io/txns/9Vrpx1yrLNcXKcKZjtubxHj9pffYSUSH1rVNtp2Bc2QY) | [purchase after expiry, anchored refusal](https://testnet.nearblocks.io/txns/8Z82WXxnvkStQtS5pKEXPd4W5mxLWEDHRuzMpyoNrEVg) |
| R4 order unused | [release](https://testnet.nearblocks.io/txns/9Vrpx1yrLNcXKcKZjtubxHj9pffYSUSH1rVNtp2Bc2QY) | [replay refused, no state](https://testnet.nearblocks.io/txns/9F9Rzs8oXtJJoWSzzXRexF7gqFXBLxuBEySpdUVucfzW) |
| R5 caller | [release by the agent's function-call key](https://testnet.nearblocks.io/txns/9Vrpx1yrLNcXKcKZjtubxHj9pffYSUSH1rVNtp2Bc2QY) | [buyer calls purchase, refused, no state](https://testnet.nearblocks.io/txns/AJaE8PPcr6gAexmCfg4fFWiJqHbm2XQVPTmxeHdFL251) |
| R6 asset | [release](https://testnet.nearblocks.io/txns/9Vrpx1yrLNcXKcKZjtubxHj9pffYSUSH1rVNtp2Bc2QY) | [order in another asset](https://testnet.nearblocks.io/txns/2AqFpPgdBqappNc8NvTmaoYid6oZUMdFvz1sm1meMdnp) |
| R7 budget, escrow | [release](https://testnet.nearblocks.io/txns/9Vrpx1yrLNcXKcKZjtubxHj9pffYSUSH1rVNtp2Bc2QY) | [4 tokens with 3 left](https://testnet.nearblocks.io/txns/7PNNfmhrwMMUUcT1d8jMJjqByp4Pq7atvbPQ3bw84ojX) (observed 3) |
| R8 payee | [release](https://testnet.nearblocks.io/txns/9Vrpx1yrLNcXKcKZjtubxHj9pffYSUSH1rVNtp2Bc2QY) | [swapped payee](https://testnet.nearblocks.io/txns/63cvtNUF2RasgvqgrfaBJcymEqUxsVjnp6SDSdwKc1wq) |
| R9 item | [release](https://testnet.nearblocks.io/txns/9Vrpx1yrLNcXKcKZjtubxHj9pffYSUSH1rVNtp2Bc2QY) | [item outside the mandate](https://testnet.nearblocks.io/txns/rYEzroFXqWUk6XgRsVQmRGhWp5fw4r4HadYD5W5SuB2) |

Other flows:
- **Fake token:** [the buyer calls `ft_on_transfer` directly](https://testnet.nearblocks.io/txns/3abzwEHwj2emGHEtC959vXVxmk7hM3L5GkpELGDTzoWi); the full amount is handed back and nothing is stored.
- **Direct checkout (the 1Click path, `agent` null):** [the payment carries the order; the gate decides and pays in the same transaction](https://testnet.nearblocks.io/txns/EGrWM5xRFH31rh9nUzSX7vBotFTr63sh3TC6rnx92LHr). An order is accepted only on the call that creates the mandate (M3-01).
- **Refund and close:** [refused before expiry](https://testnet.nearblocks.io/txns/GQKP9nY8eyETze5DhkoLrXf5Ehcipu3bv1ADkmVs9WHh); [after expiry a stranger triggers it and the funds go to `refund_to`](https://testnet.nearblocks.io/txns/6ZhMZk66DDMaNpFi2GMEBbho5Te5Zv17KwLQBUumpSJY); once the refund settles the mandate closes, so [a second refund finds nothing](https://testnet.nearblocks.io/txns/HADBUnKtkYMsq6zSjF7M3Kac84q4MeVWKcuDN8wGt3vz) and [a purchase on it is refused without state](https://testnet.nearblocks.io/txns/D9UR22zCF4tjJW67m223ziFv5NX3d5N898TFVrEHwNG4) (M3-02).
- **Payee registration paid by the gate (Q17), once per mandate (M3-03):** in [the first release](https://testnet.nearblocks.io/txns/9Vrpx1yrLNcXKcKZjtubxHj9pffYSUSH1rVNtp2Bc2QY).
- **Payout failure restores the mandate (real, unplanned, earlier build):** in the first run the script initialised the gate with a registration deposit below the token's minimum (a rounding bug in the script's NEAR helper, now fixed and also refused at init, M3-CR4). The token refused the batch; the callback marked the payout failed and restored budget and escrow exactly ([release, failed payout](https://testnet.nearblocks.io/txns/2FcotSGVvUGf8G59pjrL5xLxRUhX45ioBGeMVCAKjCCr)). Results: `docs/m3-testnet-run1-results.json`.

Testnet maintenance: the gate account was redeployed twice. Once by deleting and recreating it (run 1), and once, after the audit changed the state layout, by wiping its state with the throwaway `spikes/gate2/cleaner` contract (`scripts/m3/reset-testnet-gate.mjs`), because NEAR refuses to delete an account with large state. Mock tokens from earlier builds stay on the token contract as unaccounted surplus of the gate (allowed: escrow total <= tokens held).

**Later change (M4, 6 Nov):** the gate was reset and re-initialised with 4 open mandates of 16 orders (finding M4-01, `docs/m4-testnet.md`). The transactions linked above stay on the explorer, but the M3 mandates and receipts are no longer in the gate's state; `make testnet-m3` re-runs the suite against the current gate.

Testnet NEAR: about 4 used by M3, mostly contract storage (the 309 KB wasm costs about 3.1 NEAR). The gate reserves its worst-case storage per open mandate against its free balance (M3-05), so the testnet caps were 6 open mandates of 8 orders (now 4 of 16, see above).
