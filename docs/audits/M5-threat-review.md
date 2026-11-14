# M5 threat review (author, step 1 of the security gate)

Milestone: M5, payments, checkout widget, relayer and test shop. Date: 7 November 2026. Builds on the A1 redesign (`docs/audits/A1-contract.md`, `A1-payments.md`, author responses).

## Design
- `packages/payments`: builds the 1Click quote request from the mandate only (EXACT_OUTPUT of the signed price, recipient = the gate, `customRecipientMsg` = `{"mandate_hash","order"}`), checks the live answer field by field, and calls only `https://1click.chaindefuser.com/v0`. No keys.
- `apps/relayer`: the Sampan relayer. It checks a signed direct-checkout mandate against a fixed policy and registers it on the gate, attaching the refundable storage deposit. Testnet server on 127.0.0.1 only.
- `apps/checkout-widget`: one script loaded with SRI. It shows the mandate, asks an EVM wallet to sign it (ERC-191), has the relayer register it, gets a live quote and shows the deposit address only if the quote matches. A dry mode previews without signing.
- `apps/test-shop`: one product page, built with the widget under a strict CSP.

## Goals touched
S1 (funds only to the signed payee within budget), S2 (refunds only to the buyer), S3 (the buyer sees what they sign), S6 (no untrusted text changes a result or runs as code).

## Threats and controls
| Threat | Control | Test |
|---|---|---|
| A page script or 1Click changes recipient, amount, refund address, message or fees | `checkLiveQuote`: every sent field must come back equal; added routing fields stop; `amountOut` = `minAmountOut` = price; `amountIn` within slippage + fee bound | `payments.test.ts` "M5-2 …" (19); `shop.test.ts` "quote tampering …" (6) |
| A rate change between quote and deposit | EXACT_OUTPUT fixes what the gate receives; `amountIn` bound; 1Click refunds a short deposit to the origin address (**Assumption**, 1Click spec) | "a changed rate …" |
| Late delivery after expiry | Quote deadline + 30 min ≤ expiry; `timeEstimate` ≤ margin; the gate keeps a late payment as refund due (A1P-02) | "M5-8 timing", "a later deadline …" |
| Oversized attribution message | `attributionMessage` refuses over 1,024; the largest mandate the formats allow fits | "A1P-01 attribution message size" |
| Mandate shown differs from mandate signed | Rendered from the same object that is canonicalized and signed; the signed text is verified and must equal it; the relayer's answer must name the same hash | `shop.test.ts` "live flow …", "a relayer answer for another mandate …" |
| Dry path signs or pays | One `dry` switch; dry mode asks for the address only, never calls the relayer, never shows a deposit address; a dry request is refused by `checkLiveQuote` | "dry-quote flow …", "M5-9 …" |
| Wrong widget code | SRI sha384 on the script tag; the browser refuses a mismatch | "a wrong SRI hash …" |
| Hostile frame, `postMessage` | Live mode refuses inside a frame; the widget registers no `message` listener; the shop sends `frame-ancestors 'none'` when served with headers | "inside a frame …" |
| The relayer is used to lock its NEAR (deposit griefing) | Policy: only agentless mandates for listed payees, price cap, lifetime 45 min to 24 h, own `0x` refund account; 10 requests per client per hour; never fills the gate's open-mandate cap; deposits come back on close | `policy.test.ts` (10) |
| Front-running the registration | `already_registered` counts as registered: the mandate on the gate is exactly the signed one | "a mandate someone else registered first …" |
| Untrusted text from 1Click or the gate shown to the buyer | `textContent` only; 1Click errors stripped to printable ASCII, 200 chars; relayer passes on only fixed reason codes | "a refusal, garbage …", "passes on only fixed reason codes …" |
| 1Click errors, timeouts, garbage, huge answers | Bounded client: 15 s timeout, 64 KB cap, JSON only; all are errors, never a quote | "1Click client: errors, timeouts, hosts" |
| Refund to the wrong party | Origin refund = the connected wallet's EIP-55 address; NEAR `refund_to` = the buyer's own `0x` account (A1P-08, **Assumption** to verify on mainnet) | "M5-6, M5-7 …" |

## Residual risk
- A compromised merchant page can show its own widget, or set its own payee in the data attributes. The buyer sees payee, gate and mandate hash before signing (A1P-09). Detection afterwards: no receipt for the buyer's mandate.
- 1Click's quote signature is not verified (A1P-09, Q38); the full answer is offered to the buyer as a payment record.
- **Assumption:** 1Click answers browser requests from a shop origin (CORS). Checked with the first live dry quote.
- The mainnet relayer and the first purchase are person-run steps, after A1 sign-off.

## Self-review (author, step 4: `/code-review high`, 7 Nov 2026)
| ID | Finding | Outcome | Regression test |
|---|---|---|---|
| M5-CR1 | Wallets often return lower-case addresses; the widget refused them as the 1Click refund address, so no checkout could start | Fixed: `toChecksumEvm` turns the wallet's address into its EIP-55 form | "M5-CR1 …" (payments, browser) |
| M5-CR2 | `refund_to` was never checked to exist on NEAR (M5-7, P-2) | Fixed: the relayer and the proof script check it with a final view before any deposit or signature | "M5-CR2 …" |
| M5-CR3 | Strict string compare of the echoed deadline could refuse every live quote if 1Click reformats it | Fixed: whole-second deadline; the echo is compared as a time | "M5-CR3 …" |
| M5-CR4 | Concurrent relayer requests could together fill the gate's mandate cap | Fixed: the cap check and registration run one at a time | "M5-CR4 …" |
| M5-CR5 | A full rate-limit table was cleared, resetting every client's count | Fixed: idle clients are dropped; while full, new clients are refused | "M5-CR5 …" |
| M5-CR6 | A quote deadline already past or minutes away was accepted | Fixed: at least 10 minutes to pay | "M5-CR6 …" |
| M5-CR7 | `amountIn` below the price was accepted | Fixed: refused (same 6-decimal USDC on both sides) | "M5-CR7 …" |
| M5-CR8 | The 64 KB response cap was applied after reading the whole body | Fixed: streaming cap | "M5-CR8 …" |
| M5-CR9 | A live widget without `data-relayer` posted the signed mandate to the shop's own origin | Fixed: live mode needs an https (or loopback) relayer URL | "M5-CR9 …" (browser) |
| M5-CR10 | CLI helpers and EIP-55 code were duplicated | Fixed: `scripts/mainnet/cli.mjs`, `toChecksumEvm` | (refactor; covered by the existing tests) |
