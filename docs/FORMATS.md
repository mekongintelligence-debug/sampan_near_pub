# Formats v1: mandate, order, receipt

Status: **frozen as v1 on 5 November 2026 (lead approval, Jan Hanken)**, pending the M2 sign-off. Any change needs lead approval and a new version (`CLAUDE.md`).
Decisions applied: signing with NEP-413 and ERC-191 (Q3), no merchant signatures (Q15), the gate's "signature" is its receipt event plus stored hash (Q11), USDC on NEAR (Q14), hashes only for item data on-chain (Q28).

## 1. Design rules (why the formats look like this)
- **ASCII only, no numbers, no free text.** Every value is a string from a fixed grammar, `true`/`false`, `null`, an array or an object. Amounts and times are decimal strings. This removes the classic canonical-JSON traps: number formatting, Unicode normalisation, escapes.
- **Canonical bytes are the only accepted input.** A document is valid only if its raw bytes equal the RFC 8785 (JCS) serialisation of what it parses to. Whitespace, key order, duplicate keys and escapes therefore all fail as `not_canonical`.
- **Closed objects.** Every listed field is required; no other field is allowed.
- **Domain separation.** Every signed mandate names its format version, `network` and `gate`, so it cannot be replayed on another network or gate.
- **Size limit:** 4096 bytes per document, checked before parsing.
- Hashes are SHA-256 over the canonical bytes, written as 64 lowercase hex characters.

## 2. Grammars
| Name | Rule |
|---|---|
| `account` | NEAR account ID: 2-64 chars, `^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$` |
| `amount` | Positive integer as decimal string, no leading zeros, at most `2^128 - 1`: `^[1-9][0-9]{0,38}$` plus range check |
| `time_ns` | Nanoseconds since 1970 as decimal string, positive, at most `2^64 - 1`: `^[1-9][0-9]{0,19}$` plus range check |
| `hex32` | 32 bytes as 64 lowercase hex chars: `^[0-9a-f]{64}$` |
| `item_id` | `^[a-z0-9][a-z0-9._-]{0,63}$` |
| `network` | `testnet` or `mainnet` |
| `buyer` | `near:ed25519:<base58 of 32-byte public key>` (canonical, not small-order) or `evm:0x<40 lowercase hex>` |
| `tx_hash` | NEAR transaction hash: base58 of 32 bytes |

## 3. Mandate (`sampan.mandate.v1`)
| Field | Type | Meaning |
|---|---|---|
| `v` | `"sampan.mandate.v1"` | Version |
| `network` | network | Domain separation |
| `gate` | account | The only gate that may honour it |
| `buyer` | buyer | Who signs |
| `agent` | account or `null` | The account allowed to spend it; `null` = the buyer pays directly |
| `asset` | account | Token contract (USDC on NEAR) |
| `max_amount` | amount | Budget ceiling (agent) or exact price (person) |
| `payee` | account | The only account that may be paid |
| `items` | array of item_id, 1-16, strictly ascending (sorted, unique) | Items the mandate covers |
| `expiry_ns` | time_ns | Not valid at or after this block time |
| `nonce` | hex32 | Single use; also the NEP-413 nonce |
| `refund_to` | account | Where unspent escrow returns |

`mandate_hash = sha256(canonical mandate bytes)`.

## 4. Signed mandate (`sampan.signed-mandate.v1`)
`{"mandate": <mandate>, "signature": <hex>, "standard": "nep413" | "erc191", "v": "sampan.signed-mandate.v1"}`, canonical as a whole.

**NEP-413** (buyer `near:ed25519:...`): the wallet signs `sha256(borsh(payload))` with ed25519, where the payload is the 4-byte little-endian tag `2^31 + 413`, then `message` (u32 length + bytes) = the canonical mandate JSON, `nonce` = the 32 bytes of `mandate.nonce`, `recipient` (u32 length + bytes) = `mandate.gate`, `callback_url` = absent (`0x00`). Signature: 64 bytes, 128 hex chars.
**Assumption:** the layout matches what NEAR wallets sign for NEP-413; checked against a real wallet in M5.
Before verifying, both implementations reject inputs on which ed25519 libraries are known to differ, so the checker (noble, strict) and the contract (NEAR's host function) always agree: a buyer key that is a small-order point or encodes `y >= p` is a `schema` error; a signature whose `R` is small-order or non-canonical, or whose `S >= L`, is `bad_signature_encoding`.

**ERC-191** (buyer `evm:0x...`): `personal_sign` over the canonical mandate JSON: `keccak256("\x19Ethereum Signed Message:\n" + decimal byte length + message)`. Signature: 65 bytes `r || s || v`, 130 hex chars. `v` must be 27 or 28 (0 or 1 accepted and normalised); `r` and `s` must be in `[1, n-1]` and `s <= n/2` (low-s, EIP-2). The recovered public key's Ethereum address must equal the buyer address.

## 5. Order (`sampan.order.v1`)
Supplied by the buyer or agent; not signed (Q15).
| Field | Type |
|---|---|
| `v` | `"sampan.order.v1"` |
| `order_id` | hex32 (single use) |
| `mandate_hash` | hex32 |
| `item` | item_id |
| `amount` | amount |
| `asset` | account |
| `payee` | account |

`order_hash = sha256(canonical order bytes)`.

## 6. Receipt core (`sampan.receipt.v1`)
Anchored by the gate: its hash is emitted in the receipt event and stored (Q11).
| Field | Type |
|---|---|
| `v` | `"sampan.receipt.v1"` |
| `network`, `gate` | as in the mandate |
| `mandate_hash`, `order_hash` | hex32 |
| `observed` | `{"amount": amount, "asset": account}`: what the gate itself saw |
| `rules` | array of `{"id": "R1".."R9", "pass": true/false}`, exactly R1 to R9 in order |
| `decision` | `"release"` or `"refuse"` |
| `block_height` | decimal string, positive, at most `2^64 - 1` |

`decision` must be `"release"` if and only if every rule passes.

## 7. Receipt envelope (`sampan.receipt-envelope.v1`)
Not anchored; the checker re-derives each part. Ordinary JSON (not required to be canonical), at most 16 KiB, closed object:
`v`, `core` (receipt core), `core_hash` (hex32), `signed_mandate`, `order`, `tx` (`{"deposit": tx_hash|null, "decision": tx_hash, "payout": tx_hash|null}`), `untrusted` (`{"agent_note": string <= 280 chars}` or `null`). Anything under `untrusted` is shown as plain text and never trusted.

## 8. Error codes (identical in Rust and TypeScript)
`too_large`, `invalid_json`, `not_canonical`, `schema`, `unsupported_standard`, `bad_signature_encoding`, `high_s`, `bad_signature`, `wrong_signer`, `inconsistent`.

## 9. Rules R1-R9 (checked by the gate in M3, recorded in the receipt)
R1 signature valid for `buyer` · R2 `network` and `gate` match the contract · R3 not expired · R4 nonce and order ID unused · R5 caller is the `agent` (or the buyer when `agent` is null) · R6 asset matches · R7 amount within remaining budget and equal to the escrow observed · R8 payee matches · R9 item is in `items`.
