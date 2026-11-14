# M2 threat review (author, step 1 of the security gate)

Milestone: M2, formats v1 and shared crypto. Date: 5 November 2026.

## Goals touched (`docs/SECURITY.md` section 1)
- **S1** funds only to the signed payee within budget: depends on the mandate parsing exactly the signed bytes.
- **S4 / S5** receipts that cannot be forged and a checker that never shows a forgery green: depend on identical hashing and verification in Rust and TypeScript.
- S2, S3, S6, S7 indirectly (formats carry `refund_to`, `agent`; no secrets in vectors).

## Threats and controls
| Threat | Control | Tests |
|---|---|---|
| Two parsers read the same bytes differently (duplicate keys, number formats, Unicode, escapes) | ASCII-only grammars, no numbers, canonical-bytes-only input (`docs/FORMATS.md` 1) | Vectors for duplicates, whitespace, key order, escapes, non-ASCII, numbers; property test: any re-serialisation other than canonical is rejected |
| Signature replay across networks, gates or format versions | `v`, `network`, `gate` inside the signed bytes; NEP-413 recipient = gate | Vectors: testnet mandate checked as mainnet, other gate, other version |
| Signature malleability (secp256k1 high-s, odd `v`) | Low-s required, `v` in {0,1,27,28}, r,s range checks | Vectors: high-s, v=2, r=0, s=n |
| Wrong signer accepted (comparing keys as bytes, address derivation errors) | Address derived from recovered key with keccak; ed25519 key taken from `buyer` | Vectors: valid signature by another key |
| Amount or time overflow | Decimal strings with length and range checks against u128 / u64 | Vectors: u128 max, u128 max + 1, leading zeros, zero |
| Unbounded input (DoS) | 4096-byte limit before parsing; arrays capped | Vectors: oversize, 17 items |
| Receipt core says "release" while a rule failed | `inconsistent` error | Vector |
| Key material leaks through test vectors | Vectors hold only public keys and signatures; keys derived from fixed seeds inside the generator at run time; secrets scan runs on vectors | Secrets scan in `make security`; generator never prints keys |
| Vectors silently changed to make a failing implementation pass | Generator never overwrites an existing vector; a manifest of vector hashes is checked in tests | Test: manifest matches files |

## Out of scope for M2
Contract state, escrow and replay storage (M3); checker UI (M6).
