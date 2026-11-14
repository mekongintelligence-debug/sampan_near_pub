# M2 mutation testing (author)

`make mutants` on `crates/formats`, 5 November 2026, cargo-mutants 27.1.0.

| Run | Caught | Missed | Unviable |
|---|---|---|---|
| First | 158 | 23 | 13 |
| After 25 boundary vectors | 178 | 3 | 13 |

## Remaining survivors: equivalent mutants (no observable change)
| Mutant | Why no test can kill it |
|---|---|
| `grammar.rs` `positive_decimal`: `\|\|` → `&&` in the length/digit pre-check | Any value with a non-digit or too many digits still fails the following `parse::<u128>()` / `parse::<u64>()` with the same `schema` error. The pre-check is defence in depth. |
| `grammar.rs` `base58_exact`: `\|\|` → `&&` in the 32-44 length pre-check | A base58 string outside 32-44 characters cannot decode to exactly 32 bytes, so the byte-length check rejects it with the same result. |
| `grammar.rs` `base58_exact`: `&&` → `\|\|` in the length-and-re-encode check | Base58 without padding round-trips exactly, so re-encoding always matches; every caller also converts to `[u8; 32]`, which rejects other lengths with the same `schema` error. |

The security owner may accept these or ask for the redundant checks to be removed instead.
