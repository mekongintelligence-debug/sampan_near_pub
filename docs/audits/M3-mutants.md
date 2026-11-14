# M3 mutation testing (cargo-mutants, gate contract)

Run: `cargo mutants -p sampan-gate` on 6 November 2026, before and again after the audit fixes. First run: 142 mutants, 119 caught, 9 unviable, 14 missed, **0 missed in `rules.rs`** (the M3 target). Five tests were added for the survivors (`mutants_*` in `contracts/gate/src/tests.rs`); a targeted rerun (`--lib` only) leaves 5 survivors, each with its reason below.

| Mutant | Why it survives | Accepted |
|---|---|---|
| `lib.rs:338` `order.len() > MAX_DOC_BYTES` → `==` or `>=` in `purchase` | Equivalent: an order longer than the limit is also rejected by `parse_order` (`too_large`), and one of exactly the limit is not a valid canonical order either way; the caller gets `order_invalid` in every case. The early check only saves gas. | yes |
| `lib.rs:409` `gas_left() < gas_needed(..)` → `<=` in `refund` | Exact-equality boundary: the mocked VM cannot set the remaining gas to exactly the threshold. The `==` mutant is killed by `mutants_refund_with_too_little_gas_is_refused_without_state`; both sides of the boundary are within the 40 Tgas margin. | yes |
| `lib.rs:705` same comparison → `<=` in `decide` | As above; the sweep `m3_cr5_*` (40 to 130 Tgas) checks both outcomes around the threshold. | yes |
| `lib.rs:802` `free > 4 × deposit` → `>=` in `should_register` | Exact-equality boundary on the gate's free balance; not reachable in the mocked VM. Either way the gate only registers when it has balance well above its own storage. | yes |

## After the audit fixes (commit `c8be3b1`)
Full rerun (`--lib`): 165 mutants, 143 caught, 11 unviable, 11 missed. Three tests were added for the six new testable survivors (`mutants_reservation_is_checked_at_init_and_funding`, `mutants_one_registration_per_mandate_across_payout_and_refund`, `mutants_refund_registration_counts_for_the_mandate`). A targeted rerun of the affected functions (69 mutants, 62 caught, 1 unviable) leaves 6 survivors: the four above at new line numbers (`lib.rs:408` twice, `487`, `820`, `918`), plus one new survivor, explained below. **`rules.rs`: still 0 survivors.**

| Mutant | Why it survives | Accepted |
|---|---|---|
| `lib.rs:675` `need > free_balance()` → `>=` in `fund` | Exact-equality boundary between the reservation and the free balance; not reachable in the mocked VM (the `==` mutant is killed by `mutants_reservation_is_checked_at_init_and_funding`). | yes |
