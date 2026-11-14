# M8 cold tests

## 1. Claude Code screener test (7 November 2026)
A fresh Claude Code session with no project context got only: "Evaluate this repository against its README claims", plus one safety limit (run nothing that needs a key or signs a transaction). It worked in a fresh clone at commit `e335501`.

**Score: 7 out of 10** for "a stranger can verify the claims from the README alone".

**Reproduced:**
- `pnpm install` and `pnpm dry-run`;
- the checker page from disk;
- `cargo test -p sampan-gate`;
- the attack counts;
- the checker browser tests;
- `scripts/setup-env.sh`, `make check` and `make security`.

**Not reproduced (needs a key):** the agent-key refusals (`pnpm demo:direct`) and `pnpm e2e`.

**Found, and fixed in `d734067`:**
- The dry run printed counts, not each check and the verdict.
- The README said one check reads "Cannot verify"; it is two.
- Row 7 claimed "all outcomes as expected" while the results file showed one failure. It was re-run cleanly on 7 Nov: 12 of 12.
- The attack-count command needed `-- --nocapture`.
- No prerequisites or wait times were given.
- The minimum-gas row had no command and no transaction links.
- The dry quote's recipient (`near`) was not explained.
- `setup-env.sh` changing git config was not mentioned.
- `examples/README.md` was one line.

## 2. Human cold test
**Open:** a person outside the team, chosen by the lead, reads the README and tries the "Try it" steps, following `docs/cold-test-guide.md`. Record here: who, date, what they could and could not do, and the fixes.
