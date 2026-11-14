# Hackathon disclosures

NEAR Hackathon: Build Beyond Boundaries. Submission closes 14 November 2026, 23:59 UTC.
This file holds the disclosures the hackathon rules require. Items still marked as blank fields are filled in by the team before submission.

## Team
- Team name: Sampan
- Members and roles: Jan Hanken (lead, security owner, runs the mainnet steps) and Vosumtey Seng (co-owner; Gate 1 sign-off). Built with Claude Code.
- NEAR account for any prize: `sampantrust.near` (the team's top-level account, on a hardware wallet; to be created with the mainnet accounts)

## Other entries
- Projects by team members in other entries of this hackathon: none
- No code is shared with any other hackathon entry.

## When the work was done
- All work in this repository was done on or after 19 October 2026. First commit: `dc93a36` in the team's private repository, 5 November 2026 (08:44 UTC). The public repository is created from a checked export with a fresh history, so this and the other commit hashes cited in `docs/` refer to the private history; the security owner can show it on request.
- Earlier work: none in this repository; it starts from the first commit above.

## Funds
- Only team money is used, in tiny amounts, for mainnet tests. No outside funds.

## Tools
- Built mainly with Claude Code. Every merge follows the automated checks (`make check`, `make security`) and an audit by a fresh Claude Code session; each audit report ends with the security owner's sign-off line (`docs/audits/`), signed so far for A1-contract, A1-payments and A1R.

## Third-party services and code
- NEAR Intents 1Click API (`https://1click.chaindefuser.com/v0`): quotes, dry quotes and status. 1Click delivers USDC to the gate.
- NEAR RPC endpoints: `rpc.mainnet.near.org`, `rpc.testnet.near.org` and FastNEAR (`rpc.fastnear.com`, `test.rpc.fastnear.com`), plus NEAR's archival hosts (`archival-rpc.mainnet.near.org`, `archival-rpc.testnet.near.org`); the checker lets the user pick and cross-check them.
- Native USDC on NEAR (`17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1`) as the settlement token on mainnet; a mock test token on testnet.
- Explorer links point to NearBlocks; nothing depends on it.
- Open-source dependencies: see `Cargo.lock` and `pnpm-lock.yaml`.
