# M1 threat review (author, step 1 of the security gate)

Milestone: M1, gate tests (Gate 2 on testnet, 1Click checks, mainnet scripts for people). Date: 5 November 2026.

## Goals touched (`docs/SECURITY.md` section 1)
- **S3** the agent key reaches the gate's `purchase` and nothing else: this is what Gate 2 tests.
- **S7** no secret committed, logged or published: M1 is the first milestone that handles a real (testnet) private key.
- S1 indirectly: the spike gate pays out a mock token; it is throwaway code and never merged into `contracts/`.

## Threats and controls
| Threat | Control | Test |
|---|---|---|
| Testnet private key printed, logged or written to disk | Key read only from `NEAR_TESTNET_PRIVATE_KEY` into an in-memory key store; scripts never print keys, never write credential files; error messages pass through a redaction helper | Unit test: redaction removes any `ed25519:` secret from messages; secrets scan in `make security` |
| A script touches mainnet by mistake | Hard guard: network must be `testnet`, every account must end in `.testnet`, RPC URL must be a testnet endpoint; otherwise exit before any call | Unit tests for the guard |
| The agent's function-call key outlives the run or is reused | Key generated fresh in memory each run, never stored, deleted from the agent account at the end of the run | Script output shows the delete transaction |
| The agent key can do more than call `purchase` | Gate 2 itself: the script tries `ft_transfer` on the token, another gate method, and a call with an attached deposit, and requires each to fail | Recorded transaction outcomes in `docs/gates.md` |
| Spike code mistaken for the real gate | Lives in `spikes/gate2/`, outside the workspace and `contracts/`; README says throwaway | `make check` does not build it; M3 starts from `docs/ARCHITECTURE_AND_PLAN.md` 3.4 |
| Mainnet payment script run with wrong amount or recipient | Scripts for Gates 3/4 are dry-run by default, print the exact quote and require typing a confirmation; a person runs them | Script review in the audit |

## Out of scope for M1
The real gate contract (M3), escrow accounting, receipts.
