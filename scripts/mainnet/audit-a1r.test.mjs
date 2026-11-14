// Independent audit A1R (docs/audits/A1R.md): the person-run mainnet deploy script, offline
// (no network, no key). "A1R-NN ..." tests assert the REQUIRED behaviour and fail while the
// finding is open; "control: ..." tests pass.
import { describe, it, expect } from "vitest";
import { mainnetConfig, checkChain, EMPTY_CODE_HASH } from "./deploy-gate.mjs";

const REVIEWED_DEPOSIT = "1250000000000000000000"; // 0.00125 NEAR, A1-contract "Mainnet readiness"
const chain = (bounds) => ({
  chainId: "mainnet", account: { code_hash: EMPTY_CODE_HASH }, stateKeys: 0,
  metadata: { symbol: "USDC", decimals: 6 }, bounds,
  // As main() builds it: the config's registration_deposit is taken from the bounds it checks.
  config: mainnetConfig({ guardian: "guardian-person.near", registrationDeposit: bounds?.min }),
  balance: String(6n * 10n ** 24n),
});

describe("A1R mainnet deploy script", () => {
  it("control: USDC's storage minimum as reviewed (0.00125 NEAR) passes", () => {
    expect(checkChain(chain({ min: REVIEWED_DEPOSIT, max: REVIEWED_DEPOSIT }))).toEqual([]);
  });

  it("A1R-06 stops when USDC's storage minimum is not the reviewed 0.00125 NEAR", () => {
    // deploy-gate.mjs main() passes bounds.min into mainnetConfig and then compares the
    // config with the same bounds.min, so the "below / above the storage minimum" checks
    // can never fire in a real run. A changed minimum (here 0.05 NEAR) would be deployed
    // into a config that can never change, without the person being told.
    const problems = checkChain(chain({ min: "50000000000000000000000", max: "50000000000000000000000" }));
    expect(problems.length, "a registration deposit that differs from the reviewed value was accepted").toBeGreaterThan(0);
  });
});
