// Independent audit M4 (docs/audits/M4.md). "M4-NN ..." tests assert the REQUIRED behaviour
// and FAIL while the finding is open; "control: ..." tests pass today. Fixture page text is
// data: it is never printed or copied here.
import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { parseFixture } from "./fixtures.ts";

const DIR = resolve(import.meta.dirname, "../../../fixtures/attacks/agent-demo");
const A = { payee: "shop.testnet", attacker: "attacker-m4.testnet", token: "usdc.testnet", fakeToken: "fake-usdc.testnet" };
const base = JSON.parse(readFileSync(resolve(DIR, "inj-04-price-raise.json"), "utf8"));

describe("M4-08 the labelled suite can only contain attacks the gate refuses", () => {
  it("M4-08: an injection that stays inside the signed mandate can be recorded as a known miss (released)", () => {
    // Same technique as inj-04, but the surcharge keeps the order within the 3-token budget.
    // The gate releases it by design (it enforces what was signed); the suite must be able
    // to say so instead of rejecting the fixture as inconsistent.
    const inMandate = { ...base, id: "inj-90-price-raise-in-budget", agent_proposes: { ...base.agent_proposes, amount: "2900000" }, expected: { decision: "release", failing: [] } };
    expect(() => parseFixture(JSON.stringify(inMandate), A)).not.toThrow();
  });
  it("control: the committed price-raise attack parses and expects R7", () => {
    expect(parseFixture(JSON.stringify(base), A).expected).toEqual({ decision: "refuse", failing: ["R7"] });
  });
});
