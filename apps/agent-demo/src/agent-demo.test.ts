// M4 unit tests: fixture parsing never trusts page text, and the agent process refuses to
// run with operator secrets or with anything but a gate.purchase function-call key.
import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { loadFixtures, parseFixture, orderFor } from "./fixtures.ts";
import { assertAgentEnvironment, assertFunctionCallOnly, assertTestnetAccounts } from "./safety.ts";
import { parseOrder, toBytes } from "../../../packages/mandate/src/index.ts";

const DIR = resolve(import.meta.dirname, "../../../fixtures/attacks/agent-demo");
const A = { payee: "shop.testnet", attacker: "attacker-m4.testnet", token: "usdc.testnet", fakeToken: "fake-usdc.testnet" };
const raw = (id: string) => readFileSync(resolve(DIR, `${id}.json`), "utf8");

describe("agent-demo fixtures", () => {
  it("loads the labelled suite, attacks first, with at least 6 attacks and 3 controls", () => {
    const f = loadFixtures(DIR, A);
    const attacks = f.filter((x) => x.label === "attack");
    expect(attacks.length).toBeGreaterThanOrEqual(6);
    expect(f.filter((x) => x.label === "control").length).toBeGreaterThanOrEqual(3);
    expect(f.slice(0, attacks.length).every((x) => x.label === "attack")).toBe(true);
    // Known misses (M4-08) are labelled attacks that the gate releases by design.
    expect(attacks.filter((x) => x.expected.decision === "release").map((x) => x.id)).toEqual(["inj-07-surcharge-within-budget", "inj-08-swap-approved-item"]);
  });
  it("resolves placeholders and never returns the page text", () => {
    const f = parseFixture(raw("inj-01-swapped-payee"), A);
    expect(f.proposes.payee).toBe("attacker-m4.testnet");
    expect(f.proposes.asset).toBe("usdc.testnet");
    // Compare with the page text read from the fixture: attack strings stay in fixtures/attacks/.
    const page: string = JSON.parse(raw("inj-01-swapped-payee")).page;
    expect(JSON.stringify(f)).not.toContain(page.slice(0, 40));
    expect(Object.keys(f)).not.toContain("page");
  });
  it("builds a canonical order that parses as sampan.order.v1", () => {
    const f = parseFixture(raw("ctl-01-report-001"), A);
    const o = orderFor(f, "ab".repeat(32), "cd".repeat(32));
    expect(parseOrder(toBytes(o)).order.payee).toBe("shop.testnet");
  });
  it("rejects malformed or mislabelled fixtures", () => {
    const base = JSON.parse(raw("ctl-01-report-001"));
    const bad = (patch: object) => () => parseFixture(JSON.stringify({ ...base, ...patch }), A);
    expect(bad({ label: "attack" })).toThrow(); // id prefix and label disagree
    expect(bad({ extra: 1 })).toThrow();
    expect(bad({ expected: { decision: "release", failing: ["R8"] } })).toThrow();
    expect(bad({ agent_proposes: { ...base.agent_proposes, payee: "Not An Account" } })).toThrow();
    expect(bad({ agent_proposes: { ...base.agent_proposes, amount: "0" } })).toThrow();
  });
});

describe("agent process safety", () => {
  it("refuses to run when operator secrets are visible", () => {
    expect(() => assertAgentEnvironment({ NEAR_TESTNET_PRIVATE_KEY: "x" })).toThrow(/secrets/);
    expect(() => assertAgentEnvironment({ PATH: "/bin", HOME: "/root", NEAR_TESTNET_ACCOUNT_ID: "x.testnet" })).not.toThrow();
    expect(() => assertAgentEnvironment({ TG_TOKEN: "x" })).toThrow(/secrets/);
    // M4-CR3: any credential-like name, not just the two operator variables.
    for (const k of ["NEAR_MAINNET_PRIVATE_KEY", "GH_TOKEN", "OPENAI_API_KEY", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY"]) {
      expect(() => assertAgentEnvironment({ [k]: "x" }), k).toThrow(/secrets/);
    }
    expect(() => assertAgentEnvironment({ PATH: "/bin" })).not.toThrow();
  });
  it("accepts only a function-call key for gate.purchase", () => {
    const gate = "gate-m3.x.testnet";
    expect(() => assertFunctionCallOnly({ permission: "FullAccess" }, gate)).toThrow(/not a function-call key/);
    expect(() => assertFunctionCallOnly({ permission: { FunctionCall: { receiver_id: "token.x.testnet", method_names: ["purchase"] } } }, gate)).toThrow(/limited to the gate/);
    expect(() => assertFunctionCallOnly({ permission: { FunctionCall: { receiver_id: gate, method_names: [] } } }, gate)).toThrow(/only purchase/);
    expect(() => assertFunctionCallOnly({ permission: { FunctionCall: { receiver_id: gate, method_names: ["purchase", "refund"] } } }, gate)).toThrow(/only purchase/);
    expect(() => assertFunctionCallOnly({ permission: { FunctionCall: { receiver_id: gate, method_names: ["purchase"], allowance: "1" } } }, gate)).not.toThrow();
    // M4-CR2: no allowance means unlimited gas spending.
    expect(() => assertFunctionCallOnly({ permission: { FunctionCall: { receiver_id: gate, method_names: ["purchase"], allowance: null } } }, gate)).toThrow(/allowance/);
    expect(() => assertFunctionCallOnly({ permission: { FunctionCall: { receiver_id: gate, method_names: ["purchase"] } } }, gate)).toThrow(/allowance/);
  });
  it("refuses non-testnet accounts", () => {
    expect(() => assertTestnetAccounts(["gate.near"])).toThrow();
    expect(() => assertTestnetAccounts(["gate-m3.x.testnet"])).not.toThrow();
  });
});
