// A1C-06: the person-run mainnet deploy script's checks, offline (no network, no key).
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { mainnetConfig, checkInputs, checkChain, checkDeployed, checkLocked, reservationPerMandate, USDC, EMPTY_CODE_HASH } from "./deploy-gate.mjs";

const HASH = "PgEuTpCVtCZ4xWEJ97Qa6wMYCqUspFd2VRVu2sNDGMj";
const cfg = mainnetConfig({ guardian: "guardian-person.near" });
const okChain = {
  chainId: "mainnet", account: { code_hash: EMPTY_CODE_HASH }, stateKeys: 0,
  metadata: { symbol: "USDC", decimals: 6 }, bounds: { min: "1250000000000000000000" }, config: cfg, balance: String(6n * 10n ** 24n),
};

describe("A1C-06 mainnet deploy checks", () => {
  it("the reviewed config: native USDC, 24 h lifetime, caps 1/10/50 USDC, 100 mandates (A1R-03), 16 orders", () => {
    expect(cfg).toMatchObject({ network: "mainnet", token: USDC, min_funding: "1000000", max_escrow_per_mandate: "10000000", max_total_escrow: "50000000", max_mandates: 100, max_orders_per_mandate: 16, max_lifetime_ns: 86_400_000_000_000, guardian: "guardian-person.near" });
    expect(reservationPerMandate(16, cfg.registration_deposit)).toBe(98_500_000_000_000_000_000_000n);
  });
  it("inputs: refuses testnet or implicit accounts, the gate as guardian, a build that is not the reviewed code", () => {
    expect(checkInputs({ gate: "gate.sampan.near", guardian: "guardian-person.near", codeHash: HASH, wasmHash: HASH, config: cfg })).toEqual([]);
    expect(checkInputs({ gate: "gate.sampan.testnet", codeHash: HASH })).toContain("gate must be a named .near account");
    expect(checkInputs({ gate: "ab".repeat(32), codeHash: HASH })).toContain("gate must be a named .near account");
    expect(checkInputs({ gate: "g.near", guardian: "g.near", codeHash: HASH })).toContain("guardian must not be the gate account");
    expect(checkInputs({ gate: "g.near", codeHash: HASH, wasmHash: "x" + HASH.slice(1) }).join()).toMatch(/is not the reviewed code/);
    expect(checkInputs({ gate: "g.near", codeHash: "" })).toHaveLength(1);
    expect(checkInputs({ gate: "g.near", codeHash: HASH, config: { ...cfg, network: "testnet" } })).toContain("config network must be mainnet");
    expect(checkInputs({ gate: "g.near", codeHash: HASH, config: { ...cfg, token: "usdc.fakes.near" } })).toContain("config token must be native USDC");
  });
  it("chain: stops on testnet, existing code or state, wrong token, deposit not the storage minimum, low balance", () => {
    expect(checkChain(okChain)).toEqual([]);
    for (const [patch, msg] of [
      [{ chainId: "testnet" }, /not mainnet/], [{ account: null }, /does not exist/], [{ account: { code_hash: HASH } }, /already has a contract/],
      [{ stateKeys: 3 }, /has state/], [{ metadata: { symbol: "USDC", decimals: 18 } }, /USDC with 6/],
      [{ bounds: { min: "2000000000000000000000" } }, /below/], [{ bounds: { min: "1000000000000000000000" } }, /above/],
      [{ balance: "1" }, /below 5 NEAR/],
    ]) expect(checkChain({ ...okChain, ...patch }).join()).toMatch(msg);
  });
  it("after deploy: config must deep-equal, code must be the reviewed hash, totals zero and not stopped", () => {
    const totals = { total_escrow: "0", total_refund_due: "0", mandates: 0, registrations: 0, stopped: false };
    const good = { config: { ...cfg }, expectedConfig: cfg, codeHash: HASH, expectedHash: HASH, totals };
    expect(checkDeployed(good)).toEqual([]);
    expect(checkDeployed({ ...good, config: { ...cfg, max_mandates: 101 } })).toHaveLength(1);
    expect(checkDeployed({ ...good, codeHash: "x" })).toHaveLength(1);
    expect(checkDeployed({ ...good, totals: { ...totals, stopped: true } })).toHaveLength(1);
  });
  it("lock: any remaining key stops the publication", () => {
    expect(checkLocked([])).toEqual([]);
    expect(checkLocked([{ public_key: "ed25519:x" }])).toHaveLength(1);
  });
  it("refuses to run without a person at a terminal, or with a key in the environment", () => {
    const r = spawnSync(process.execPath, [resolve(import.meta.dirname, "deploy-gate.mjs"), "plan", "--gate", "g.near", "--code-hash", HASH], { encoding: "utf8", input: "", env: { PATH: process.env.PATH } });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/interactive terminal/);
  });
});

describe("mainnet scripts read final data (M8 author finding: near-api-js defaults to optimistic)", () => {
  it("every provider view call passes final finality in the parameter the method actually reads", async () => {
    const { readFileSync } = await import("node:fs");
    for (const f of ["deploy-gate.mjs", "../mainnet-proof/proof.mjs", "../mainnet-proof/agent-refusal.mjs"]) {
      const s = readFileSync(resolve(import.meta.dirname, f), "utf8");
      for (const m of s.matchAll(/provider\.(viewAccount|callFunction|viewAccessKeyList|viewAccessKey)\(\{[^)]*\}\)/g)) {
        const want = m[1] === "viewAccount" || m[1] === "callFunction" ? 'blockQuery: { finality: "final" }' : 'finalityQuery: { finality: "final" }';
        expect(m[0], `${f}: ${m[0]}`).toContain(want);
      }
    }
  });
});
