// The checker lists a mainnet gate only after mainnet shows it is the reviewed, locked, USDC gate.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { checkListable, firstEmptyHeight, withMainnetGate } from "./add-known-gate.mjs";
import { REVIEWED_CODE_HASH, USDC } from "./deploy-gate.mjs";

const ok = { account: { code_hash: REVIEWED_CODE_HASH }, keys: [], config: { network: "mainnet", token: USDC }, totals: { stopped: false } };
describe("add-known-gate", () => {
  it("lists only the reviewed, locked, USDC gate", () => {
    expect(checkListable(ok)).toEqual([]);
    for (const patch of [{ account: { code_hash: "X" } }, { keys: [{ public_key: "ed25519:x" }] }, { config: { network: "mainnet", token: "usdc.fake.near" } }, { totals: { stopped: true } }, { keys: undefined }]) {
      expect(checkListable({ ...ok, ...patch }).length, JSON.stringify(patch)).toBeGreaterThan(0);
    }
  });
  it("adds exactly one mainnet entry with the reviewed hash and native USDC, once", () => {
    const src = readFileSync(resolve(import.meta.dirname, "../../apps/checker/src/gates.ts"), "utf8");
    const out = withMainnetGate(src, "gate.sampantrust.near", 123456789);
    expect(out).toContain('account: "gate.sampantrust.near"');
    expect(out).toContain(REVIEWED_CODE_HASH);
    expect(out).toContain(USDC);
    expect(out).toContain("lockedAtBlock: 123456789");
    expect(withMainnetGate(out, "gate.sampantrust.near", 123456789)).toBe(out);
    expect(() => withMainnetGate(src, "gate.testnet", 1)).toThrow();
    expect(() => withMainnetGate(src, "gate.sampantrust.near")).toThrow(/lock block/);
  });

  // A2F-02: keys deleted in steps must not make the recorded lock height too early.
  it("A2F-02 the lock height is where the key list becomes empty, not the last receipt's block", async () => {
    const calls = [];
    for (const [emptyFrom, last] of [[1000, 1000], [990, 1000], [500, 1000], [2, 1000], [1000, 1001]]) {
      calls.length = 0;
      const h = await firstEmptyHeight(async (x) => { calls.push(x); return x >= emptyFrom; }, last);
      expect(h, `emptyFrom ${emptyFrom}`).toBe(emptyFrom);
    }
  });
  it("A2F-02 an RPC that cannot answer for old blocks stops the script", async () => {
    await expect(firstEmptyHeight(async (x) => { if (x < 1000) throw new Error("not archival"); return true; }, 1000)).rejects.toThrow(/archival/);
  });
  it("A2F-02 a non-empty key list at the lock block is refused", async () => {
    await expect(firstEmptyHeight(async () => false, 1000)).rejects.toThrow(/not empty/);
  });
});
