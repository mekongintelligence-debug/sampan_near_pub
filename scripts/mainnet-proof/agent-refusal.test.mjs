// The person-run mainnet refusal example: its pure checks, offline.
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { erc191Hash, evmAddress } from "../../packages/mandate/src/index.ts";
import { toChecksumEvm } from "../../packages/payments/src/index.ts";
import { buildProofMandate, signedFromSignature } from "./proof.mjs";
import { swappedPayeeOrder, isAnchoredPayeeRefusal, isPurchaseOnlyKey } from "./agent-refusal.mjs";

const sk = sha256(new TextEncoder().encode("refusal-test-only-key"));
const BUYER = toChecksumEvm(evmAddress(secp256k1.getPublicKey(sk, false)));
const r = buildProofMandate({ gate: "gate.sampan.near", buyer: BUYER, payee: "shop.near", item: "report-001", items: ["report-001", "report-002"], price: "1", nowMs: Date.UTC(2026, 10, 10), nonce: "ab".repeat(32), agent: "agent.sampan.near" });
const rec = secp256k1.sign(erc191Hash(r.message), sk, { prehash: false, format: "recovered", lowS: true });
const { verified } = signedFromSignature(r.mandate, "0x" + bytesToHex(new Uint8Array([...rec.subarray(1), 27 + rec[0]])));

describe("mainnet refusal example", () => {
  it("the agent mandate names the agent, two items and a 1 USDC budget", () => {
    expect(r.problems).toEqual([]);
    expect(verified.mandate).toMatchObject({ agent: "agent.sampan.near", items: ["report-001", "report-002"], max_amount: "1000000" });
    expect(buildProofMandate({ ...{ gate: "gate.sampan.near", buyer: BUYER, payee: "shop.near", item: "x", price: "1", nowMs: 0, nonce: "ab".repeat(32) }, agent: "shop.near" }).problems.join()).toMatch(/agent/);
  });
  it("the tricked order differs from the mandate only in the payee", () => {
    const o = JSON.parse(swappedPayeeOrder(verified, "attacker.near"));
    expect(o).toMatchObject({ mandate_hash: verified.mandateHash, item: "report-001", amount: "500000", payee: "attacker.near" });
    expect(() => swappedPayeeOrder(verified, "shop.near")).toThrow();
    expect(() => swappedPayeeOrder(verified, "gate.sampan.near")).toThrow();
  });
  it("only an anchored refusal naming R8 counts", () => {
    const ev = (ids) => ({ core: { rules: ["R1", "R8"].map((id) => ({ id, pass: !ids.includes(id) })) } });
    expect(isAnchoredPayeeRefusal({ decision: "refuse", anchored: true }, ev(["R8"]))).toBe(true);
    expect(isAnchoredPayeeRefusal({ decision: "refuse", anchored: false }, ev(["R8"]))).toBe(false);
    expect(isAnchoredPayeeRefusal({ decision: "release", anchored: true }, ev([]))).toBe(false);
    expect(isAnchoredPayeeRefusal({ decision: "refuse", anchored: true }, ev(["R1"]))).toBe(false);
  });
  it("refuses to run without a person at a terminal", () => {
    const p = spawnSync(process.execPath, [resolve(import.meta.dirname, "agent-refusal.mjs"), "prepare"], { encoding: "utf8", input: "", env: { PATH: process.env.PATH } });
    expect(p.status).toBe(1);
    expect(p.stderr).toMatch(/interactive terminal/);
  });
  it("M8-08: only a function-call key for the gate's purchase is accepted as the agent's key", () => {
    expect(isPurchaseOnlyKey({ FunctionCall: { receiver_id: "gate.sampan.near", method_names: ["purchase"], allowance: "1" } }, "gate.sampan.near")).toBe(true);
    expect(isPurchaseOnlyKey("FullAccess", "gate.sampan.near")).toBe(false);
    expect(isPurchaseOnlyKey({ FunctionCall: { receiver_id: "gate.sampan.near", method_names: [] } }, "gate.sampan.near")).toBe(false);
    expect(isPurchaseOnlyKey({ FunctionCall: { receiver_id: "gate.sampan.near", method_names: ["purchase", "refund"] } }, "gate.sampan.near")).toBe(false);
    expect(isPurchaseOnlyKey({ FunctionCall: { receiver_id: "other.near", method_names: ["purchase"] } }, "gate.sampan.near")).toBe(false);
  });
});
