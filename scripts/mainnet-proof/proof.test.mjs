// M5: the person-run first-purchase script's checks, offline (no network, no key).
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { erc191Hash, evmAddress } from "../../packages/mandate/src/index.ts";
import { toChecksumEvm } from "../../packages/payments/src/index.ts";
import { buildProofMandate, signedFromSignature, confirmationPhrase, checkGateReady, priceUnits, settlement, printable } from "./proof.mjs";
import { USDC, REVIEWED_CODE_HASH as R } from "../mainnet/deploy-gate.mjs";

const sk = sha256(new TextEncoder().encode("m5-proof-test-only-key"));
const lc = evmAddress(secp256k1.getPublicKey(sk, false));
const BUYER = toChecksumEvm(lc);
const base = { gate: "gate.sampan.near", buyer: BUYER, payee: "shop.near", item: "item-1", price: "1", nowMs: Date.UTC(2026, 10, 10), nonce: "ab".repeat(32) };
const sign = (message, key = sk) => {
  const rec = secp256k1.sign(erc191Hash(message), key, { prehash: false, format: "recovered", lowS: true });
  return "0x" + bytesToHex(new Uint8Array([...rec.subarray(1), 27 + rec[0]]));
};

describe("M5 mainnet proof: mandate and signature", () => {
  it("builds a direct-checkout mandate: exact price, own 0x refund account, 2-hour lifetime", () => {
    const r = buildProofMandate(base);
    expect(r.problems).toEqual([]);
    expect(r.mandate).toMatchObject({ network: "mainnet", agent: null, max_amount: "1000000", refund_to: lc, buyer: `evm:${lc}` });
    expect(BigInt(r.mandate.expiry_ns) / 1_000_000n - BigInt(base.nowMs)).toBe(2n * 3_600_000n);
  });
  it("P-1, P-2: refuses prices above 2 USDC, an unchecksummed buyer, testnet or implicit accounts, the gate as payee", () => {
    expect(priceUnits("2")).toBe(2_000_000n);
    for (const [k, v] of [["price", "2.000001"], ["price", "0"], ["price", "1.0000001"], ["buyer", lc], ["payee", "shop.testnet"], ["payee", "ab".repeat(32)], ["payee", "gate.sampan.near"], ["gate", "gate.testnet"], ["item", "Item 1"]]) {
      expect(buildProofMandate({ ...base, [k]: v }).problems.length, `${k}=${v}`).toBeGreaterThan(0);
    }
  });
  it("accepts only the buyer's signature over exactly the prepared mandate", () => {
    const r = buildProofMandate(base);
    expect(signedFromSignature(r.mandate, sign(r.message)).verified.mandateHash).toBe(r.mandateHash);
    const other = sha256(new TextEncoder().encode("someone-else"));
    expect(() => signedFromSignature(r.mandate, sign(r.message, other))).toThrow();
    expect(() => signedFromSignature({ ...r.mandate, payee: "attacker.near" }, sign(r.message))).toThrow();
    expect(() => signedFromSignature(r.mandate, "0x1234")).toThrow(/65-byte/);
  });
  it("P-3: the confirmation phrase binds amount, gate, refund address, mandate hash and deadline", () => {
    const p = confirmationPhrase({ amountIn: "1010000", gate: "gate.sampan.near", refundTo: BUYER, mandateHash: "cd".repeat(32), deadline: "2026-11-10T01:00:00Z" });
    for (const part of ["1010000", "gate.sampan.near", BUYER, "cdcdcdcdcdcd", "2026-11-10T01:00:00Z"]) expect(p).toContain(part);
  });
});

describe("M5 mainnet proof: the gate must be the reviewed, locked deployment", () => {
  const ok = { gateRecord: { gate: "gate.sampan.near", code_hash: R }, account: { code_hash: R }, keys: [], config: { network: "mainnet", token: USDC }, usdcStorage: { total: "1250000000000000000000" }, totals: { stopped: false } };
  it("control: reviewed, locked, registered, not stopped", () => expect(checkGateReady(ok)).toEqual([]));
  it("stops on other code, any key left, wrong token, no USDC registration, a stopped gate, a missing record", () => {
    for (const patch of [{ account: { code_hash: "X" } }, { keys: [{ public_key: "ed25519:x" }] }, { config: { network: "mainnet", token: "usdc.fake.near" } }, { usdcStorage: null }, { totals: { stopped: true } }, { gateRecord: {} }]) {
      expect(checkGateReady({ ...ok, ...patch }).length, JSON.stringify(patch)).toBeGreaterThan(0);
    }
  });
  it("refuses to run without a person at a terminal", () => {
    const r = spawnSync(process.execPath, [resolve(import.meta.dirname, "proof.mjs"), "prepare"], { encoding: "utf8", input: "", env: { PATH: process.env.PATH } });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/interactive terminal/);
  });
});

describe("M5 audit regressions (proof script)", () => {
  it("M5-06: the gate's USDC storage must be at least 0.00125 NEAR", () => {
    const ok = { gateRecord: { gate: "g.near", code_hash: R }, account: { code_hash: R }, keys: [], config: { network: "mainnet", token: USDC }, totals: { stopped: false } };
    expect(checkGateReady({ ...ok, usdcStorage: { total: "1250000000000000000000" } })).toEqual([]);
    expect(checkGateReady({ ...ok, usdcStorage: { total: "1" } }).join()).toMatch(/0.00125/);
  });
  it("M5-06: the person stops on any outcome but a released, paid order with nothing owed back", () => {
    const paid = { status: "SUCCESS", receipt: { decision: "release", payout: "Done" }, mandate: { refund_due: "0" } };
    expect(settlement(paid)).toEqual([]);
    for (const patch of [{ status: "REFUNDED" }, { status: "FAILED" }, { status: "INCOMPLETE_DEPOSIT" }, { receipt: null }, { receipt: { decision: "release", payout: "Failed" } }, { receipt: { decision: "release", payout: "Pending" } }, { mandate: { refund_due: "10000" } }]) {
      expect(settlement({ ...paid, ...patch }).length, JSON.stringify(patch)).toBeGreaterThan(0);
    }
  });
  it("M5-05: text from 1Click is printed without control or escape characters", () => {
    expect(printable("SUCCESS\u001b[1A\r0xbad")).toBe("SUCCESS?[1A?0xbad");
    expect(printable("x".repeat(500)).length).toBe(120);
  });
});

describe("runbook: smoke test before the lock", () => {
  it("--before-lock tolerates the deploy key, and only that", () => {
    const ok = { gateRecord: { gate: "g.near", code_hash: R }, account: { code_hash: R }, keys: [{ public_key: "ed25519:deploy" }], config: { network: "mainnet", token: USDC }, usdcStorage: { total: "1250000000000000000000" }, totals: { stopped: false } };
    expect(checkGateReady(ok).join()).toMatch(/access key/);
    expect(checkGateReady({ ...ok, beforeLock: true })).toEqual([]);
    expect(checkGateReady({ ...ok, beforeLock: true, account: { code_hash: "X" } }).length).toBeGreaterThan(0);
  });
});
