// M5 abuse cases for the Sampan relayer: it must only pay deposits for mandates the checkout
// itself produces, within rate and open-mandate limits, and answer with fixed codes only.
import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { base58 } from "@scure/base";
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalize, nep413Hash } from "@sampan/mandate";
import { checkMandate, handle, Limits, MAX_BODY_BYTES, type Policy, type Registrar } from "./policy.ts";

const NOW = Date.UTC(2026, 10, 10, 12);
const HOUR = 3_600_000;
const sk = new Uint8Array(32).fill(5);
const policy: Policy = {
  network: "testnet", gate: "gate-m3.sampan-trust-01.testnet", asset: "token.sampan-trust-01.testnet",
  payees: new Set(["payee2-m3.sampan-trust-01.testnet"]), maxPrice: 2_000_000n, maxLifetimeMs: 24 * HOUR, minLifetimeMs: 45 * 60_000,
};
function signed(over: Record<string, unknown> = {}, nonce = "ab".repeat(32)): string {
  const mandate = {
    v: "sampan.mandate.v1", network: "testnet", gate: policy.gate, buyer: `near:ed25519:${base58.encode(ed25519.getPublicKey(sk))}`,
    agent: null, asset: policy.asset, max_amount: "1000000", payee: "payee2-m3.sampan-trust-01.testnet", items: ["report-002"],
    expiry_ns: String(BigInt(NOW + 2 * HOUR) * 1_000_000n), nonce, refund_to: "buyer.sampan-trust-01.testnet", ...over,
  };
  const sig = ed25519.sign(nep413Hash(canonicalize(mandate), mandate.nonce as string, mandate.gate as string), sk);
  return canonicalize({ v: "sampan.signed-mandate.v1", mandate, standard: "nep413", signature: bytesToHex(sig) });
}
const reason = (text: unknown) => { const c = checkMandate(text, policy, NOW); return c.ok ? "ok" : c.reason; };

describe("relayer policy: pays only for mandates the checkout produces", () => {
  it("control: a direct-checkout mandate for a known shop is accepted", () => {
    expect(reason(signed())).toBe("ok");
  });
  it("refuses tampered, oversized or non-string input", () => {
    expect(reason(signed().replace('"1000000"', '"9000000"'))).toBe("invalid");
    expect(reason("x".repeat(MAX_BODY_BYTES + 1))).toBe("invalid");
    expect(reason({ mandate: {} })).toBe("invalid");
    expect(reason(undefined)).toBe("invalid");
  });
  it("refuses another network, gate or asset", () => {
    expect(reason(signed({ network: "mainnet" }))).toBe("wrong_network");
    expect(reason(signed({ gate: "other-gate.testnet" }))).toBe("wrong_gate");
    expect(reason(signed({ asset: "fake-usdc.testnet" }))).toBe("wrong_asset");
  });
  it("refuses agent mandates, unknown payees and prices above the checkout's", () => {
    expect(reason(signed({ agent: "agent.testnet" }))).toBe("not_direct_checkout");
    expect(reason(signed({ payee: "attacker.testnet" }))).toBe("unknown_payee");
    expect(reason(signed({ max_amount: "2000001" }))).toBe("price_too_high");
  });
  it("refuses the gate itself as refund account or payee (A1R re-verification)", () => {
    expect(reason(signed({ refund_to: policy.gate }))).toBe("refund_account");
    expect(reason(signed({ payee: policy.gate }))).toBe("unknown_payee");
  });
  it("refuses lifetimes the checkout never produces (slot squatting, late delivery)", () => {
    expect(reason(signed({ expiry_ns: String(BigInt(NOW + 24 * HOUR + 1) * 1_000_000n) }))).toBe("lifetime_too_long");
    expect(reason(signed({ expiry_ns: String(BigInt(NOW + 10 * 60_000) * 1_000_000n) }))).toBe("lifetime_too_short");
  });
});

describe("relayer limits and answers", () => {
  const registrar = (open = 0, result: { registered: boolean; reason?: string } = { registered: true }): Registrar & { calls: number } => {
    const r = { calls: 0, openMandates: async () => open + r.calls, accountExists: async (a: string) => a !== "missing.testnet", register: async () => { r.calls++; await new Promise((s) => setTimeout(s, 5)); return result; } };
    return r;
  };
  it("rate-limits each client per hour, and recovers after the hour", async () => {
    const limits = new Limits(2, 8);
    const reg = registrar();
    const ask = (n: number, t = NOW) => handle({ signed_mandate: signed({}, String(n).padStart(2, "0").repeat(32)) }, "1.2.3.4", { policy, limits, registrar: reg, nowMs: t });
    expect((await ask(10)).status).toBe(200);
    expect((await ask(11)).status).toBe(200);
    expect((await ask(12)).body.reason).toBe("rate_limited");
    expect(reg.calls).toBe(2);
    // Recovery after the hour (the per-client hold of M5-03 is tested separately).
    expect(limits.allow("1.2.3.4", NOW + HOUR + 1)).toBe(true);
  });
  it("never fills the gate's open-mandate cap", async () => {
    const reg = registrar(8);
    const r = await handle({ signed_mandate: signed() }, "c", { policy, limits: new Limits(10, 8), registrar: reg, nowMs: NOW });
    expect(r.body.reason).toBe("busy");
    expect(reg.calls).toBe(0);
  });
  it("a mandate someone else registered first is still registered (front-running costs the buyer nothing)", async () => {
    const r = await handle({ signed_mandate: signed() }, "c", { policy, limits: new Limits(10, 8), registrar: registrar(0, { registered: false, reason: "already_registered" }), nowMs: NOW });
    expect(r).toMatchObject({ status: 200, body: { registered: true } });
  });
  it("passes on only fixed reason codes from the gate", async () => {
    const r = await handle({ signed_mandate: signed() }, "c", { policy, limits: new Limits(10, 8), registrar: registrar(0, { registered: false, reason: "<img src=x onerror=alert(1)>" }), nowMs: NOW });
    expect(r.body.reason).toBe("refused");
  });
  it("a refused mandate never reaches the gate", async () => {
    const reg = registrar();
    await handle({ signed_mandate: signed({ payee: "attacker.testnet" }) }, "c", { policy, limits: new Limits(10, 8), registrar: reg, nowMs: NOW });
    expect(reg.calls).toBe(0);
  });

  it("M5-CR2: a refund account that does not exist on NEAR is refused before any deposit", async () => {
    const reg = registrar();
    const r = await handle({ signed_mandate: signed({ refund_to: "missing.testnet" }) }, "c", { policy, limits: new Limits(10, 8), registrar: reg, nowMs: NOW });
    expect(r.body.reason).toBe("refund_account_missing");
    expect(reg.calls).toBe(0);
  });
  it("M5-CR4: concurrent requests cannot together fill the gate's cap", async () => {
    const reg = registrar(6);
    const limits = new Limits(100, 8);
    const rs = await Promise.all(Array.from({ length: 6 }, (_, i) => handle({ signed_mandate: signed({}, String(20 + i).repeat(32)) }, `c${i}`, { policy, limits, registrar: reg, nowMs: NOW })));
    expect(reg.calls).toBe(2);
    expect(rs.filter((r) => r.body.reason === "busy")).toHaveLength(4);
  });
  it("M5-CR5: a full client table never resets anyone's count", () => {
    const limits = new Limits(1, 8);
    expect(limits.allow("main", NOW)).toBe(true);
    for (let i = 0; i < 10_000; i++) limits.allow(`x${i}`, NOW);
    expect(limits.allow("main", NOW + 1)).toBe(false);
    expect(limits.allow("new-client", NOW + 2)).toBe(false);
    expect(limits.allow("new-client", NOW + 3_600_001 + 1)).toBe(true);
  });
  it("M5-03: the sweeper returns expired mandates for closing, once the gate has closed them they are dropped", async () => {
    const { Sweeper } = await import("./policy.ts");
    const sw = new Sweeper();
    sw.add("a", NOW + HOUR);
    sw.add("b", NOW + 2 * HOUR);
    expect(sw.due(NOW + HOUR)).toEqual([]);
    expect(sw.due(NOW + HOUR + 60_000)).toEqual(["a"]);
    sw.done("a");
    expect(sw.due(NOW + 3 * HOUR)).toEqual(["b"]);
  });
});
