// Audit M5 (independent, fresh subagent): exploit tests for the Sampan relayer policy.
// Each "M5-NN" test asserts the REQUIRED behaviour, so it fails while its finding is open.
// Throwaway keys from fixed test seeds; no network; the registrar is an in-memory fake.
import { describe, it, expect } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalize, erc191Hash, evmAddress } from "@sampan/mandate";
import { checkMandate, handle, Limits, type Policy, type Registrar } from "./policy.ts";

const NOW = Date.UTC(2026, 10, 10, 12);
const HOUR = 3_600_000;
// As apps/relayer/src/server.ts builds it: maxLifetimeMs is the gate's max_lifetime_ns (24 h on mainnet).
const policy: Policy = {
  network: "testnet", gate: "gate-m3.sampan-trust-01.testnet", asset: "token.sampan-trust-01.testnet",
  payees: new Set(["payee2-m3.sampan-trust-01.testnet"]), maxPrice: 2_000_000n, maxLifetimeMs: 24 * HOUR, minLifetimeMs: 45 * 60_000,
};

/** A mandate exactly as the checkout widget builds it (EVM buyer, own 0x refund account), signed by `seed`. */
function evmSigned(seed: string, lifetimeMs = 2 * HOUR): string {
  const sk = sha256(new TextEncoder().encode(`audit-m5-relayer-${seed}`));
  const addr = evmAddress(secp256k1.getPublicKey(sk, false));
  const mandate = {
    v: "sampan.mandate.v1", network: "testnet", gate: policy.gate, buyer: `evm:${addr}`, agent: null, asset: policy.asset,
    max_amount: "1000000", payee: "payee2-m3.sampan-trust-01.testnet", items: ["report-002"],
    expiry_ns: String(BigInt(NOW + lifetimeMs) * 1_000_000n), nonce: bytesToHex(sha256(new TextEncoder().encode(seed))), refund_to: addr,
  };
  const rec = secp256k1.sign(erc191Hash(canonicalize(mandate)), sk, { prehash: false, format: "recovered", lowS: true });
  const signature = bytesToHex(new Uint8Array([...rec.subarray(1), 27 + rec[0]!]));
  return canonicalize({ v: "sampan.signed-mandate.v1", mandate, standard: "erc191", signature });
}

/** A gate with `max_mandates` = 10, as on mainnet; the relayer may use 9 (server.ts: max_mandates - 1). */
function fakeGate(): Registrar & { live: number } {
  const g = { live: 0, openMandates: async () => g.live, accountExists: async () => true, register: async () => { g.live++; return { registered: true }; } };
  return g;
}

describe("audit M5: the relayer's NEAR and the gate's mandate slots", () => {
  it("control: a mandate exactly as the widget builds it (2 h) is accepted", () => {
    expect(checkMandate(evmSigned("control"), policy, NOW).ok).toBe(true);
  });

  // The widget only ever produces 2-hour mandates (LIFETIME_MS). The relayer accepts anything up to the gate's
  // 24 h, so each free request holds a slot and the relayer's deposit twelve times longer than any checkout needs.
  it("M5-03 a lifetime far beyond what the checkout produces (12 h) is refused", () => {
    const c = checkMandate(evmSigned("long", 12 * HOUR), policy, NOW);
    expect(c.ok).toBe(false);
  });

  // The relayer pays every deposit. One client, within its hourly limit and at no cost, registers mandates
  // signed with throwaway keys until the relayer's share of the gate's cap is full. Every real buyer then gets
  // "busy" until those mandates expire, and the client can renew them.
  it("M5-03 one client cannot use up every slot the relayer may fill, so a real buyer can still register", async () => {
    const gate = fakeGate();
    const limits = new Limits(10, 9);
    for (let i = 0; i < 9; i++) {
      await handle({ signed_mandate: evmSigned(`squat-${i}`) }, "203.0.113.7", { policy, limits, registrar: gate, nowMs: NOW });
    }
    const buyer = await handle({ signed_mandate: evmSigned("real-buyer") }, "198.51.100.20", { policy, limits, registrar: gate, nowMs: NOW + 1000 });
    expect(buyer.body).toMatchObject({ registered: true });
  });
});
