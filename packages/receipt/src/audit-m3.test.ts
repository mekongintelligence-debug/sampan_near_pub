// Independent audit M3 (docs/audits/M3.md): the receipt checker against what the gate
// contract can and cannot anchor. "M3-09 ..." tests assert the REQUIRED behaviour and fail
// while finding M3-09 is open; "control ..." tests pass today.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { base58 } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { parseEnvelope } from "./index.ts";
import { FormatError, canonicalize, hashHex } from "@sampan/mandate";

const DIR = resolve(import.meta.dirname, "../../../fixtures/vectors");
const vec = (rel: string) => JSON.parse(Buffer.from(JSON.parse(readFileSync(join(DIR, rel), "utf8")).input_b64, "base64").toString("utf8"));
const coreHashOf = (core: unknown) => Buffer.from(sha256(new TextEncoder().encode(canonicalize(core)))).toString("hex");
const tx = (label: string) => base58.encode(sha256(new TextEncoder().encode(label)));

type Rule = { id: string; pass: boolean };
function envelope(failing: string[], observedAmount?: string, orderPatch: Record<string, string> = {}) {
  const core = vec("receipt_core/release.json") as Record<string, unknown> & { rules: Rule[]; observed: { amount: string; asset: string } };
  const order = { ...vec("order/valid.json"), ...orderPatch };
  const signed = vec("signed_mandate/nep413-valid.json");
  const c = {
    ...core,
    decision: failing.length ? "refuse" : "release",
    observed: { amount: observedAmount ?? order.amount, asset: signed.mandate.asset },
    order_hash: hashHex(canonicalize(order)),
    rules: core.rules.map((r) => ({ id: r.id, pass: !failing.includes(r.id) })),
  };
  return {
    v: "sampan.receipt-envelope.v1", core: c, core_hash: coreHashOf(c), signed_mandate: signed, order,
    tx: { deposit: null, decision: tx("decision"), payout: null }, untrusted: null,
  };
}
const code = (o: unknown) => {
  try { parseEnvelope(new TextEncoder().encode(JSON.stringify(o))); return "ok"; }
  catch (e) { if (e instanceof FormatError) return e.code; throw e; }
};

describe("audit M3: receipts the gate can anchor are accepted (controls)", () => {
  it("control: release, and refusals failing R3, R6, R8, R9 alone", () => {
    expect(code(envelope([]))).toBe("ok");
    expect(code(envelope(["R3"]))).toBe("ok");
    expect(code(envelope(["R6"], undefined, { asset: "fake-usdc.testnet" }))).toBe("ok");
    expect(code(envelope(["R8"], undefined, { payee: "x.testnet" }))).toBe("ok");
    expect(code(envelope(["R9"], undefined, { item: "report-404" }))).toBe("ok");
  });
  it("control: R7 refusal observing the smaller escrow, alone and with R3", () => {
    expect(code(envelope(["R7"], "1"))).toBe("ok");
    expect(code(envelope(["R3", "R7"], "2499999"))).toBe("ok");
  });
  it("control: a release or R7 pass with an observed amount other than the order's is rejected", () => {
    expect(code(envelope([], "2499999"))).toBe("inconsistent");
    expect(code(envelope(["R3"], "2499999"))).toBe("inconsistent");
  });
});

describe("audit M3: receipts the gate can never anchor (M3-09)", () => {
  // The gate refuses R1/R2 at funding (tokens returned) and R4/R5 without writing state
  // (lib.rs fund/decide), so no anchored receipt core ever has them false.
  it("M3-09 rejects a receipt core with R1, R2, R4 or R5 false", () => {
    for (const r of ["R1", "R2", "R4", "R5"]) expect(code(envelope([r])), r).toBe("inconsistent");
  });
  // R7 fails only when the order exceeds the escrow (escrow <= remaining budget is an
  // invariant), and then the gate observes the whole, strictly smaller escrow.
  it("M3-09 rejects an R7 refusal whose observed amount equals the order amount", () => {
    expect(code(envelope(["R7"]))).toBe("inconsistent");
  });
});
