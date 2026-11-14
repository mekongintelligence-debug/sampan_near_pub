// Receipt envelope: valid case built from the shared vectors, then one tampering per check.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { base58 } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { parseEnvelope, MAX_NOTE_CHARS, MAX_ENVELOPE_BYTES } from "./index.ts";
import { FormatError, canonicalize, hashHex } from "@sampan/mandate";

const DIR = resolve(import.meta.dirname, "../../../fixtures/vectors");
const vec = (rel: string) => JSON.parse(Buffer.from(JSON.parse(readFileSync(join(DIR, rel), "utf8")).input_b64, "base64").toString("utf8"));
const coreHashOf = (core: unknown) => Buffer.from(sha256(new TextEncoder().encode(canonicalize(core)))).toString("hex");
const tx = (label: string) => base58.encode(sha256(new TextEncoder().encode(label)));

function valid() {
  const core = vec("receipt_core/release.json");
  return {
    v: "sampan.receipt-envelope.v1",
    core,
    core_hash: coreHashOf(core),
    signed_mandate: vec("signed_mandate/nep413-valid.json"),
    order: vec("order/valid.json"),
    tx: { deposit: tx("deposit"), decision: tx("decision"), payout: tx("payout") },
    untrusted: { agent_note: "Bought report-001 as asked." },
  };
}
const bytes = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
const code = (o: unknown) => {
  try { parseEnvelope(typeof o === "string" ? new TextEncoder().encode(o) : bytes(o)); return "ok"; }
  catch (e) { if (e instanceof FormatError) return e.code; throw e; }
};

describe("receipt envelope", () => {
  it("accepts a consistent envelope and keeps the agent note as untrusted text", () => {
    const env = parseEnvelope(bytes(valid()));
    expect(env.core.decision).toBe("release");
    expect(env.agentNote).toBe("Bought report-001 as asked.");
    expect(env.tx.payout).toBe(tx("payout"));
  });

  it("accepts null deposit, payout and untrusted", () => {
    expect(code({ ...valid(), tx: { deposit: null, decision: tx("d"), payout: null }, untrusted: null })).toBe("ok");
  });

  it("rejects a core_hash that does not match the core", () => {
    expect(code({ ...valid(), core_hash: "0".repeat(64) })).toBe("inconsistent");
  });

  it("rejects a core whose mandate_hash is not the signed mandate's", () => {
    const e = valid(); e.core = { ...e.core, mandate_hash: "1".repeat(64) }; e.core_hash = coreHashOf(e.core);
    expect(code(e)).toBe("inconsistent");
  });

  it("rejects a core whose order_hash is not the order's", () => {
    const e = valid(); e.core = { ...e.core, order_hash: "2".repeat(64) }; e.core_hash = coreHashOf(e.core);
    expect(code(e)).toBe("inconsistent");
  });

  it("rejects an order that points at another mandate", () => {
    const e = valid(); e.order = { ...e.order, mandate_hash: "3".repeat(64) };
    expect(code(e)).toBe("inconsistent");
  });

  it("rejects a core for another gate or network", () => {
    const e = valid(); e.core = { ...e.core, gate: "other-gate.testnet" }; e.core_hash = coreHashOf(e.core);
    expect(code(e)).toBe("inconsistent");
    const n = valid(); n.core = { ...n.core, network: "mainnet" }; n.core_hash = coreHashOf(n.core);
    expect(code(n)).toBe("inconsistent");
  });

  it("rejects a tampered signed mandate", () => {
    const e = valid(); e.signed_mandate = { ...e.signed_mandate, mandate: { ...e.signed_mandate.mandate, payee: "attacker.testnet" } };
    expect(code(e)).toBe("bad_signature");
  });

  it("rejects malformed transaction hashes", () => {
    expect(code({ ...valid(), tx: { ...valid().tx, decision: "not-base58!" } })).toBe("schema");
    expect(code({ ...valid(), tx: { ...valid().tx, decision: base58.encode(new Uint8Array(31).fill(7)) } })).toBe("schema");
    expect(code({ ...valid(), tx: { ...valid().tx, payout: 5 } })).toBe("schema");
  });

  it("limits the untrusted note and accepts no other untrusted fields", () => {
    expect(code({ ...valid(), untrusted: { agent_note: "x".repeat(MAX_NOTE_CHARS + 1) } })).toBe("schema");
    expect(code({ ...valid(), untrusted: { agent_note: "x".repeat(MAX_NOTE_CHARS) } })).toBe("ok");
    expect(code({ ...valid(), untrusted: { agent_note: "x", html: "<b>" } })).toBe("schema");
  });

  it("rejects unknown fields, wrong version, numbers, deep nesting, size and bad JSON (M2-CR3)", () => {
    expect(code({ ...valid(), extra: true })).toBe("schema");
    expect(code({ ...valid(), v: "sampan.receipt-envelope.v2" })).toBe("schema");
    expect(code(JSON.stringify(valid()).replace('"untrusted":', '"untrusted":{"agent_note":"a","n":1},"x":'))).toBe("schema");
    expect(code(JSON.stringify({ ...valid(), untrusted: { agent_note: JSON.stringify([]) } }).replace('"untrusted"', '"deep":' + "[".repeat(40) + "]".repeat(40) + ',"untrusted"'))).toBe("invalid_json");
    expect(code(" ".repeat(MAX_ENVELOPE_BYTES + 1))).toBe("too_large");
    expect(code("{not json")).toBe("invalid_json");
    expect(() => parseEnvelope(new Uint8Array([0xff]))).toThrowError(/invalid_json/);
  });

  // M3-X1: refusals record what the gate actually holds (contracts/gate rules.rs).
  describe("observed values on refusals (M3-X1)", () => {
    type Rule = { id: string; pass: boolean };
    function refusal(failing: string[], observed: { amount: string; asset: string }, orderPatch: Record<string, string> = {}) {
      const e = valid();
      e.order = { ...e.order, ...orderPatch };
      const core = e.core as { rules: Rule[] } & Record<string, unknown>;
      e.core = {
        ...core,
        decision: "refuse",
        observed,
        order_hash: hashHex(canonicalize(e.order)),
        rules: core.rules.map((r) => ({ id: r.id, pass: !failing.includes(r.id) })),
      };
      e.core_hash = coreHashOf(e.core);
      return e;
    }
    const asset = "token.vectors-only.testnet";
    it("accepts an R7 refusal whose observed amount is the smaller escrow", () => {
      expect(code(refusal(["R7"], { amount: "1000000", asset }))).toBe("ok");
    });
    it("rejects an R7 refusal that claims the order amount or more (M3-09)", () => {
      expect(code(refusal(["R7"], { amount: "2500000", asset }))).toBe("inconsistent");
      expect(code(refusal(["R7"], { amount: "2500001", asset }))).toBe("inconsistent");
    });
    it("rejects a refusal with R7 passing but a different observed amount", () => {
      expect(code(refusal(["R9"], { amount: "1000000", asset }, { item: "report-999" }))).toBe("inconsistent");
    });
    it("accepts an R6 refusal observing the mandate's asset", () => {
      expect(code(refusal(["R6"], { amount: "2500000", asset }, { asset: "fake-usdc.testnet" }))).toBe("ok");
    });
    it("rejects an R6 refusal observing any other asset", () => {
      expect(code(refusal(["R6"], { amount: "2500000", asset: "fake-usdc.testnet" }, { asset: "fake-usdc.testnet" }))).toBe("inconsistent");
      expect(code(refusal(["R6"], { amount: "2500000", asset: "other.testnet" }, { asset: "fake-usdc.testnet" }))).toBe("inconsistent");
    });
    it("a release still needs the exact order amount and asset", () => {
      const e = valid();
      e.core = { ...e.core, observed: { amount: "1000000", asset } };
      e.core_hash = coreHashOf(e.core);
      expect(code(e)).toBe("inconsistent");
    });
  });
});
