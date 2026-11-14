// Independent audit of M2 (docs/audits/M2.md): exploit tests. Each test asserts the behaviour
// docs/FORMATS.md or docs/SECURITY.md requires; a failing test is an open finding. Signed-mandate
// inputs are byte-identical to those in crates/formats/tests/audit_m2.rs.
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { base58 } from "@scure/base";
import { parseMandate, verifySignedMandate, parseCanonical, canonicalize, toBytes, FormatError, nep413Hash, MAX_DOC_BYTES } from "./index.ts";
import { parseEnvelope } from "../../receipt/src/index.ts";

const ROOT = resolve(import.meta.dirname, "../../..");
const VEC = join(ROOT, "fixtures/vectors");
const b64 = (s: string) => new Uint8Array(Buffer.from(s, "base64"));
const code = (f: () => unknown): string => {
  try { f(); return "ok"; } catch (e) { if (e instanceof FormatError) return e.code; throw e; }
};
const sm = (s: string) => code(() => verifySignedMandate(b64(s)));

const X = {
  "F1_FORGED": "eyJtYW5kYXRlIjp7ImFnZW50IjoiYWdlbnQuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJhc3NldCI6InRva2VuLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYnV5ZXIiOiJuZWFyOmVkMjU1MTk6NHVRZVZqNXRxVmlRaDd5V1dHU3R2a0VHMVptaHg2dWFzSnRXQ0p6aW9oWiIsImV4cGlyeV9ucyI6IjE3OTQ4NzM2MDAwMDAwMDAwMDAiLCJnYXRlIjoiZ2F0ZS5zYW1wYW4tdHJ1c3QtMDEudGVzdG5ldCIsIml0ZW1zIjpbInJlcG9ydC0wMDEiXSwibWF4X2Ftb3VudCI6IjUwMDAwMDAiLCJuZXR3b3JrIjoidGVzdG5ldCIsIm5vbmNlIjoiZDExOTg0NmI0M2M5YmM3YWRmODEyNDNiNWZlNTA5NjdjMGYwZmFkNDU2Y2Y1MDA0YWIxMjBmNmE5ZWMxYWY5ZCIsInBheWVlIjoiYXR0YWNrZXIudGVzdG5ldCIsInJlZnVuZF90byI6ImJ1eWVyLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwidiI6InNhbXBhbi5tYW5kYXRlLnYxIn0sInNpZ25hdHVyZSI6IjU4NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjYwMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwic3RhbmRhcmQiOiJuZXA0MTMiLCJ2Ijoic2FtcGFuLnNpZ25lZC1tYW5kYXRlLnYxIn0=",
  "F1_MANDATE_K0": "eyJhZ2VudCI6ImFnZW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYXNzZXQiOiJ0b2tlbi5zYW1wYW4tdHJ1c3QtMDEudGVzdG5ldCIsImJ1eWVyIjoibmVhcjplZDI1NTE5OjR1UWVWajV0cVZpUWg3eVdXR1N0dmtFRzFabWh4NnVhc0p0V0NKemlvaFoiLCJleHBpcnlfbnMiOiIxNzk0ODczNjAwMDAwMDAwMDAwIiwiZ2F0ZSI6ImdhdGUuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJpdGVtcyI6WyJyZXBvcnQtMDAxIl0sIm1heF9hbW91bnQiOiI1MDAwMDAwIiwibmV0d29yayI6InRlc3RuZXQiLCJub25jZSI6ImQxMTk4NDZiNDNjOWJjN2FkZjgxMjQzYjVmZTUwOTY3YzBmMGZhZDQ1NmNmNTAwNGFiMTIwZjZhOWVjMWFmOWQiLCJwYXllZSI6ImF0dGFja2VyLnRlc3RuZXQiLCJyZWZ1bmRfdG8iOiJidXllci5zYW1wYW4tdHJ1c3QtMDEudGVzdG5ldCIsInYiOiJzYW1wYW4ubWFuZGF0ZS52MSJ9",
  "F1_MANDATE_K1": "eyJhZ2VudCI6ImFnZW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYXNzZXQiOiJ0b2tlbi5zYW1wYW4tdHJ1c3QtMDEudGVzdG5ldCIsImJ1eWVyIjoibmVhcjplZDI1NTE5Okd4OWRETnh6cEFMQ293VnVaYjdwQmNlQkxKdWdMQThzUGE2VEpEWHJwZmdpIiwiZXhwaXJ5X25zIjoiMTc5NDg3MzYwMDAwMDAwMDAwMCIsImdhdGUiOiJnYXRlLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiaXRlbXMiOlsicmVwb3J0LTAwMSJdLCJtYXhfYW1vdW50IjoiNTAwMDAwMCIsIm5ldHdvcmsiOiJ0ZXN0bmV0Iiwibm9uY2UiOiJkMTE5ODQ2YjQzYzliYzdhZGY4MTI0M2I1ZmU1MDk2N2MwZjBmYWQ0NTZjZjUwMDRhYjEyMGY2YTllYzFhZjlkIiwicGF5ZWUiOiJtZXJjaGFudC5zYW1wYW4tdHJ1c3QtMDEudGVzdG5ldCIsInJlZnVuZF90byI6ImJ1eWVyLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwidiI6InNhbXBhbi5tYW5kYXRlLnYxIn0=",
  "F1_R_NEG_ZERO": "eyJtYW5kYXRlIjp7ImFnZW50IjoiYWdlbnQuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJhc3NldCI6InRva2VuLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYnV5ZXIiOiJuZWFyOmVkMjU1MTk6RlZYV2lxamdLTDRhRjI4Y2RIOFZ6Z3RBWGhZeHlGU3J2bmVrRm5qRVNXQ1giLCJleHBpcnlfbnMiOiIxNzk0ODczNjAwMDAwMDAwMDAwIiwiZ2F0ZSI6ImdhdGUuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJpdGVtcyI6WyJyZXBvcnQtMDAxIl0sIm1heF9hbW91bnQiOiI1MDAwMDAwIiwibmV0d29yayI6InRlc3RuZXQiLCJub25jZSI6ImQxMTk4NDZiNDNjOWJjN2FkZjgxMjQzYjVmZTUwOTY3YzBmMGZhZDQ1NmNmNTAwNGFiMTIwZjZhOWVjMWFmOWQiLCJwYXllZSI6Im1lcmNoYW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwicmVmdW5kX3RvIjoiYnV5ZXIuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJ2Ijoic2FtcGFuLm1hbmRhdGUudjEifSwic2lnbmF0dXJlIjoiMDEwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA4MDAxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJzdGFuZGFyZCI6Im5lcDQxMyIsInYiOiJzYW1wYW4uc2lnbmVkLW1hbmRhdGUudjEifQ==",
  "CONTROL_VALID": "eyJtYW5kYXRlIjp7ImFnZW50IjoiYWdlbnQuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJhc3NldCI6InRva2VuLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYnV5ZXIiOiJuZWFyOmVkMjU1MTk6RlZYV2lxamdLTDRhRjI4Y2RIOFZ6Z3RBWGhZeHlGU3J2bmVrRm5qRVNXQ1giLCJleHBpcnlfbnMiOiIxNzk0ODczNjAwMDAwMDAwMDAwIiwiZ2F0ZSI6ImdhdGUuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJpdGVtcyI6WyJyZXBvcnQtMDAxIl0sIm1heF9hbW91bnQiOiI1MDAwMDAwIiwibmV0d29yayI6InRlc3RuZXQiLCJub25jZSI6ImQxMTk4NDZiNDNjOWJjN2FkZjgxMjQzYjVmZTUwOTY3YzBmMGZhZDQ1NmNmNTAwNGFiMTIwZjZhOWVjMWFmOWQiLCJwYXllZSI6Im1lcmNoYW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwicmVmdW5kX3RvIjoiYnV5ZXIuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJ2Ijoic2FtcGFuLm1hbmRhdGUudjEifSwic2lnbmF0dXJlIjoiYjA5NGU4YWZlNzA1YzIwMmVjNzk2NDBkZTRjM2QzNDQ0YmEwYzVlYjJmZGY2NzUxNGNlNTE4OGNmZjI2ZWYxNjBkNzFhNzgwZWM1NjJlNjYwY2MxNTE3NmVkMDFkMTc1YmMzZjQwMDBlZjliNDc2YjI3ZDRjYjAxZDQwZGUwMGIiLCJzdGFuZGFyZCI6Im5lcDQxMyIsInYiOiJzYW1wYW4uc2lnbmVkLW1hbmRhdGUudjEifQ==",
  "F2_MIXED_R": "eyJtYW5kYXRlIjp7ImFnZW50IjoiYWdlbnQuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJhc3NldCI6InRva2VuLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYnV5ZXIiOiJuZWFyOmVkMjU1MTk6RlZYV2lxamdLTDRhRjI4Y2RIOFZ6Z3RBWGhZeHlGU3J2bmVrRm5qRVNXQ1giLCJleHBpcnlfbnMiOiIxNzk0ODczNjAwMDAwMDAwMDAwIiwiZ2F0ZSI6ImdhdGUuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJpdGVtcyI6WyJyZXBvcnQtMDAxIl0sIm1heF9hbW91bnQiOiI1MDAwMDAwIiwibmV0d29yayI6InRlc3RuZXQiLCJub25jZSI6ImQxMTk4NDZiNDNjOWJjN2FkZjgxMjQzYjVmZTUwOTY3YzBmMGZhZDQ1NmNmNTAwNGFiMTIwZjZhOWVjMWFmOWQiLCJwYXllZSI6Im1lcmNoYW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwicmVmdW5kX3RvIjoiYnV5ZXIuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJ2Ijoic2FtcGFuLm1hbmRhdGUudjEifSwic2lnbmF0dXJlIjoiNzA2M2VhMzNmNGE5OWNmMGE5NGVhOTA1YTAzN2NjMjM2ZjM0OWU3NTFmMTAyOTQzMDZlMGFkMDZlYjFhMWQwYWIwOWQ0ZmE5ZDU3NjM1MGE1ZTE4MzAyODM2ZWU5NTMyZTA5OThjYjZiMWExZmJlMzU5ZmZhOGJiNzAyMTdhMDgiLCJzdGFuZGFyZCI6Im5lcDQxMyIsInYiOiJzYW1wYW4uc2lnbmVkLW1hbmRhdGUudjEifQ==",
  "F2_MIXED_A": "eyJtYW5kYXRlIjp7ImFnZW50IjoiYWdlbnQuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJhc3NldCI6InRva2VuLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYnV5ZXIiOiJuZWFyOmVkMjU1MTk6MkU0QTc2NWZ0WnNvTjhHZTlqbVUxenhpeDJRODh0SkNyckNqcjd2NTc4bmYiLCJleHBpcnlfbnMiOiIxNzk0ODczNjAwMDAwMDAwMDAwIiwiZ2F0ZSI6ImdhdGUuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJpdGVtcyI6WyJyZXBvcnQtMDAxIl0sIm1heF9hbW91bnQiOiI1MDAwMDAwIiwibmV0d29yayI6InRlc3RuZXQiLCJub25jZSI6ImM2MzljMmU5ZjQ2NmUwMjA2YWRiYjQ0ZWIxYTgyYTY2Y2M0NDE2NjU2YjRlYjhkYTJkYjhhNjg0OTc0YWRmNmQiLCJwYXllZSI6Im1lcmNoYW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwicmVmdW5kX3RvIjoiYnV5ZXIuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJ2Ijoic2FtcGFuLm1hbmRhdGUudjEifSwic2lnbmF0dXJlIjoiNGRlMzZmZTM0MGZjMjNlNDFlYTlmMTA5NTg5ZDQ2OWJkZmMzYjJjMTc0OTdhMzhjNTIzNjNiODc0MzE3NTA4ZTY4NzY4YTZlMDg3MWIxNzBkMWYzNmRiNjM0NmFmNjVkZWNiZTAyZDFjMTMxNzgyMzVlOTFjYTNlMTExYWM4MDQiLCJzdGFuZGFyZCI6Im5lcDQxMyIsInYiOiJzYW1wYW4uc2lnbmVkLW1hbmRhdGUudjEifQ=="
} as const;

describe("audit M2: harness sanity", () => {
  it("an honest NEP-413 signature over the same mandate verifies (tests below are not vacuous)", () => {
    expect(sm(X.CONTROL_VALID)).toBe("ok");
  });
});

describe("M2-01: x = 0 encodings with the sign bit set pass the ed25519 guard", () => {
  it("M2-01 forged signature under the negative-zero identity key is a schema error (TS: bad_signature, Rust: ok)", () => {
    expect(sm(X.F1_FORGED)).toBe("schema");
  });
  it("M2-01 buyer key 01 00..00 80 (identity, sign bit set) is a schema error", () => {
    expect(code(() => parseMandate(b64(X.F1_MANDATE_K0)))).toBe("schema");
  });
  it("M2-01 buyer key ec ff..ff ff (order-2 point, sign bit set) is a schema error", () => {
    expect(code(() => parseMandate(b64(X.F1_MANDATE_K1)))).toBe("schema");
  });
  it("M2-01 R = 01 00..00 80 is bad_signature_encoding", () => {
    expect(sm(X.F1_R_NEG_ZERO)).toBe("bad_signature_encoding");
  });
});

describe("M2-02: TypeScript accepts ed25519 signatures that NEAR's host rejects", () => {
  // noble checks the cofactored equation [8](R + kA - SB) = 0; ed25519-dalek `verify` (NEAR host)
  // checks R == SB - kA exactly. The guard does not reject torsion components.
  it("M2-02 mixed-order R (R = rB + T8, S = r + k a) is rejected, as by the contract", () => {
    expect(sm(X.F2_MIXED_R)).not.toBe("ok");
  });
  it("M2-02 mixed-order buyer key (A = aB + T8) signature is rejected, as by the contract", () => {
    expect(sm(X.F2_MIXED_A)).not.toBe("ok");
  });
});

// ---- envelope --------------------------------------------------------------------------------
const vec = (rel: string) => JSON.parse(Buffer.from(JSON.parse(readFileSync(join(VEC, rel), "utf8")).input_b64, "base64").toString("utf8"));
const hashOf = (o: unknown) => bytesToHex(sha256(toBytes(canonicalize(o))));
const tx = (label: string) => base58.encode(sha256(toBytes(label)));
function envelopeWith(orderOver: Record<string, string>, observedOver: Record<string, string> = {}) {
  const signed = vec("signed_mandate/nep413-valid.json");
  const order = { ...vec("order/valid.json"), ...orderOver };
  const core = { ...vec("receipt_core/release.json") };
  core.order_hash = hashOf(order);
  core.observed = { amount: order.amount, asset: order.asset, ...observedOver };
  return {
    v: "sampan.receipt-envelope.v1", core, core_hash: hashOf(core), signed_mandate: signed, order,
    tx: { deposit: tx("deposit"), decision: tx("decision"), payout: tx("payout") }, untrusted: null,
  };
}
const env = (o: unknown) => code(() => parseEnvelope(toBytes(JSON.stringify(o))));

describe("M2-03: a release envelope whose order breaks the signed mandate is accepted", () => {
  it("control: the consistent envelope is accepted", () => {
    expect(env(envelopeWith({}))).toBe("ok");
  });
  it("M2-03 release paid to a payee other than the mandate's payee is inconsistent", () => {
    expect(env(envelopeWith({ payee: "attacker.testnet" }))).toBe("inconsistent");
  });
  it("M2-03 release above the mandate's max_amount is inconsistent", () => {
    expect(env(envelopeWith({ amount: "9000000000" }))).toBe("inconsistent");
  });
  it("M2-03 release in another asset is inconsistent", () => {
    expect(env(envelopeWith({ asset: "fake-usdc.testnet" }))).toBe("inconsistent");
  });
  it("M2-03 release for an item not in the mandate is inconsistent", () => {
    expect(env(envelopeWith({ item: "report-999" }))).toBe("inconsistent");
  });
  it("M2-03 observed amount different from the order amount is inconsistent", () => {
    expect(env(envelopeWith({}, { amount: "1" }))).toBe("inconsistent");
  });
});

// ---- canonical parser ------------------------------------------------------------------------
describe("M2-06: error code differs from Rust when a duplicate key hides an invalid value", () => {
  it("M2-06 lone surrogate in an overwritten duplicate is invalid_json (Rust: invalid_json, TS: not_canonical)", () => {
    expect(code(() => parseCanonical(toBytes('{"a":"\\ud800","a":"x"}'), MAX_DOC_BYTES))).toBe("invalid_json");
  });
  it("M2-06 nesting deeper than serde_json's limit in an overwritten duplicate is invalid_json", () => {
    const doc = `{"a":${"[".repeat(130)}${"]".repeat(130)},"a":null}`;
    expect(code(() => parseCanonical(toBytes(doc), MAX_DOC_BYTES))).toBe("invalid_json");
  });
});

// ---- vectors -----------------------------------------------------------------------------------
const vectorFiles = () => readdirSync(VEC, { withFileTypes: true }).filter((d) => d.isDirectory())
  .flatMap((d) => readdirSync(join(VEC, d.name)).filter((f) => f.endsWith(".json")).map((f) => `${d.name}/${f}`));

describe("M2-04: vectors can be removed or edited together with the manifest without any test failing", () => {
  it("M2-04 the TypeScript suite's vector-count floor is not below the frozen vector count", () => {
    const src = readFileSync(join(ROOT, "packages/mandate/src/vectors.test.ts"), "utf8");
    const floor = Number(/vectors\.length\)\.toBeGreaterThanOrEqual\((\d+)\)/.exec(src)?.[1]);
    expect(floor).toBeGreaterThanOrEqual(vectorFiles().length);
  });
  it("M2-04 the Rust suite checks the manifest too", () => {
    expect(readFileSync(join(ROOT, "crates/formats/tests/vectors.rs"), "utf8")).toMatch(/MANIFEST\.sha256/);
  });
  it("M2-04 make check runs the generator drift check (scripts/gen-vectors.ts)", () => {
    expect(readFileSync(join(ROOT, "Makefile"), "utf8")).toMatch(/gen-vectors/);
  });
});

describe("M2-05: the vector signing keys are public", () => {
  // Author's note (lead decision, 5 Nov 2026, option a): the seeds stay public so the vectors
  // are reproducible, and every vector that verifies uses the never-deployed namespace
  // *.vectors-only.testnet. Only rejected attack inputs (audit M2-01/02) name planned accounts.
  it("M2-05 no accepted vector names a real or planned account; generator uses vectors-only names", () => {
    for (const f of vectorFiles()) {
      const v = JSON.parse(readFileSync(join(VEC, f), "utf8"));
      const text = Buffer.from(v.input_b64, "base64").toString("utf8");
      if (v.expect.ok) expect(text, f).not.toMatch(/sampan-trust|\.near"/);
    }
    const gen = readFileSync(join(ROOT, "scripts/gen-vectors.ts"), "utf8");
    expect(gen).not.toMatch(/sampan-trust-01/);
    expect(gen).toMatch(/vectors-only\.testnet/);
  });
});

describe("M2-07, M2-08: envelope input handling", () => {
  it("M2-07 an envelope with a UTF-8 BOM is rejected like every other document", () => {
    const bytes = toBytes(JSON.stringify(envelopeWith({})));
    expect(code(() => parseEnvelope(new Uint8Array([0xef, 0xbb, 0xbf, ...bytes])))).toBe("invalid_json");
  });
  it("M2-08 agent_note with bidi override, NUL or a lone surrogate is rejected", () => {
    for (const note of ["Paid ‮eeyap‬", "a\u0000b"]) {
      expect(env({ ...envelopeWith({}), untrusted: { agent_note: note } }), JSON.stringify(note)).toBe("schema");
    }
    // Author's note (fix of M2-06/M2-08): an escaped lone surrogate is now rejected by the shared
    // pre-scan as invalid_json, the same rule as every other document, before the note is read.
    expect(env({ ...envelopeWith({}), untrusted: { agent_note: "\ud800" } })).toBe("invalid_json");
  });
});

describe("M2-09: docs/SECURITY.md section 6 (M2) edge cases without a shared vector", () => {
  const inputs = vectorFiles().map((f) => {
    const v = JSON.parse(readFileSync(join(VEC, f), "utf8"));
    return { kind: v.kind as string, text: Buffer.from(v.input_b64, "base64").toString("utf8") };
  });
  it("M2-09 empty object", () => {
    expect(inputs.some((v) => v.text === "{}")).toBe(true);
  });
  it("M2-09 NFD (decomposed) string", () => {
    expect(inputs.some((v) => v.text.normalize("NFC") !== v.text)).toBe(true);
  });
  it("M2-09 EVM-style address (0x + 40 hex) in an account field", () => {
    expect(inputs.some((v) => /"(payee|gate|asset|agent|refund_to)":"0x[0-9a-f]{40}"/.test(v.text))).toBe(true);
  });
  it("M2-09 signature over a different format version", () => {
    // Author's note: the vector presents a v1 mandate with a signature made over a v0 mandate
    // (the attack), so its text contains only v1; check for that vector by name instead.
    expect(vectorFiles()).toContain("signed_mandate/nep413-signed-other-version.json");
  });
});

describe("M2-10: make fuzz is not cargo-fuzz (docs/SECURITY.md 5)", () => {
  it("M2-10 the fuzz target runs cargo-fuzz targets", () => {
    // Author's note: the nightly toolchain is pinned by date (cargo +nightly-YYYY-MM-DD fuzz).
    expect(readFileSync(join(ROOT, "Makefile"), "utf8")).toMatch(/cargo\s+(\+nightly[-\d]*\s+)?fuzz run/);
  });
});
