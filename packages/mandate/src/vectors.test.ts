// Runs every shared vector in fixtures/vectors/ against the TypeScript implementation.
// The Rust implementation runs the same files (crates/formats/tests/vectors.rs).
import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { parseMandate, parseOrder, verifySignedMandate, canonicalize, parseCanonical, FormatError, ERROR_CODES, toBytes } from "./index.ts";
import { parseReceiptCore } from "../../receipt/src/index.ts";

const DIR = resolve(import.meta.dirname, "../../../fixtures/vectors");
type Vector = { name: string; kind: string; description: string; input_b64: string; expect: { ok: true; hash: string } | { ok: false; error: string } };

function load(): Vector[] {
  const out: Vector[] = [];
  for (const kind of readdirSync(DIR, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name)) {
    for (const f of readdirSync(join(DIR, kind)).filter((f) => f.endsWith(".json"))) {
      out.push(JSON.parse(readFileSync(join(DIR, kind, f), "utf8")));
    }
  }
  return out;
}

function run(v: Vector): { ok: true; hash: string } | { ok: false; error: string } {
  const bytes = new Uint8Array(Buffer.from(v.input_b64, "base64"));
  try {
    switch (v.kind) {
      case "mandate": return { ok: true, hash: parseMandate(bytes).hash };
      case "signed_mandate": return { ok: true, hash: verifySignedMandate(bytes).mandateHash };
      case "order": return { ok: true, hash: parseOrder(bytes).hash };
      case "receipt_core": return { ok: true, hash: parseReceiptCore(bytes).hash };
      default: throw new Error(`unknown vector kind ${v.kind}`);
    }
  } catch (e) {
    if (e instanceof FormatError) return { ok: false, error: e.code };
    throw e; // any other exception is a bug, never a pass
  }
}

const vectors = load();
const RUNS = Number(process.env.FC_NUM_RUNS ?? 0) || undefined;

describe("shared vectors", () => {
  it("there are at least 20 vectors and every expected error code is known", () => {
    // Floor = the current vector count, so deleting vectors fails here (M2-04). Raise it when adding.
    expect(vectors.length).toBeGreaterThanOrEqual(137);
    for (const v of vectors) if (!v.expect.ok) expect(ERROR_CODES).toContain(v.expect.error);
  });

  it("the manifest lists every vector file with its exact hash (vectors are never edited)", () => {
    const manifest = readFileSync(join(DIR, "MANIFEST.sha256"), "utf8").trim().split("\n").map((l) => l.split(" "));
    const listed = new Map(manifest.map(([h, p]) => [p, h]));
    const files = vectors.map((v) => `${v.kind}/${v.name}.json`);
    expect([...listed.keys()].sort()).toEqual(files.sort());
    for (const f of files) {
      expect(bytesToHex(sha256(readFileSync(join(DIR, f)))), f).toBe(listed.get(f));
    }
  });

  for (const v of vectors) {
    it(`${v.kind}/${v.name}: ${v.description}`, () => {
      expect(run(v)).toEqual(v.expect);
    });
  }
});

describe("canonical form (property tests)", () => {
  const ascii = fc.string({ unit: fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz0123456789-_.".split("")), maxLength: 12 });
  const value: fc.Arbitrary<unknown> = fc.letrec((tie) => ({
    v: fc.oneof({ depthSize: "small" }, ascii, fc.boolean(), fc.constant(null), fc.array(tie("v"), { maxLength: 4 }), fc.dictionary(ascii, tie("v"), { maxKeys: 4 })),
  })).v;

  it("canonical text always parses back to itself", () => {
    fc.assert(fc.property(value, (v) => {
      const text = canonicalize(v);
      expect(parseCanonical(toBytes(text), 1 << 20).text).toBe(text);
    }), { numRuns: RUNS ?? 500 });
  });

  it("any other serialisation of the same value is rejected", () => {
    fc.assert(fc.property(value, fc.integer({ min: 1, max: 4 }), (v, indent) => {
      const pretty = JSON.stringify(v, null, indent);
      const canonical = canonicalize(v);
      fc.pre(pretty !== canonical);
      expect(() => parseCanonical(toBytes(pretty), 1 << 20)).toThrowError(/not_canonical/);
    }), { numRuns: RUNS ?? 500 });
  });

  it("numbers are never accepted anywhere in a document", () => {
    fc.assert(fc.property(fc.double({ noNaN: true, noDefaultInfinity: true }), (n) => {
      expect(() => parseCanonical(toBytes(JSON.stringify({ a: n })), 4096)).toThrowError(/schema|not_canonical/);
    }), { numRuns: RUNS ?? 200 });
  });

  it("random bytes never crash the parser (only FormatError)", () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 300 }), (b) => {
      for (const f of [parseMandate, verifySignedMandate, parseOrder, parseReceiptCore]) {
        try { f(b); } catch (e) { expect(e).toBeInstanceOf(FormatError); }
      }
    }), { numRuns: RUNS ?? 1000 });
  });
});
