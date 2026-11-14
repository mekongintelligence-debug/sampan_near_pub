// M6 checker tests (docs/SECURITY.md section 6, M6). They replay genuine testnet answers
// recorded by scripts/m6/capture-fixtures.mjs, so no network is used.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { verifyReceipt, receiptFromFragment, type Result } from "./verify.ts";
import { canonicalize, hashHex } from "../../../packages/mandate/src/index.ts";
import { checkRpcUrl } from "./rpc.ts";

const FIX = resolve(import.meta.dirname, "../test/fixtures");
const load = (name: string) => JSON.parse(readFileSync(resolve(FIX, `${name}.json`), "utf8"));
const release = load("release"), refuse = load("refuse");
const RPC = "https://rpc.testnet.near.org";
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

type Rec = { method: string; params: unknown; response: any };
/** A fetch that answers only recorded requests; `patch` may rewrite an answer. */
function replay(recs: Rec[], patch: (method: string, params: any, response: any) => any = (_m, _p, r) => r, hosts: string[] = ["rpc.testnet.near.org"]) {
  const log: string[] = [];
  const fetchFn = async (url: string, init: { body: string }) => {
    log.push(new URL(url).hostname);
    if (!hosts.includes(new URL(url).hostname)) throw new Error("network refused");
    const req = JSON.parse(init.body);
    const rec = recs.find((r) => r.method === req.method && JSON.stringify(r.params) === JSON.stringify(req.params));
    if (!rec) return { ok: true, json: async () => ({ jsonrpc: "2.0", id: "x", error: { name: "HANDLER_ERROR", cause: { name: "UNKNOWN_TRANSACTION" } } }) };
    return { ok: true, json: async () => patch(req.method, req.params, clone(rec.response)) };
  };
  return { fetchFn, log };
}
const allRecs: Rec[] = [...release.recorded, ...refuse.recorded];
const bytes = (o: unknown) => new TextEncoder().encode(typeof o === "string" ? o : JSON.stringify(o));
async function check(envelope: unknown, opts: { patch?: Parameters<typeof replay>[1]; second?: boolean; secondPatch?: Parameters<typeof replay>[1] } = {}): Promise<Result> {
  const primary = replay(allRecs, opts.patch);
  const secondary = replay(allRecs, opts.secondPatch, ["test.rpc.fastnear.com"]);
  const fetchFn = async (url: string, init: any) => (new URL(url).hostname === "test.rpc.fastnear.com" ? secondary.fetchFn(url, init) : primary.fetchFn(url, init));
  return verifyReceipt(bytes(envelope), { rpcUrl: RPC, secondRpcUrl: opts.second ? "https://test.rpc.fastnear.com" : undefined, fetchFn: fetchFn as any });
}
const status = (r: Result, id: string) => r.checks.find((c) => c.id === id)?.status;
/** A forger who recomputes every hash so the file stays internally consistent. */
function forge(env: any, mutate: (e: any) => void) {
  const e = clone(env);
  mutate(e);
  e.core.order_hash = hashHex(canonicalize(e.order));
  e.core_hash = hashHex(canonicalize(e.core));
  return e;
}

describe("valid receipts are all green", () => {
  it("release: every check passes, including payout", async () => {
    const r = await check(release.envelope);
    expect(r.overall).toBe("verified");
    expect(r.checks.map((c) => c.id)).toEqual(["file", "signature", "order", "gate", "locked", "anchor", "tx", "then", "block", "expiry", "payout", "deposit-tx"]); // "then" is never dropped since A2-01
    expect(r.facts?.decision).toBe("release");
  });
  it("refusal: every check passes, and no money moved", async () => {
    const r = await check(refuse.envelope);
    expect(r.overall).toBe("verified");
    expect(status(r, "payout")).toBe("pass");
    expect(r.facts?.decision).toBe("refuse");
  });
  it("a second RPC that agrees adds a passing cross-check", async () => {
    const r = await check(release.envelope, { second: true });
    expect(r.overall).toBe("verified");
    expect(status(r, "second-rpc")).toBe("pass");
  });
});

describe("every tampered field turns red and names the failing check", () => {
  const naive = (mutate: (e: any) => void) => { const e = clone(release.envelope); mutate(e); return e; };
  it.each([
    ["amount", (e: any) => { e.order.amount = "900000"; }],
    ["payee", (e: any) => { e.order.payee = "attacker.testnet"; }],
    ["item", (e: any) => { e.order.item = "report-002"; }],
    ["asset", (e: any) => { e.order.asset = "fake-usdc.testnet"; }],
    ["rule result", (e: any) => { e.core.rules[7].pass = false; }],
    ["decision", (e: any) => { e.core.decision = "refuse"; }],
    ["mandate hash", (e: any) => { e.core.mandate_hash = "1".repeat(64); }],
    ["order hash", (e: any) => { e.core.order_hash = "2".repeat(64); }],
    ["block height", (e: any) => { e.core.block_height = "1"; }],
    ["signature", (e: any) => { e.signed_mandate.signature = e.signed_mandate.signature.replace(/^./, (c: string) => (c === "a" ? "b" : "a")); }],
    ["mandate budget", (e: any) => { e.signed_mandate.mandate.max_amount = "999000000"; }],
  ])("naive tamper of %s: the file check fails", async (_name, mutate) => {
    const r = await check(naive(mutate));
    expect(r.overall).toBe("invalid");
    expect(status(r, "file")).toBe("fail");
  });

  it.each([
    ["amount (forged hashes)", (e: any) => { e.order.amount = "500000"; e.core.observed.amount = "500000"; }, "anchor"],
    ["item (forged hashes)", (e: any) => { e.order.item = "report-002"; }, "anchor"],
    ["block height (forged hashes)", (e: any) => { e.core.block_height = String(BigInt(e.core.block_height) + 1n); }, "anchor"],
    ["rule result (forged hashes)", (e: any) => { e.core.rules[2].pass = false; e.core.decision = "refuse"; }, "anchor"],
  ])("sophisticated forgery of %s: the chain check fails", async (_name, mutate, failing) => {
    const r = await check(forge(release.envelope, mutate));
    expect(r.overall).toBe("invalid");
    expect(status(r, "file")).toBe("pass");
    expect(status(r, failing as string)).toBe("fail");
  });

  it("transaction hash swapped for another real gate transaction: the tx check fails", async () => {
    const e = clone(release.envelope);
    e.tx.decision = refuse.envelope.tx.decision;
    const r = await check(e);
    expect(r.overall).toBe("invalid");
    expect(status(r, "tx")).toBe("fail");
  });
  it("transaction hash that does not exist: cannot verify, never green", async () => {
    const e = clone(release.envelope);
    e.tx.decision = "11111111111111111111111111111111";
    const r = await check(e);
    expect(r.overall).not.toBe("verified");
  });
});

describe("release versus refusal on chain", () => {
  it("a receipt claiming release where the chain shows a refusal is red", async () => {
    const e = forge(refuse.envelope, (x) => {
      x.core.rules = x.core.rules.map((r: any) => ({ ...r, pass: true }));
      x.core.decision = "release";
      x.order.payee = x.signed_mandate.mandate.payee; // make the file itself consistent
      x.core.observed.amount = x.order.amount;
    });
    const r = await check(e);
    expect(r.overall).toBe("invalid");
    expect(status(r, "anchor")).toBe("fail");
  });
  it("a receipt claiming refusal where the chain shows a release is red", async () => {
    const e = forge(release.envelope, (x) => { x.core.rules[2].pass = false; x.core.decision = "refuse"; }); // R3: the one rule the file cannot contradict
    const r = await check(e);
    expect(status(r, "anchor")).toBe("fail");
  });
});

describe("chain answers that must not count", () => {
  const isTx = (m: string) => m === "tx";
  it("a lookalike event from a different contract is rejected", async () => {
    const r = await check(release.envelope, { patch: (m, _p, res) => { if (isTx(m)) for (const o of res.result.receipts_outcome) if (o.outcome.executor_id.startsWith("gate-m3")) o.outcome.executor_id = "lookalike.testnet"; return res; } });
    expect(status(r, "tx")).toBe("fail");
    expect(r.overall).toBe("invalid");
  });
  it("an event from a failed receipt is rejected", async () => {
    const r = await check(release.envelope, { patch: (m, _p, res) => { if (isTx(m)) for (const o of res.result.receipts_outcome) if (o.outcome.logs.some((l: string) => l.includes('"receipt"'))) o.outcome.status = { Failure: { ActionError: {} } }; return res; } });
    expect(status(r, "tx")).toBe("fail");
  });
  it("a transaction that is not final is not green", async () => {
    const r = await check(release.envelope, { patch: (m, _p, res) => { if (isTx(m)) res.result.final_execution_status = "EXECUTED_OPTIMISTIC"; return res; } });
    expect(status(r, "tx")).toBe("unknown");
    expect(r.overall).toBe("unverifiable");
  });
  it("an RPC error is 'cannot verify', never green", async () => {
    const r = await check(release.envelope, { patch: (m) => (m === "query" ? { jsonrpc: "2.0", id: "x", error: { name: "INTERNAL_ERROR" } } : undefined) });
    expect(r.overall).toBe("unverifiable");
  });
  it("garbage from the RPC is 'cannot verify', never green", async () => {
    const r = await check(release.envelope, { patch: () => "<html>not json-rpc</html>" });
    expect(r.overall).toBe("unverifiable");
  });
  it("a second RPC that disagrees makes the result 'cannot verify'", async () => {
    const r = await check(release.envelope, { second: true, secondPatch: (m, _p, res) => { if (m === "query" && res.result?.result) { const v = JSON.parse(new TextDecoder().decode(Uint8Array.from(res.result.result))); v.core_hash = "0".repeat(64); res.result.result = Array.from(new TextEncoder().encode(JSON.stringify(v))); } return res; } });
    expect(status(r, "second-rpc")).toBe("unknown");
    expect(r.overall).toBe("unverifiable");
  });
  it("a testnet receipt checked against a mainnet RPC is not green", async () => {
    const r = await check(release.envelope, { patch: (m, _p, res) => { if (m === "status") res.result.chain_id = "mainnet"; return res; } });
    expect(status(r, "network")).toBe("unknown");
    expect(r.overall).toBe("unverifiable");
  });
});

describe("hostile files", () => {
  it("malformed JSON is red", async () => {
    const r = await check("{not json");
    expect(r.overall).toBe("invalid");
  });
  it("a huge file is refused before parsing", async () => {
    const r = await check("x".repeat(20_000_000));
    expect(status(r, "file")).toBe("fail");
    expect(r.checks[0].detail).toMatch(/too_large/);
  });
  it("XSS payloads in the only free-text field are returned as plain data", async () => {
    const e = clone(release.envelope);
    e.untrusted = { agent_note: '<img src=x onerror="alert(1)"><script>alert(2)</script>' };
    const r = await check(e);
    expect(r.overall).toBe("verified"); // the note is untrusted and outside the checks
    expect(r.facts?.agentNote).toContain("<img");
  });
  it("XSS payloads in checked fields are rejected by the grammars", async () => {
    const r = await check(naiveXss());
    expect(r.overall).toBe("invalid");
    function naiveXss() { const e = clone(release.envelope); e.order.item = "<script>"; return e; }
  });
});

describe("RPC hosts and links", () => {
  it("only the allowed HTTPS RPC hosts can be configured", () => {
    expect(checkRpcUrl("https://rpc.testnet.near.org")).toBe("https://rpc.testnet.near.org/");
    for (const bad of ["http://rpc.testnet.near.org", "https://evil.example", "https://user:pw@rpc.testnet.near.org", "javascript:alert(1)", "not a url"]) {
      expect(() => checkRpcUrl(bad), bad).toThrow();
    }
  });
  it("the checker contacts only the configured RPC host", async () => {
    const p = replay(allRecs);
    await verifyReceipt(bytes(release.envelope), { rpcUrl: RPC, fetchFn: p.fetchFn as any });
    expect(new Set(p.log)).toEqual(new Set(["rpc.testnet.near.org"]));
  });
  it("a receipt link carries the file in the fragment (no request)", () => {
    const text = JSON.stringify(release.envelope);
    const b64 = Buffer.from(text).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(new TextDecoder().decode(receiptFromFragment("#r=" + b64)!)).toBe(text);
    expect(receiptFromFragment("#r=<script>")).toBeNull();
  });
});

// ---- regression tests: self-review findings (docs/audits/M6-threat-review.md) ----------
const viewPatch = (method: string, fn: (v: any, params: any) => any) => (m: string, p: any, res: any) => {
  if (m === "query" && p.method_name === method) {
    const v = JSON.parse(new TextDecoder().decode(Uint8Array.from(res.result.result)));
    res.result.result = Array.from(new TextEncoder().encode(JSON.stringify(fn(v, p))));
  }
  return res;
};

describe("M6-CR1 the gate must be a known deployment of a reviewed build", () => {
  it("M6-CR1 a gate account that is not known is red, even if it answers like a gate", async () => {
    // A self-consistent forgery: the attacker is buyer and gate (look-alike contract).
    const e = clone(release.envelope);
    e.core.gate = "look-alike-gate.testnet";
    const r = await check(e);
    expect(status(r, "file")).toBe("fail"); // the signed mandate names the real gate
    const forged = clone(release.envelope);
    forged.signed_mandate.mandate.gate = "look-alike-gate.testnet";
    expect((await check(forged)).overall).toBe("invalid");
  });
  it("M6-CR1 the known gate account running other code is red", async () => {
    const r = await check(release.envelope, { patch: (m, p, res) => { if (m === "query" && p.request_type === "view_account") res.result.code_hash = "11111111111111111111111111111111"; return res; } });
    expect(status(r, "gate")).toBe("fail");
    expect(r.overall).toBe("invalid");
  });
  it("M6-CR1 a gate configured with another token is red", async () => {
    const r = await check(release.envelope, { patch: viewPatch("get_config", (v) => ({ ...v, token: "fake-usdc.testnet" })) });
    expect(status(r, "gate")).toBe("fail");
  });
});

describe("M6-CR2 unusable chain data is 'cannot verify', never a crash", () => {
  it("M6-CR2 an event core containing a number", async () => {
    const r = await check(release.envelope, { patch: (m, _p, res) => {
      if (m === "tx") for (const o of res.result.receipts_outcome) o.outcome.logs = o.outcome.logs.map((l: string) => l.replace('"block_height":"', '"block_height":1,"x":"'));
      return res;
    } });
    expect(r.overall).not.toBe("verified");
  });
  it("M6-CR2 a block timestamp that is not a number", async () => {
    const r = await check(release.envelope, { patch: (m, _p, res) => { if (m === "block") res.result.header.timestamp_nanosec = "abc"; return res; } });
    expect(r.overall).toBe("unverifiable");
  });
});

describe("M6-CR3 a refusal says why, in plain language", () => {
  it("M6-CR3 the refusal check names the swapped payee and does not claim the order was inside the mandate", async () => {
    const r = await check(refuse.envelope);
    const c = r.checks.find((x) => x.id === "order")!;
    expect(c.title).toBe("The refusal matches the buyer's limits");
    expect(c.detail).toMatch(/someone other than the payee the buyer signed/);
    expect(r.facts?.refusedBecause.length).toBe(1);
  });
});

describe("M6-CR7 the RPC answer size is capped while reading", () => {
  it("M6-CR7 an oversized streamed answer is refused as 'cannot verify'", async () => {
    let sent = 0;
    const body = new ReadableStream<Uint8Array>({ pull(c) { sent += 65536; if (sent > 6_000_000) c.close(); else c.enqueue(new Uint8Array(65536).fill(32)); } });
    const fetchFn = async () => ({ ok: true, json: async () => ({}), body });
    const r = await verifyReceipt(bytes(release.envelope), { rpcUrl: RPC, fetchFn: fetchFn as any });
    expect(r.overall).toBe("unverifiable");
    expect(sent).toBeLessThan(5_000_000); // stopped early, not after reading everything
  });
});
