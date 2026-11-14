// Audit M8 (independent): tests for scripts/dry-run.mjs, with no network.
// A preload replaces fetch: every request is logged, 1Click gets a dry answer with no deposit
// address, and every NEAR RPC call gets the answer a regular (non-archival) RPC gives for a
// transaction older than about a day: UNKNOWN_TRANSACTION.
// "M8-NN ..." tests assert the REQUIRED behaviour and fail while the finding is open.
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const dir = mkdtempSync(join(tmpdir(), "audit-m8-dry-"));
const log = join(dir, "requests.jsonl");
const preload = join(dir, "preload.mjs");
writeFileSync(preload, `
import { appendFileSync } from "node:fs";
globalThis.fetch = async (url, init = {}) => {
  const u = String(url);
  appendFileSync(${JSON.stringify(log)}, JSON.stringify({ url: u, method: init.method ?? "GET", body: init.body ?? null }) + "\\n");
  if (u.startsWith("https://1click.chaindefuser.com/")) {
    return new Response(JSON.stringify({ quote: { amountOut: "1000000", amountInFormatted: "1.01" } }), { status: 200, headers: { "content-type": "application/json" } });
  }
  const id = (() => { try { return JSON.parse(init.body).id; } catch { return 1; } })();
  return new Response(JSON.stringify({ jsonrpc: "2.0", id, error: { name: "HANDLER_ERROR", cause: { name: "UNKNOWN_TRANSACTION", info: {} }, code: -32000, message: "Server error", data: "unknown transaction" } }), { status: 200, headers: { "content-type": "application/json" } });
};
`);
const r = spawnSync(process.execPath, ["--import", pathToFileURL(preload).href, resolve(import.meta.dirname, "dry-run.mjs")], { encoding: "utf8", timeout: 120_000 });
const requests = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
const rpcCalls = requests.filter((q) => !q.url.startsWith("https://1click.chaindefuser.com/"));
const methods = rpcCalls.map((q) => { try { return JSON.parse(q.body).method; } catch { return "?"; } });

describe("audit M8: dry run", () => {
  it("control: the dry run reports a real failure (old transactions not found) and exits 1", () => {
    expect(r.status, r.stdout + r.stderr).toBe(1);
    expect(r.stdout).toMatch(/FAIL/);
    expect(r.stdout).not.toMatch(/everything checks out/);
  });

  it("control: it asks 1Click only for dry quotes and never sends a transaction", () => {
    const oneclick = requests.filter((q) => q.url.startsWith("https://1click.chaindefuser.com/"));
    expect(oneclick.length).toBeGreaterThan(0);
    for (const q of oneclick) {
      expect(q.url).toMatch(/\/v0\/quote$/);
      expect(JSON.parse(q.body).dry).toBe(true);
    }
    expect(methods.length).toBeGreaterThan(0);
    for (const m of methods) expect(["broadcast_tx_commit", "broadcast_tx_async", "send_tx"]).not.toContain(m);
  });

  it("control: it contacts only 1Click and NEAR RPC hosts", () => {
    // Author adaptation after the M8 fixes (docs/audits/M8.md, author response): the pattern
    // also allows NEAR's archival hosts (archival-rpc.<network>.near.org), which M8-01 below requires.
    for (const q of requests) expect(new URL(q.url).hostname).toMatch(/^(1click\.chaindefuser\.com|([a-z-]+\.)?rpc\.(testnet|mainnet)\.near\.org|archival-rpc\.(testnet|mainnet)\.near\.org|(test\.)?rpc\.fastnear\.com)$/);
  });

  it("M8-01 the example receipts are checked with an RPC that keeps old transactions (archival)", () => {
    // A regular testnet RPC no longer finds a transaction from 6 Nov 2026 (checked 7 Nov), so
    // the README's dry run stops reproducing a day or two after the examples were made.
    const hosts = new Set(rpcCalls.map((q) => new URL(q.url).hostname));
    expect(hosts.size).toBeGreaterThan(0);
    for (const h of hosts) expect(h, "a receipt check went to a regular RPC").toMatch(/^archival-rpc\./);
  });
});
