// M8 author test for the no-funds path, with no network: a stub answers 1Click (dry, no
// deposit address) and NEAR RPC (as for a receipt the RPC knows nothing about).
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

function run(oneclickAnswer) {
  const dir = mkdtempSync(join(tmpdir(), "dry-run-"));
  const log = join(dir, "log.jsonl");
  const pre = join(dir, "pre.mjs");
  writeFileSync(pre, `import { appendFileSync } from "node:fs";
globalThis.fetch = async (url, init = {}) => {
  appendFileSync(${JSON.stringify(log)}, JSON.stringify({ url: String(url), body: init.body ?? null }) + "\\n");
  if (String(url).startsWith("https://1click.chaindefuser.com/")) return new Response(${JSON.stringify(JSON.stringify(oneclickAnswer))}, { status: 200 });
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { cause: { name: "UNKNOWN_TRANSACTION" } } }), { status: 200 });
};`);
  const r = spawnSync(process.execPath, ["--import", pathToFileURL(pre).href, resolve(import.meta.dirname, "dry-run.mjs")], { encoding: "utf8", timeout: 120_000 });
  const reqs = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").map((l) => JSON.parse(l)) : [];
  return { r, reqs };
}

describe("M8 dry run (no network)", () => {
  it("asks 1Click only for a dry quote, sends no transaction, and reads receipts from archival RPC", () => {
    const { reqs } = run({ quote: { amountOut: "1000000", amountInFormatted: "1.01" } });
    const q = reqs.filter((x) => x.url.startsWith("https://1click.chaindefuser.com/"));
    expect(q.length).toBe(1);
    expect(JSON.parse(q[0].body).dry).toBe(true);
    for (const x of reqs.filter((y) => !y.url.startsWith("https://1click"))) {
      expect(new URL(x.url).hostname).toMatch(/^archival-rpc\.(testnet|mainnet)\.near\.org$/);
      expect(JSON.parse(x.body).method).not.toMatch(/broadcast|send_tx/);
    }
  });
  it("a quote with a deposit address, or a receipt the chain does not confirm, is a failure (exit 1)", () => {
    const { r } = run({ quote: { amountOut: "1000000", depositAddress: "0x" + "12".repeat(20) } });
    expect(r.status).toBe(1);
    expect(r.stdout).toMatch(/FAIL/);
    expect(r.stdout).not.toMatch(/everything checks out/);
  });
  it("1Click text is printed without control characters", () => {
    const { r } = run({ quote: { amountOut: "1000000", amountInFormatted: "1.0\u001b[2J" } });
    expect(r.stdout).not.toMatch(/\u001b/);
  });
});
