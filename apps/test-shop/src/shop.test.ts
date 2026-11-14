// M5 browser tests (Playwright, Chromium): the built test shop and checkout widget, served
// locally. 1Click and the relayer are answered by routes; every request is logged and any
// other host is blocked. The wallet is a mock that signs with a throwaway test key.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createRequire } from "node:module";
import { createServer, type Server } from "node:http";
import { readFileSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { erc191Hash, evmAddress, verifySignedMandate, toBytes } from "../../../packages/mandate/src/index.ts";
import { toChecksumEvm } from "../../../packages/payments/src/index.ts";
// @ts-expect-error plain JS build script
import { buildShop } from "../build.mjs";

const require = createRequire(import.meta.url);
let playwright: any = null;
try { playwright = require("playwright"); } catch { /* reported below */ }

const SK = sha256(new TextEncoder().encode("m5-shop-test-only-wallet-key"));
const ADDRESS_LC = evmAddress(secp256k1.getPublicKey(SK, false));
const ADDRESS = toChecksumEvm(ADDRESS_LC); // EIP-55 form, as many wallets return it
const ONECLICK = "1click.chaindefuser.com";

let browser: any;
const servers: Server[] = [];
async function serve(dir: string, extra: Record<string, string> = {}): Promise<string> {
  const s = createServer((req, res) => {
    const name = req.url === "/" ? "index.html" : (req.url ?? "").slice(1);
    if (!/^[a-z.-]+$/.test(name)) { res.writeHead(404); return res.end(); }
    try {
      const body = name in extra ? extra[name]! : readFileSync(join(dir, name));
      res.writeHead(200, { "content-type": name.endsWith(".js") ? "text/javascript" : "text/html" });
      res.end(body);
    } catch { res.writeHead(404); res.end(); }
  });
  servers.push(s);
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
  return `http://127.0.0.1:${(s.address() as any).port}`;
}

beforeAll(async () => {
  if (!playwright) throw new Error("Playwright is required for the M5 browser tests (preinstalled in the dev environment; CI installs it)");
  browser = await playwright.chromium.launch();
}, 60_000);
afterAll(async () => { await browser?.close(); servers.forEach((s) => s.close()); });

async function shop(mode: "dry" | "live", opts: { integrity?: string; echo?: Record<string, unknown>; quote?: Record<string, unknown>; relayer?: Record<string, unknown>; relayerUrl?: string; walletAddress?: string; gateForgets?: boolean } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "shop-"));
  await buildShop({ out: dir, mode, integrity: opts.integrity, ...(opts.relayerUrl !== undefined ? { relayer: opts.relayerUrl } : {}) });
  const url = await serve(dir);
  const page = await browser.newPage();
  const hosts: string[] = [], blocked: string[] = [], quotes: any[] = [], registered: any[] = [];
  await page.exposeFunction("__testSign", (hexMsg: string) => {
    const msg = new TextDecoder().decode(hexToBytes(hexMsg.slice(2)));
    const rec = secp256k1.sign(erc191Hash(msg), SK, { prehash: false, format: "recovered", lowS: true });
    return "0x" + bytesToHex(new Uint8Array([...rec.subarray(1), 27 + rec[0]!]));
  });
  await page.addInitScript((address: string) => {
    const w = window as any;
    w.__calls = [];
    w.__messageListeners = 0;
    const add = window.addEventListener.bind(window);
    window.addEventListener = ((t: string, ...rest: any[]) => { if (t === "message") w.__messageListeners++; return (add as any)(t, ...rest); }) as any;
    w.ethereum = {
      request: async ({ method, params }: { method: string; params?: unknown[] }) => {
        w.__calls.push(method);
        if (method === "eth_requestAccounts") return [address];
        if (method === "personal_sign") return w.__testSign((params as string[])[0]);
        throw new Error("unsupported");
      },
    };
  }, opts.walletAddress ?? ADDRESS);
  const cors = { "access-control-allow-origin": "*", "access-control-allow-headers": "content-type" };
  await page.route("**/*", async (route: any) => {
    const req = route.request();
    const u = new URL(req.url());
    hosts.push(u.host);
    if (u.origin === url) return route.continue();
    if (req.method() === "OPTIONS") return route.fulfill({ status: 204, headers: cors });
    if (u.hostname === ONECLICK && u.pathname === "/v0/quote") {
      const body = JSON.parse(req.postData() ?? "{}");
      quotes.push(body);
      const quote = { amountIn: "1010000", amountInFormatted: "1.01", amountOut: body.amount, minAmountOut: body.amount, deadline: body.deadline, timeEstimate: 35, ...(body.dry ? {} : { depositAddress: "0x" + "12".repeat(20) }), ...opts.quote };
      return route.fulfill({ status: 200, contentType: "application/json", headers: cors, body: JSON.stringify({ quoteRequest: { ...body, ...opts.echo }, quote, signature: "ed25519:test", correlationId: "c-1" }) });
    }
    if (u.host === "127.0.0.1:8790" && u.pathname === "/register") {
      const body = JSON.parse(req.postData() ?? "{}");
      registered.push(body);
      const v = verifySignedMandate(toBytes(body.signed_mandate));
      return route.fulfill({ status: 200, contentType: "application/json", headers: cors, body: JSON.stringify({ registered: true, mandate_hash: v.mandateHash, ...opts.relayer }) });
    }
    if (u.host === "rpc.testnet.near.org" && req.method() === "POST") {
      // The gate's answers (M5-01, M5-07): accounts exist; get_mandate returns what the relayer registered.
      const q = JSON.parse(req.postData() ?? "{}").params ?? {};
      const ok = (result: unknown) => route.fulfill({ status: 200, contentType: "application/json", headers: cors, body: JSON.stringify({ jsonrpc: "2.0", id: "sampan", result }) });
      if (q.request_type === "view_account") return ok({ amount: "1", code_hash: "11111111111111111111111111111111" });
      if (q.request_type === "call_function" && q.method_name === "get_mandate") {
        const last = registered.at(-1);
        const m = last ? verifySignedMandate(toBytes(last.signed_mandate)).mandate : null;
        const rec = m && !opts.gateForgets ? { agent: m.agent, payee: m.payee, refund_to: m.refund_to, max_amount: m.max_amount, expiry_ns: m.expiry_ns } : null;
        return ok({ result: [...new TextEncoder().encode(JSON.stringify(rec))], logs: [], block_height: 1, block_hash: "1" });
      }
    }
    blocked.push(u.host);
    return route.abort();
  });
  await page.goto(url);
  const text = (id: string) => page.locator(`#sampan-checkout [data-id="${id}"]`).textContent({ timeout: 5000 }).catch(() => null);
  return { page, url, hosts, blocked, quotes, registered, text };
}

describe("M5 test shop and checkout widget (built, served locally)", () => {
  it("dry-quote flow: shows the mandate and a preview; never signs, never registers, no deposit address", async () => {
    const s = await shop("dry");
    await s.page.locator('#sampan-checkout [data-id="start"]').click();
    await s.page.locator('#sampan-checkout [data-id="preview_in"]').waitFor();
    expect(await s.text("payee")).toBe("payee2-m3.sampan-trust-01.testnet");
    expect(await s.text("gate")).toBe("gate-m3.sampan-trust-01.testnet (testnet)");
    expect(await s.text("refund_to")).toBe(ADDRESS_LC);
    expect(await s.text("mandate_hash")).toMatch(/^[0-9a-f]{64}$/);
    expect(s.quotes).toHaveLength(1);
    expect(s.quotes[0]).toMatchObject({ dry: true, swapType: "EXACT_OUTPUT", amount: "1000000", recipient: "gate-m3.sampan-trust-01.testnet" });
    expect(JSON.parse(s.quotes[0].customRecipientMsg).mandate_hash).toBe(await s.text("mandate_hash"));
    expect(await s.page.evaluate(() => (window as any).__calls)).toEqual(["eth_requestAccounts"]);
    expect(s.registered).toHaveLength(0);
    expect(await s.page.locator('#sampan-checkout [data-id="deposit_address"]').count()).toBe(0);
    expect(s.blocked).toEqual([]);
    expect(new Set(s.hosts)).toEqual(new Set([new URL(s.url).host, ONECLICK]));
    expect(await s.text("item")).toContain("report-002");
    await s.page.close();
  });

  it("live flow: the signed mandate is the one shown, registered, quote checked, then the deposit address", async () => {
    const s = await shop("live");
    await s.page.locator('#sampan-checkout [data-id="start"]').click();
    await s.page.locator('#sampan-checkout [data-id="deposit_address"]').waitFor();
    const shown = await s.text("mandate_hash");
    expect(await s.text("deposit_mandate_hash")).toBe(shown);
    expect(s.registered).toHaveLength(1);
    const v = verifySignedMandate(toBytes(s.registered[0].signed_mandate));
    expect(v.mandateHash).toBe(shown);
    expect(v.mandate).toMatchObject({ payee: await s.text("payee"), refund_to: await s.text("refund_to"), max_amount: "1000000", agent: null });
    expect(s.quotes.map((q) => q.dry)).toEqual([false]);
    expect(await s.page.evaluate(() => (window as any).__calls)).toEqual(["eth_requestAccounts", "personal_sign"]);
    await s.page.close();
  });

  for (const [name, opts] of [
    ["recipient changed in the echo", { echo: { recipient: "attacker.testnet" } }],
    ["refund address changed in the echo", { echo: { refundTo: "0x" + "99".repeat(20) } }],
    ["message changed in the echo", { echo: { customRecipientMsg: "{}" } }],
    ["less delivered than the price", { quote: { amountOut: "999999" } }],
    ["rate changed beyond the bound", { quote: { amountIn: "1100000" } }],
    ["fees added", { echo: { appFees: [{ recipient: "x.near", fee: 100 }] } }],
  ] as const) {
    it(`quote tampering (${name}): no deposit address is shown`, async () => {
      const s = await shop("live", opts as any);
      await s.page.locator('#sampan-checkout [data-id="start"]').click();
      await s.page.locator('#sampan-checkout [data-id="status"]').waitFor();
      expect(await s.text("status")).toMatch(/does not match the mandate/);
      expect(await s.page.locator('#sampan-checkout [data-id="deposit_address"]').count()).toBe(0);
      await s.page.close();
    });
  }

  it("a relayer answer for another mandate stops the checkout", async () => {
    const s = await shop("live", { relayer: { mandate_hash: "ab".repeat(32) } });
    await s.page.locator('#sampan-checkout [data-id="start"]').click();
    await s.page.locator('#sampan-checkout [data-id="status"]').waitFor();
    expect(await s.text("status")).toMatch(/could not register/);
    expect(s.quotes).toHaveLength(0);
    await s.page.close();
  });

  it("M5-CR1: a wallet that returns a lower-case address can still pay", async () => {
    const s = await shop("live", { walletAddress: ADDRESS_LC });
    await s.page.locator('#sampan-checkout [data-id="start"]').click();
    await s.page.locator('#sampan-checkout [data-id="deposit_address"]').waitFor();
    expect(s.quotes[0].refundTo).toBe(ADDRESS);
    expect(await s.text("refund_origin")).toBe(ADDRESS);
    await s.page.close();
  });

  it("M5-CR9: a live widget without a valid relayer URL does not start", async () => {
    for (const relayerUrl of ["", "http://shop.example", "javascript:alert(1)"]) {
      const s = await shop("live", { relayerUrl });
      expect(await s.text("status")).toMatch(/data-relayer/);
      expect(await s.page.locator('#sampan-checkout [data-id="start"]').count()).toBe(0);
      await s.page.close();
    }
  });

  it("M5-02 (accepted): a live widget refuses mainnet until the checkout runs in an isolated frame", async () => {
    const dir = mkdtempSync(join(tmpdir(), "shop-"));
    await buildShop({ out: dir, mode: "live" });
    const html = readFileSync(join(dir, "index.html"), "utf8").replace('data-network="testnet"', 'data-network="mainnet"');
    const url = await serve(dir, { "index.html": html });
    const p = await browser.newPage();
    await p.goto(url);
    await expect(p.locator('#sampan-checkout [data-id="status"]').textContent()).resolves.toMatch(/mainnet are not enabled/);
    expect(await p.locator('#sampan-checkout [data-id="start"]').count()).toBe(0);
    await p.close();
  });

  it("a wrong SRI hash: the browser refuses to run the widget", async () => {
    const s = await shop("live", { integrity: "sha384-" + Buffer.alloc(48).toString("base64") });
    await s.page.waitForTimeout(300);
    expect(await s.page.locator('#sampan-checkout [data-id="start"]').count()).toBe(0);
    await s.page.close();
  });

  it("inside a frame the live widget refuses to pay; it registers no postMessage listener", async () => {
    const s = await shop("live");
    expect(await s.page.evaluate(() => (window as any).__messageListeners)).toBe(0);
    const outer = await serve(mkdtempSync(join(tmpdir(), "frame-")), { "index.html": `<!doctype html><iframe src="${s.url}/" width="600" height="600"></iframe>` });
    const p = await browser.newPage();
    await p.addInitScript(() => { (window as any).ethereum = { request: async ({ method }: any) => (method === "eth_requestAccounts" ? ["0x8ba1f109551bD432803012645Ac136ddd64DBA72"] : null) }; });
    await p.goto(outer);
    const f = p.frameLocator("iframe");
    await f.locator('#sampan-checkout [data-id="start"]').click();
    await expect(f.locator('#sampan-checkout [data-id="status"]').textContent()).resolves.toMatch(/its own tab/);
    await p.close();
    await s.page.close();
  });
});
