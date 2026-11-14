// Audit M5 (independent, fresh subagent): browser exploit tests for the checkout widget in the built test shop.
// Each "M5-NN" test asserts the REQUIRED behaviour, so it fails while its finding is open.
// Served locally; 1Click, the relayer and any NEAR RPC are answered by routes; every other host is blocked.
// The wallet is a mock that signs with a throwaway test key. No network, no real funds.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createRequire } from "node:module";
import { createServer, type Server } from "node:http";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
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

const SK = sha256(new TextEncoder().encode("audit-m5-shop-test-only-wallet-key"));
const ADDRESS = toChecksumEvm(evmAddress(secp256k1.getPublicKey(SK, false)));
const ONECLICK = "1click.chaindefuser.com";
const HONEST_DEPOSIT = "0x" + "12".repeat(20);
const ATTACKER_DEPOSIT = "0x" + "66".repeat(20);

let browser: any;
const servers: Server[] = [];
async function serve(dir: string): Promise<string> {
  const s = createServer((req, res) => {
    const name = req.url === "/" ? "index.html" : (req.url ?? "").slice(1);
    if (!/^[a-z.-]+$/.test(name)) { res.writeHead(404); return res.end(); }
    try {
      res.writeHead(200, { "content-type": name.endsWith(".js") ? "text/javascript" : "text/html" });
      res.end(readFileSync(join(dir, name)));
    } catch { res.writeHead(404); res.end(); }
  });
  servers.push(s);
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
  return `http://127.0.0.1:${(s.address() as any).port}`;
}

beforeAll(async () => {
  if (!playwright) throw new Error("Playwright is required for the M5 audit browser tests");
  browser = await playwright.chromium.launch();
}, 60_000);
afterAll(async () => { await browser?.close(); servers.forEach((s) => s.close()); });

type Opts = { patchHtml?: (html: string) => string; pageScript?: string; unknownAccounts?: boolean; gateHolds?: boolean };
async function shop(mode: "dry" | "live", opts: Opts = {}) {
  const dir = mkdtempSync(join(tmpdir(), "audit-m5-shop-"));
  await buildShop({ out: dir, mode });
  if (opts.patchHtml) writeFileSync(join(dir, "index.html"), opts.patchHtml(readFileSync(join(dir, "index.html"), "utf8")));
  const url = await serve(dir);
  const page = await browser.newPage();
  const registered: string[] = [], rpcCalls: unknown[] = [], blocked: string[] = [];
  await page.exposeFunction("__testSign", (hexMsg: string) => {
    const msg = new TextDecoder().decode(hexToBytes(hexMsg.slice(2)));
    const rec = secp256k1.sign(erc191Hash(msg), SK, { prehash: false, format: "recovered", lowS: true });
    return "0x" + bytesToHex(new Uint8Array([...rec.subarray(1), 27 + rec[0]!]));
  });
  await page.addInitScript((address: string) => {
    (window as any).__calls = [];
    (window as any).ethereum = {
      request: async ({ method, params }: { method: string; params?: unknown[] }) => {
        (window as any).__calls.push(method);
        if (method === "eth_requestAccounts") return [address];
        if (method === "personal_sign") return (window as any).__testSign((params as string[])[0]);
        throw new Error("unsupported");
      },
    };
  }, ADDRESS);
  // A script the merchant page runs (an analytics tag, a compromised dependency): same realm as the widget.
  if (opts.pageScript) await page.addInitScript(opts.pageScript);
  const cors = { "access-control-allow-origin": "*", "access-control-allow-headers": "content-type" };
  await page.route("**/*", async (route: any) => {
    const req = route.request();
    const u = new URL(req.url());
    if (u.origin === url) return route.continue();
    if (req.method() === "OPTIONS") return route.fulfill({ status: 204, headers: cors });
    if (u.hostname === ONECLICK && u.pathname === "/v0/quote") {
      const body = JSON.parse(req.postData() ?? "{}");
      const quote = { amountIn: "1010000", amountInFormatted: "1.01", amountOut: body.amount, minAmountOut: body.amount, deadline: body.deadline, timeEstimate: 35, ...(body.dry ? {} : { depositAddress: HONEST_DEPOSIT }) };
      return route.fulfill({ status: 200, contentType: "application/json", headers: cors, body: JSON.stringify({ quoteRequest: body, quote, signature: "ed25519:test", correlationId: "c-1" }) });
    }
    if (u.host === "127.0.0.1:8790" && u.pathname === "/register") {
      // A relayer answer that claims success. Nothing is registered on the gate.
      const body = JSON.parse(req.postData() ?? "{}");
      registered.push(body.signed_mandate);
      const v = verifySignedMandate(toBytes(body.signed_mandate));
      return route.fulfill({ status: 200, contentType: "application/json", headers: cors, body: JSON.stringify({ registered: true, mandate_hash: v.mandateHash }) });
    }
    if (req.method() === "POST" && /^\s*\{/.test(req.postData() ?? "")) {
      // Any NEAR JSON-RPC query: the gate knows no such mandate (get_mandate -> null).
      const rpc = JSON.parse(req.postData() ?? "{}");
      rpcCalls.push(rpc);
      // Author adaptation after the M5 fixes (docs/audits/M5.md, author response): the widget now asks NEAR
      // whether refund_to exists before signing (M5-07), so view_account gets an account answer here; and the
      // M5-02 test needs a gate that holds the mandate, or it would stop at the M5-01 check and pass vacuously.
      if (!opts.unknownAccounts && rpc.params?.request_type === "view_account") return route.fulfill({ status: 200, contentType: "application/json", headers: cors, body: JSON.stringify({ jsonrpc: "2.0", id: rpc.id ?? 0, result: { amount: "1", code_hash: "11111111111111111111111111111111" } }) });
      if (opts.gateHolds && registered.length) {
        const m = verifySignedMandate(toBytes(registered.at(-1))).mandate;
        const rec = { agent: m.agent, payee: m.payee, refund_to: m.refund_to, max_amount: m.max_amount, expiry_ns: m.expiry_ns };
        return route.fulfill({ status: 200, contentType: "application/json", headers: cors, body: JSON.stringify({ jsonrpc: "2.0", id: rpc.id ?? 0, result: { result: [...new TextEncoder().encode(JSON.stringify(rec))], logs: [], block_height: 1, block_hash: "11111111111111111111111111111111" } }) });
      }
      if (opts.unknownAccounts) return route.fulfill({ status: 200, contentType: "application/json", headers: cors, body: JSON.stringify({ jsonrpc: "2.0", id: rpc.id ?? 0, error: { name: "HANDLER_ERROR", cause: { name: "UNKNOWN_ACCOUNT", info: {} }, code: -32000, message: "Server error" } }) });
      return route.fulfill({ status: 200, contentType: "application/json", headers: cors, body: JSON.stringify({ jsonrpc: "2.0", id: rpc.id ?? 0, result: { result: [...new TextEncoder().encode("null")], logs: [], block_height: 1, block_hash: "11111111111111111111111111111111" } }) });
    }
    blocked.push(u.host);
    return route.abort();
  });
  await page.goto(url);
  const text = (id: string) => page.locator(`#sampan-checkout [data-id="${id}"]`).textContent({ timeout: 5000 }).catch(() => null);
  const widgetText = () => page.evaluate(() => document.getElementById("sampan-checkout")?.shadowRoot?.textContent ?? "");
  const walletCalls = () => page.evaluate(() => (window as any).__calls as string[]);
  return { page, text, widgetText, walletCalls, registered, rpcCalls, blocked };
}

/** Wait until the live flow has ended, with a deposit address or a status message. */
async function finished(s: Awaited<ReturnType<typeof shop>>) {
  await s.page.locator('#sampan-checkout [data-id="start"]').click();
  await s.page.locator('#sampan-checkout [data-id="deposit_address"], #sampan-checkout [data-id="status"]').first().waitFor({ timeout: 10_000 });
}

describe("audit M5: checkout widget", () => {
  // The widget shows the deposit address as soon as the relayer says {"registered": true}. It never asks the
  // gate. If that answer is wrong (a faulty or compromised relayer, or a data-relayer URL the page chose), the
  // buyer pays for a mandate the gate does not know: the gate hands the payment back to 1Click's account
  // (unknown_mandate), not to refund_to.
  it("M5-01 no deposit address unless the gate itself confirms the mandate is registered", async () => {
    const s = await shop("live");
    await finished(s);
    expect(s.registered).toHaveLength(1);
    expect(await s.page.locator('#sampan-checkout [data-id="deposit_address"]').count()).toBe(0);
    await s.page.close();
  }, 30_000);

  // Any script on the merchant page runs in the widget's realm. It can wrap window.fetch and change the
  // 1Click answer after the network but before checkLiveQuote, which cannot tell a swapped deposit address
  // from a real one (the quote signature is not verified, A1P-09). SECURITY.md section 2 lists exactly this attack.
  // Accepted by the lead on 7 Nov 2026 (option A, docs/audits/M5.md author response): not fixable inside the
  // merchant's page; documented in the README, and the live widget refuses mainnet until the checkout runs in
  // an isolated frame. `it.fails` keeps this exploit running: it turns red the day the attack stops working,
  // so the acceptance is revisited, and it can never silently pass.
  it.fails("M5-02 a page script cannot make the widget show its own deposit address", async () => {
    const pageScript = `(() => {
      const real = window.fetch.bind(window);
      window.fetch = async (input, init) => {
        const r = await real(input, init);
        if (!String(input).includes("/v0/quote")) return r;
        const j = await r.clone().json();
        if (j && j.quote && j.quote.depositAddress) j.quote.depositAddress = "${ATTACKER_DEPOSIT}";
        return new Response(JSON.stringify(j), { status: r.status, headers: { "content-type": "application/json" } });
      };
    })();`;
    const s = await shop("live", { pageScript, gateHolds: true });
    await finished(s);
    expect(await s.text("deposit_address")).not.toBe(ATTACKER_DEPOSIT);
    await s.page.close();
  }, 30_000);

  // M5-5 and SECURITY.md 6 "M5": the buyer must see the mandate fields that are signed. The widget rounds the
  // price to cents and shows data-label instead of the signed item id.
  it("M5-04 the price shown before signing is the exact signed amount", async () => {
    const s = await shop("dry", { patchHtml: (h) => h.replace('data-price="1000000"', 'data-price="1004999"') });
    await s.page.locator('#sampan-checkout [data-id="start"]').click();
    await s.page.locator('#sampan-checkout [data-id="mandate_hash"]').waitFor();
    expect(await s.widgetText()).toContain("1.004999");
    await s.page.close();
  }, 30_000);

  it("M5-04 the item shown before signing is the signed item id, not only the merchant's label", async () => {
    const s = await shop("dry", { patchHtml: (h) => h.replace('data-item="report-002"', 'data-item="annual-plan-999"') });
    await s.page.locator('#sampan-checkout [data-id="start"]').click();
    await s.page.locator('#sampan-checkout [data-id="mandate_hash"]').waitFor();
    expect(await s.widgetText()).toContain("annual-plan-999");
    await s.page.close();
  }, 30_000);

  // A1-payments M5-7: refund_to must be checked to exist on NEAR (final view) BEFORE the buyer signs. The widget
  // asks for the signature first and leaves the check to the relayer. A new EVM wallet's 0x account usually does
  // not exist yet (**Assumption**), so such buyers sign and are only then refused (refund_account_missing).
  it("M5-07 a refund account that NEAR does not know stops the checkout before any signature", async () => {
    const s = await shop("live", { unknownAccounts: true });
    await finished(s);
    expect(await s.walletCalls()).not.toContain("personal_sign");
    await s.page.close();
  }, 30_000);
});
