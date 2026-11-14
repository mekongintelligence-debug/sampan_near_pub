// M6 browser tests (Playwright, Chromium): the built page opened as a local file. RPC
// answers are replayed from the recorded testnet fixtures; every request is logged and
// anything that is not an allowed RPC host is blocked and counted.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createRequire } from "node:module";
import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { canonicalize, hashHex } from "../../../packages/mandate/src/index.ts";
// @ts-expect-error plain JS build script
import { buildChecker } from "../build.mjs";

const require = createRequire(import.meta.url);
let playwright: any = null;
try { playwright = require("playwright"); } catch { /* reported below */ }

const FIX = resolve(import.meta.dirname, "../test/fixtures");
const release = JSON.parse(readFileSync(resolve(FIX, "release.json"), "utf8"));
const refuse = JSON.parse(readFileSync(resolve(FIX, "refuse.json"), "utf8"));
const recs = [...release.recorded, ...refuse.recorded];
const ALLOWED = new Set(["rpc.testnet.near.org", "rpc.mainnet.near.org", "test.rpc.fastnear.com", "rpc.fastnear.com", "archival-rpc.testnet.near.org", "archival-rpc.mainnet.near.org"]); // = ALLOWED_RPC_HOSTS (the page CSP)

let browser: any, fileUrl = "";
beforeAll(async () => {
  if (!playwright) throw new Error("Playwright is required for the M6 browser tests (preinstalled in the dev environment; CI installs it)");
  const out = join(mkdtempSync(join(tmpdir(), "checker-")), "index.html");
  await buildChecker(out);
  fileUrl = pathToFileURL(out).href;
  browser = await playwright.chromium.launch();
}, 60_000);
afterAll(async () => { await browser?.close(); });

async function open(hash = "") {
  const page = await browser.newPage();
  const requests: string[] = [], blocked: string[] = [], dialogs: string[] = [];
  page.on("dialog", (d: any) => { dialogs.push(d.message()); void d.dismiss(); });
  await page.route("**/*", async (route: any) => {
    const url = new URL(route.request().url());
    requests.push(url.protocol === "file:" ? "file" : url.hostname);
    if (url.protocol === "file:") return route.continue();
    if (!ALLOWED.has(url.hostname)) { blocked.push(url.hostname); return route.abort(); }
    const req = JSON.parse(route.request().postData() ?? "{}");
    const rec = recs.find((r: any) => r.method === req.method && JSON.stringify(r.params) === JSON.stringify(req.params));
    const body = rec ? rec.response : { jsonrpc: "2.0", id: "x", error: { name: "HANDLER_ERROR", cause: { name: "UNKNOWN_TRANSACTION" } } };
    return route.fulfill({ status: 200, contentType: "application/json", headers: { "access-control-allow-origin": "*" }, body: JSON.stringify(body) });
  });
  await page.goto(fileUrl + hash);
  return { page, requests, blocked, dialogs };
}
async function checkText(page: any, text: string) {
  await page.fill("#receipt", text);
  await page.click("#check");
  await page.waitForSelector("#result:not([hidden])");
  return { verdict: await page.textContent("#verdict"), states: await page.$$eval("#checks li", (ls: Element[]) => ls.map((l) => l.className)) };
}

describe("checker page (built, opened as a local file)", () => {
  it("a valid receipt is all green", async () => {
    const { page } = await open();
    const r = await checkText(page, JSON.stringify(release.envelope));
    expect(r.verdict).toMatch(/^Verified/);
    expect(r.states.every((s: string) => s === "pass")).toBe(true);
    await page.close();
  }, 30_000);

  it("a forged receipt turns red and names the failing check", async () => {
    const e = JSON.parse(JSON.stringify(release.envelope));
    e.order.amount = "500000"; e.core.observed.amount = "500000";
    e.core.order_hash = hashHex(canonicalize(e.order)); e.core_hash = hashHex(canonicalize(e.core));
    const { page } = await open();
    const r = await checkText(page, JSON.stringify(e));
    expect(r.verdict).toMatch(/^Not valid/);
    expect(await page.textContent("#checks li.fail")).toMatch(/The gate recorded this decision/);
    await page.close();
  }, 30_000);

  it("XSS payloads are shown as text: no dialog, no injected element", async () => {
    const e = JSON.parse(JSON.stringify(release.envelope));
    e.untrusted = { agent_note: '<img src=x onerror="alert(1)"><script>alert(2)</script>' };
    const { page, dialogs } = await open();
    await checkText(page, JSON.stringify(e));
    expect(await page.textContent("#note-text")).toContain("<img src=x");
    expect(await page.$$eval("img, #note-text script", (x: Element[]) => x.length)).toBe(0);
    expect(dialogs).toEqual([]);
    await page.close();
  }, 30_000);

  it("a receipt link (#r=...) is checked without any extra request", async () => {
    const b64 = Buffer.from(JSON.stringify(refuse.envelope)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const { page } = await open("#r=" + b64);
    await page.waitForSelector("#result:not([hidden])");
    expect(await page.textContent("#verdict")).toMatch(/^Verified: the gate refused this order, and no money moved/);
    expect(await page.textContent("#verdict")).not.toMatch(/payment matches/); // M6-CR9
    await page.close();
  }, 30_000);

  it("network isolation: the page contacts only the configured RPC host", async () => {
    const { page, requests, blocked } = await open();
    await checkText(page, JSON.stringify(release.envelope));
    expect(blocked).toEqual([]);
    // The default is the archival host (audit M8-01 / A3-01): a regular RPC forgets older transactions.
    expect(new Set(requests.filter((h) => h !== "file"))).toEqual(new Set(["archival-rpc.testnet.near.org"]));
    await page.close();
  }, 30_000);

  it("the CSP blocks a host outside the allow-list even if the page tried", async () => {
    const { page, requests } = await open();
    const violations: string[] = [];
    page.on("console", (m: any) => { if (/Content Security Policy/i.test(m.text())) violations.push(m.text()); });
    const outcome = await page.evaluate(async () => {
      try { await fetch("https://example.com/"); return "fetched"; } catch { return "blocked"; }
    });
    expect(outcome).toBe("blocked");
    // Blocked by the CSP itself: the request never reached the network layer.
    expect(requests).not.toContain("example.com");
    expect(violations.length).toBeGreaterThan(0);
    await page.close();
  }, 30_000);

  it("M6-CR8 a receipt opened from a file is checked; a file over 1 MB is refused", async () => {
    const dir = mkdtempSync(join(tmpdir(), "checker-file-"));
    const good = join(dir, "receipt.json"), big = join(dir, "big.json");
    writeFileSync(good, JSON.stringify(refuse.envelope));
    writeFileSync(big, "x".repeat(1_100_000));
    const { page } = await open();
    await page.setInputFiles("#file", good);
    await page.waitForSelector("#result:not([hidden])");
    expect(await page.textContent("#verdict")).toMatch(/^Verified/);
    expect(await page.textContent("#facts")).toMatch(/Refused, no money moved/);
    expect(await page.textContent("#facts")).toMatch(/Payee in the order/);
    await page.setInputFiles("#file", big);
    await page.waitForFunction(() => /larger than 1 MB/.test(document.getElementById("checks")?.textContent ?? ""));
    expect(await page.textContent("#verdict")).toMatch(/^Not valid/);
    await page.close();
  }, 30_000);

  it("M6-CR8 a mainnet receipt switches the default RPC to mainnet", async () => {
    const e = JSON.parse(JSON.stringify(release.envelope));
    e.core.network = "mainnet";
    const { page } = await open();
    await page.fill("#receipt", JSON.stringify(e));
    await page.click("#check");
    await page.waitForSelector("#result:not([hidden])");
    expect(await page.inputValue("#rpc")).toBe("https://archival-rpc.mainnet.near.org");
    await page.close();
  }, 30_000);

  // M6-13: every field from MILESTONES M6 tampered in the real page, not only the amount.
  const forge = (mutate: (e: any) => void) => {
    const e = JSON.parse(JSON.stringify(release.envelope));
    mutate(e);
    e.core.order_hash = hashHex(canonicalize(e.order)); e.core_hash = hashHex(canonicalize(e.core));
    return e;
  };
  for (const [name, mutate] of [
    ["payee", (e: any) => { e.order.payee = "attacker.testnet"; }],
    ["item", (e: any) => { e.order.item = "report-002"; }],
    ["rule result", (e: any) => { e.core.rules[2].pass = false; e.core.decision = "refuse"; }],
    ["transaction hash", (e: any) => { e.tx.decision = refuse.envelope.tx.decision; }],
  ] as [string, (e: any) => void][]) {
    it(`M6-13 a forged ${name} turns the page red`, async () => {
      const { page } = await open();
      const r = await checkText(page, JSON.stringify(forge(mutate)));
      expect(r.verdict).toMatch(/^Not valid/);
      await page.close();
    }, 30_000);
  }

  it("M6-13 XSS payloads in every string field never run or render as markup", async () => {
    const payload = '"><img src=x onerror=alert(1)><svg onload=alert(2)>';
    const { page, dialogs } = await open();
    for (const mutate of [
      (e: any) => { e.order.payee = payload; }, (e: any) => { e.order.item = payload; }, (e: any) => { e.core.gate = payload; },
      (e: any) => { e.signed_mandate.mandate.buyer = payload; }, (e: any) => { e.tx.decision = payload; },
      (e: any) => { e.untrusted = { agent_note: payload }; },
    ]) {
      const e = JSON.parse(JSON.stringify(release.envelope));
      mutate(e);
      await page.fill("#receipt", JSON.stringify(e));
      await page.click("#check");
      await page.waitForSelector("#result:not([hidden])");
      await page.waitForFunction(() => !(document.getElementById("check") as HTMLButtonElement).disabled);
    }
    expect(await page.$$eval("img, svg", (x: Element[]) => x.length)).toBe(0);
    expect(dialogs).toEqual([]);
    await page.close();
  }, 60_000);
});
