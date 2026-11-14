// Independent audit M6 (docs/audits/M6.md): browser exploit tests on the built page,
// opened as a local file in Chromium, as in page.test.ts. Each test asserts the REQUIRED
// behaviour, so it FAILS while its finding is open; positive controls (marked) pass.
// RPC answers are replayed from the recorded testnet fixtures; nothing leaves the machine.
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
try { playwright = require("playwright"); } catch { /* reported in beforeAll */ }

const FIX = resolve(import.meta.dirname, "../test/fixtures");
const release = JSON.parse(readFileSync(resolve(FIX, "release.json"), "utf8"));
const refuse = JSON.parse(readFileSync(resolve(FIX, "refuse.json"), "utf8"));
const recs = [...release.recorded, ...refuse.recorded];
const ALLOWED = new Set(["rpc.testnet.near.org", "rpc.mainnet.near.org", "test.rpc.fastnear.com", "rpc.fastnear.com"]);
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const b64url = (s: string) => Buffer.from(s).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
/** A forger who recomputes every hash so the file stays internally consistent. */
function forgedAmount() {
  const e = clone(release.envelope);
  e.order.amount = "500000"; e.core.observed.amount = "500000";
  e.core.order_hash = hashHex(canonicalize(e.order)); e.core_hash = hashHex(canonicalize(e.core));
  return e;
}

let browser: any, dir = "", fileUrl = "";
beforeAll(async () => {
  if (!playwright) throw new Error("Playwright is required for the M6 audit browser tests");
  dir = mkdtempSync(join(tmpdir(), "checker-audit-"));
  const out = join(dir, "index.html");
  await buildChecker(out);
  fileUrl = pathToFileURL(out).href;
  browser = await playwright.chromium.launch();
}, 60_000);
afterAll(async () => { await browser?.close(); });

async function open(url = fileUrl, opts: { delayMs?: number } = {}) {
  const page = await browser.newPage();
  const blocked: string[] = [];
  await page.route("**/*", async (route: any) => {
    const u = new URL(route.request().url());
    if (u.protocol === "file:") return route.continue();
    if (!ALLOWED.has(u.hostname)) { blocked.push(u.hostname); return route.abort(); }
    const req = JSON.parse(route.request().postData() ?? "{}");
    const rec = recs.find((r: any) => r.method === req.method && JSON.stringify(r.params) === JSON.stringify(req.params));
    const body = rec ? rec.response : { jsonrpc: "2.0", id: "x", error: { name: "HANDLER_ERROR", cause: { name: "UNKNOWN_TRANSACTION" } } };
    if (opts.delayMs) await new Promise((r) => setTimeout(r, opts.delayMs));
    return route.fulfill({ status: 200, contentType: "application/json", headers: { "access-control-allow-origin": "*" }, body: JSON.stringify(body) });
  });
  await page.goto(url);
  return { page, blocked };
}
async function checkText(page: any, text: string) {
  await page.fill("#receipt", text);
  await page.click("#check");
  await page.waitForSelector("#result:not([hidden])");
  await page.waitForFunction(() => !(document.getElementById("check") as HTMLButtonElement).disabled);
  return (await page.textContent("#verdict")) as string;
}

describe("M6 audit: checker page", () => {
  it("control: the recorded release is Verified and no host outside the allow-list is contacted", async () => {
    const { page, blocked } = await open();
    expect(await checkText(page, JSON.stringify(release.envelope))).toMatch(/^Verified/);
    expect(blocked).toEqual([]);
    await page.close();
  }, 30_000);

  // M6-03 (Low): a verified refusal is announced as an approved payment.
  it("M6-03 a verified refusal is not announced as 'this payment matches what the buyer approved'", async () => {
    const { page } = await open();
    const verdict = await checkText(page, JSON.stringify(refuse.envelope));
    expect(verdict).toMatch(/^Verified/); // control: the refusal itself checks out
    expect(verdict).not.toMatch(/payment matches what the buyer approved/);
    await page.close();
  }, 30_000);

  // M6-04 (Medium): the verdict is not bound to the receipt on screen.
  it("M6-04 a slow earlier check cannot paint 'Verified' over a later, forged receipt", async () => {
    const d = mkdtempSync(join(tmpdir(), "checker-race-"));
    const good = join(d, "genuine.json"), bad = join(d, "forged.json");
    const forged = clone(release.envelope); forged.order.amount = "900000"; // fails the file check at once
    writeFileSync(good, JSON.stringify(release.envelope));
    writeFileSync(bad, JSON.stringify(forged));
    const { page } = await open(fileUrl, { delayMs: 300 });
    await page.setInputFiles("#file", good); // genuine: starts a slow chain check
    await page.setInputFiles("#file", bad); // forged: answered at once, red
    await page.waitForTimeout(5_000); // let the genuine check finish
    expect(await page.inputValue("#receipt")).toBe(JSON.stringify(forged));
    expect(await page.textContent("#verdict")).not.toMatch(/^Verified/);
    await page.close();
  }, 30_000);

  it("M6-04 editing the receipt after a check does not leave the old 'Verified' verdict showing", async () => {
    const { page } = await open();
    expect(await checkText(page, JSON.stringify(release.envelope))).toMatch(/^Verified/);
    await page.fill("#receipt", JSON.stringify(forgedAmount())); // not checked yet
    const shown = (await page.isVisible("#result")) ? await page.textContent("#verdict") : "";
    expect(shown).not.toMatch(/^Verified/);
    await page.close();
  }, 30_000);

  // M6-05 (Low): facts of a receipt that failed are still stated as a payment.
  it("M6-05 a receipt that is Not valid does not list 'Paid', 'Amount paid' or 'Paid to' as facts", async () => {
    const { page } = await open();
    expect(await checkText(page, JSON.stringify(forgedAmount()))).toMatch(/^Not valid/);
    expect(await page.textContent("#facts")).not.toMatch(/Amount paid|Paid to|DecisionPaid/);
    await page.close();
  }, 30_000);

  // M6-07 (Low): anyone can rewrite the note of a genuine receipt; the page attributes it to the agent.
  it("M6-07 an edited note on a genuine receipt is not attributed to the agent", async () => {
    const e = clone(release.envelope);
    e.untrusted = { agent_note: "Written by whoever edited this file, not the agent." };
    const { page } = await open();
    expect(await checkText(page, JSON.stringify(e))).toMatch(/^Verified/); // control: the note is outside the core
    expect(await page.textContent("#note h2")).not.toMatch(/from the agent/i);
    await page.close();
  }, 30_000);

  // M6-09 (Low): no anti-framing; the page runs and shows a verdict inside a foreign frame.
  it("M6-09 the checker does not show a verdict while framed by another page", async () => {
    const parent = join(dir, "frame-parent.html");
    writeFileSync(parent, `<!doctype html><meta charset="utf-8"><title>frame</title><iframe id="f" width="900" height="900" src="${fileUrl}#r=${b64url(JSON.stringify(release.envelope))}"></iframe>`);
    const { page } = await open(pathToFileURL(parent).href);
    await page.waitForTimeout(4_000);
    const frame = page.frames().find((f: any) => f.url().startsWith(fileUrl));
    expect(frame, "the checker frame loaded").toBeTruthy();
    const verdict = await frame.evaluate(() => (document.getElementById("result")?.hidden ? "" : document.getElementById("verdict")?.textContent ?? ""));
    expect(verdict).not.toMatch(/^Verified/);
    await page.close();
  }, 30_000);

  // M6-11 (Medium): "Verified ... against the NEAR blockchain" rests on one RPC operator's word.
  it("M6-11 a Verified result with one RPC says whose answers it relied on (or cross-checks by default)", async () => {
    const { page } = await open();
    const verdict = await checkText(page, JSON.stringify(release.envelope));
    expect(verdict).toMatch(/^Verified/);
    const states = await page.$$eval("#checks li", (ls: Element[]) => ls.map((l) => `${l.className}:${l.querySelector("strong")?.textContent}`));
    const crossChecked = states.includes("pass:A second RPC agrees");
    expect(crossChecked || /rpc\.testnet\.near\.org/.test(verdict)).toBe(true);
    await page.close();
  }, 30_000);

  // M6-14 (Info): the page decodes files leniently (BOM stripped), unlike parseEnvelope (M2-07).
  it("M6-14 a receipt file with a byte order mark is rejected as parseEnvelope rejects it", async () => {
    const d = mkdtempSync(join(tmpdir(), "checker-bom-"));
    const f = join(d, "bom.json");
    writeFileSync(f, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(release.envelope))]));
    const { page } = await open();
    await page.setInputFiles("#file", f);
    await page.waitForSelector("#result:not([hidden])");
    await page.waitForFunction(() => !(document.getElementById("check") as HTMLButtonElement).disabled);
    expect(await page.textContent("#verdict")).toMatch(/^Not valid/);
    await page.close();
  }, 30_000);
});
