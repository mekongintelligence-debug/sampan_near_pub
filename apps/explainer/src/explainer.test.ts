// Explainer tour: strict CSP, no network, no unsafe DOM use, banned wording, and a browser run of both outcomes.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { readFileSync, mkdtempSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
// @ts-expect-error plain JS build script
import { buildExplainer } from "../build.mjs";

const require = createRequire(import.meta.url);
let playwright: any = null;
try { playwright = require("playwright"); } catch { /* reported below */ }

const SRC = resolve(import.meta.dirname);
const js = readFileSync(resolve(SRC, "explainer.js"), "utf8");
const css = readFileSync(resolve(SRC, "style.css"), "utf8");
let html = "", fileUrl = "", browser: any;
const hash = (s: string) => `'sha256-${createHash("sha256").update(s).digest("base64")}'`;

beforeAll(async () => {
  const out = join(mkdtempSync(join(tmpdir(), "explainer-")), "index.html");
  buildExplainer(out);
  html = readFileSync(out, "utf8");
  fileUrl = pathToFileURL(out).href;
  if (!playwright) throw new Error("Playwright is required for the explainer browser tests");
  browser = await playwright.chromium.launch();
});
afterAll(async () => { await browser?.close(); });

describe("explainer: static checks", () => {
  it("has a strict CSP with hash-pinned inline script and style, and no network", () => {
    const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)![1];
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain(`script-src ${hash(js)}`);
    expect(csp).toContain(`style-src ${hash(css)}`);
    expect(csp).toContain("connect-src 'none'");
    for (const d of ["img-src 'none'", "font-src 'none'", "object-src 'none'", "base-uri 'none'", "form-action 'none'"]) expect(csp).toContain(d);
    expect(csp).not.toMatch(/unsafe-|https?:/);
  });
  it("loads nothing from outside: no external URLs, scripts or stylesheets", () => {
    expect(html).not.toMatch(/(src|href)="https?:/);
    expect(html).not.toMatch(/<link\b/);
    expect(js).not.toMatch(/https?:\/\//);
  });
  it("renders with textContent only: no innerHTML, eval, network or storage calls", () => {
    for (const bad of [/innerHTML/, /outerHTML/, /insertAdjacentHTML/, /document\.write/, /\beval\(/, /new Function/, /\bfetch\(/, /XMLHttpRequest/, /WebSocket/, /localStorage|sessionStorage|indexedDB/]) expect(js).not.toMatch(bad);
  });
  it("follows the wording rules (no firewall, unstoppable, x402, volume claims)", () => {
    const all = `${html}\n${js}`;
    expect(all).not.toMatch(/\bfirewall\b|\bunstoppable\b|\bx402\b|agent volume/i);
  });
  it("says it is an illustration and that the receipts are from testnet", () => {
    expect(html).toMatch(/Illustration/);
    expect(html).toMatch(/testnet/);
  });
});

async function open(): Promise<{ page: any; requests: string[]; errors: string[] }> {
  const page = await browser.newPage();
  const requests: string[] = [], errors: string[] = [];
  page.on("request", (r: any) => { if (!r.url().startsWith("file:")) requests.push(r.url()); });
  page.on("console", (m: any) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e: any) => errors.push(String(e)));
  await page.goto(fileUrl);
  return { page, requests, errors };
}
const nextN = async (page: any, n: number) => { for (let k = 0; k < n; k++) await page.click("#next"); };

describe("explainer: browser", () => {
  it("walks all steps with the buttons and the keyboard, and makes no network request", async () => {
    const { page, requests, errors } = await open();
    expect(await page.textContent("#count")).toBe("Step 1 of 8");
    expect(await page.isDisabled("#back")).toBe(true);
    await nextN(page, 7);
    expect(await page.textContent("#count")).toBe("Step 8 of 8");
    expect(await page.isDisabled("#next")).toBe(true);
    await page.keyboard.press("ArrowLeft");
    expect(await page.textContent("#count")).toBe("Step 7 of 8");
    expect(requests).toEqual([]);
    expect(errors).toEqual([]);
    await page.close();
  });
  it("matching order: every rule passes, released, checker green", async () => {
    const { page } = await open();
    await nextN(page, 4); // rules step
    expect(await page.locator(".rules li.fail").count()).toBe(0);
    expect(await page.locator(".rules li.pass").count()).toBe(9);
    await page.click("#next");
    expect(await page.textContent(".verdict")).toMatch(/Released/);
    await page.click("#next");
    expect(await page.textContent(".verdict")).toMatch(/matches what the buyer signed/);
    await page.close();
  });
  it("order to another shop: only the payee rule fails, refused, checker red, with text not colour alone", async () => {
    const { page } = await open();
    await nextN(page, 3); // choose-the-order step
    await page.check('input[value="other"]');
    await page.click("#next");
    expect(await page.locator(".rules li.fail").count()).toBe(1);
    expect(await page.locator(".rules li.fail").textContent()).toMatch(/Fails.*payee/);
    await page.click("#next");
    expect(await page.textContent(".verdict")).toMatch(/Refused: nothing is paid/);
    await page.click("#next");
    expect(await page.textContent(".verdict")).toMatch(/refused/);
    await page.close();
  });
  it("the last step links to the checker, the shop and the home page", async () => {
    const { page } = await open();
    await nextN(page, 7);
    const hrefs = await page.$$eval(".links a", (as: any[]) => as.map((a) => a.getAttribute("href")));
    expect(hrefs).toEqual(["../checker/", "../shop/", "../"]);
    await page.close();
  });
});
