// A3-01 regression: the live checker looked dead. (1) The default RPC must be an archival host, because a
// regular RPC forgets transactions after about a day and the checks of any older receipt timed out;
// (2) while a check runs, the page must say so, and the message must go away when the verdict is shown.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createRequire } from "node:module";
import { readFileSync, mkdtempSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { DEFAULT_RPC, ALLOWED_RPC_HOSTS } from "./rpc.ts";
// @ts-expect-error plain JS build script
import { buildChecker } from "../build.mjs";

const require = createRequire(import.meta.url);
let playwright: any = null;
try { playwright = require("playwright"); } catch { /* reported below */ }

const release = JSON.parse(readFileSync(resolve(import.meta.dirname, "../test/fixtures/release.json"), "utf8"));
let browser: any, fileUrl = "";

beforeAll(async () => {
  if (!playwright) throw new Error("Playwright is required for the checker browser tests");
  const out = join(mkdtempSync(join(tmpdir(), "checker-progress-")), "index.html");
  await buildChecker(out);
  fileUrl = pathToFileURL(out).href;
  browser = await playwright.chromium.launch();
});
afterAll(async () => { await browser?.close(); });

describe("A3-01: default RPC and progress", () => {
  it("the default RPC of each network is an archival host that the page CSP allows", () => {
    for (const net of ["testnet", "mainnet"] as const) {
      const host = new URL(DEFAULT_RPC[net]).hostname;
      expect(host).toBe(`archival-rpc.${net}.near.org`);
      expect(ALLOWED_RPC_HOSTS).toContain(host);
    }
  });
  it("shows a progress message while a check is pending, and hides it when the verdict appears", async () => {
    const page = await browser.newPage();
    const recs = release.recorded;
    let release_: () => void = () => {};
    const gate = new Promise<void>((r) => { release_ = r; });
    await page.route("**/*", async (route: any) => {
      const url = new URL(route.request().url());
      if (url.protocol === "file:") return route.continue();
      await gate; // hold every RPC answer until the test has looked at the page
      const req = JSON.parse(route.request().postData() ?? "{}");
      const rec = recs.find((r: any) => r.method === req.method && JSON.stringify(r.params) === JSON.stringify(req.params));
      const body = rec ? rec.response : { jsonrpc: "2.0", id: "x", error: { name: "HANDLER_ERROR", cause: { name: "UNKNOWN_TRANSACTION" } } };
      return route.fulfill({ status: 200, contentType: "application/json", headers: { "access-control-allow-origin": "*" }, body: JSON.stringify(body) });
    });
    await page.goto(fileUrl);
    expect(await page.isHidden("#progress")).toBe(true);
    await page.fill("textarea", JSON.stringify(release.envelope));
    await page.click("#check");
    await page.waitForSelector("#progress", { state: "visible" });
    expect(await page.textContent("#progress")).toMatch(/Checking against the NEAR chain/);
    expect(await page.isDisabled("#check")).toBe(true);
    release_();
    await page.waitForFunction(() => (document.getElementById("verdict") as HTMLElement).innerText.length > 0, undefined, { timeout: 20_000 });
    expect(await page.isHidden("#progress")).toBe(true);
    expect(await page.isDisabled("#check")).toBe(false);
    await page.close();
  }, 40_000);
});
