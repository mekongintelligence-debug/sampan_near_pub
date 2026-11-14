// M9 prep: the static public site holds exactly what judges need, with security headers.
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

describe("static public site", () => {
  const out = join(mkdtempSync(join(tmpdir(), "site-")), "site");
  const r = spawnSync(process.execPath, [resolve(import.meta.dirname, "build-site.mjs"), out], { encoding: "utf8" });
  it("builds the landing page, checker, dry shop, receipts and headers", () => {
    expect(r.status, r.stderr).toBe(0);
    for (const f of ["index.html", "checker/index.html", "shop/index.html", "shop/sampan-checkout.js", "_headers", "examples/testnet/agent-refusal.json"]) expect(existsSync(join(out, f)), f).toBe(true);
  });
  it("the shop is in dry mode and every page has a strict CSP; framing is refused by header", () => {
    expect(readFileSync(join(out, "shop/index.html"), "utf8")).toMatch(/data-mode="dry"/);
    for (const f of ["index.html", "checker/index.html", "shop/index.html"]) expect(readFileSync(join(out, f), "utf8")).toMatch(/Content-Security-Policy" content="default-src 'none'/);
    expect(readFileSync(join(out, "_headers"), "utf8")).toMatch(/frame-ancestors 'none'/);
  });
  it("vercel.json carries the same security headers as _headers (framing refused by header on Vercel too)", () => {
    const v = JSON.parse(readFileSync(join(out, "vercel.json"), "utf8"));
    const h = Object.fromEntries(v.headers[0].headers.map((x) => [x.key, x.value]));
    expect(v.headers[0].source).toBe("/(.*)");
    expect(h["Content-Security-Policy"]).toBe("frame-ancestors 'none'");
    expect(h["X-Frame-Options"]).toBe("DENY");
    for (const k of Object.keys(h)) expect(readFileSync(join(out, "_headers"), "utf8"), k).toContain(`${k}: ${h[k]}`);
  });
  it("the landing page links only to files in the site", () => {
    const html = readFileSync(join(out, "index.html"), "utf8");
    for (const m of html.matchAll(/href="([^"]+)"/g)) expect(existsSync(join(out, m[1].endsWith("/") ? m[1] + "index.html" : m[1])), m[1]).toBe(true);
  });
});
