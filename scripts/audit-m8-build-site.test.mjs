// Audit M8 (independent): tests for scripts/build-site.mjs.
// "M8-NN ..." tests assert the REQUIRED behaviour and fail while the finding is open.
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const SCRIPT = resolve(import.meta.dirname, "build-site.mjs");
const USDC = "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";

describe("audit M8: build-site", () => {
  it("M8-06 building into a directory that is not a previous site build does not delete what is in it", () => {
    // `node scripts/build-site.mjs .` or a mistyped path runs rmSync(recursive, force) on it.
    const target = join(mkdtempSync(join(tmpdir(), "audit-m8-site-")), "work");
    mkdirSync(target, { recursive: true });
    writeFileSync(join(target, "keep.txt"), "a person's file\n");
    spawnSync(process.execPath, [SCRIPT, target], { encoding: "utf8" });
    expect(existsSync(join(target, "keep.txt")), "build-site deleted a file it did not create").toBe(true);
  });

  describe("the built public site", () => {
    const out = join(mkdtempSync(join(tmpdir(), "audit-m8-site-")), "site");
    const r = spawnSync(process.execPath, [SCRIPT, out], { encoding: "utf8" });
    const shop = () => readFileSync(join(out, "shop/index.html"), "utf8");

    it("control: the site builds", () => {
      expect(r.status, r.stderr).toBe(0);
    });

    it("control: the landing page and checker carry a strict CSP and run no inline script", () => {
      for (const f of ["index.html", "checker/index.html"]) {
        const html = readFileSync(join(out, f), "utf8");
        expect(html).toMatch(/Content-Security-Policy" content="default-src 'none'/);
        expect(html).not.toMatch(/script-src[^"]*'unsafe-inline'/);
      }
      expect(readFileSync(join(out, "index.html"), "utf8")).not.toMatch(/<script/);
    });

    it("M8-07 the public dry shop asks 1Click for an asset 1Click can quote (mainnet USDC, not the testnet mock token)", () => {
      // Live 1Click answers the shop's dry request with 400 "tokenOut is not valid" (checked 7 Nov 2026),
      // so the landing page's "dry checkout preview" shows an error to every visitor.
      const html = shop();
      expect(html).toMatch(/data-mode="dry"/);
      expect(html).toMatch(new RegExp(`data-asset="${USDC}"`));
      expect(html).toMatch(/data-network="mainnet"/);
    });

    it("M8-07 the public dry shop's CSP lets the page reach no loopback relayer on the visitor's machine", () => {
      expect(shop()).not.toMatch(/connect-src[^"]*(127\.0\.0\.1|localhost)/);
    });
  });
});
