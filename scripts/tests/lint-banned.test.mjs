import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import { cpSync } from "node:fs";
import { resolve } from "node:path";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { lint } from "../lint-banned.mjs";

let root;
const put = (rel, text) => {
  const p = join(root, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, text);
};
const rules = () => lint(root).map((f) => `${f.file}:${f.rule}`).sort();

beforeEach(() => { root = mkdtempSync(join(tmpdir(), "lint-banned-")); });
afterEach(() => { rmSync(root, { recursive: true, force: true }); });

describe("code rules (apps/ and packages/)", () => {
  it("flags innerHTML, outerHTML, insertAdjacentHTML and document.write", () => {
    put("apps/checker/src/a.ts", "el.innerHTML = x;\n");
    put("apps/checker/src/b.ts", "el.outerHTML= x;\n");
    put("packages/receipt/src/c.js", "el.insertAdjacentHTML('beforeend', x)\n");
    put("apps/test-shop/index.html", "<script>document.write(x)</script>\n");
    expect(rules()).toEqual([
      "apps/checker/src/a.ts:no-innerhtml",
      "apps/checker/src/b.ts:no-innerhtml",
      "apps/test-shop/index.html:no-innerhtml",
      "packages/receipt/src/c.js:no-innerhtml",
    ]);
  });

  it("flags eval and new Function but not names that merely contain eval", () => {
    put("apps/x/a.ts", "const r = eval(s);\n");
    put("apps/x/b.ts", "const f = new Function('a', s);\n");
    put("apps/x/c.ts", "const ok = retrieval(s); obj.evaluate(s);\n");
    expect(rules()).toEqual(["apps/x/a.ts:no-eval", "apps/x/b.ts:no-eval"]);
  });

  it("flags += and bracket assignment, not comparisons (review finding M0-CR2)", () => {
    put("apps/x/a.ts", "el.innerHTML += x;\n");
    put("apps/x/b.ts", "el['outerHTML'] = x;\n");
    put("apps/x/c.ts", "if (el.innerHTML == x || el.innerHTML === y) {}\n");
    put("apps/x/d.ts", "document.writeln(x)\n");
    expect(rules()).toEqual(["apps/x/a.ts:no-innerhtml", "apps/x/b.ts:no-innerhtml", "apps/x/d.ts:no-innerhtml"]);
  });

  it("allows textContent and reading innerHTML", () => {
    put("apps/checker/src/ok.ts", "el.textContent = x; const h = el.innerHTML;\n");
    expect(rules()).toEqual([]);
  });

  it("does not lint fixtures, node_modules, target or test files", () => {
    put("fixtures/attacks/a.ts", "el.innerHTML = x; eval(s)\n");
    put("node_modules/p/a.js", "eval(s)\n");
    put("target/a.js", "eval(s)\n");
    put("apps/checker/src/a.test.ts", "el.innerHTML = '<b>tamper</b>'\n");
    expect(rules()).toEqual([]);
  });
});

describe("wording rules (public documents)", () => {
  it("flags firewall in a heading, unstoppable and x402 in public docs", () => {
    put("README.md", "# A payment firewall\n");
    put("HACKATHON.md", "Intents are unstoppable.\n");
    put("docs/PLAN.md", "x402 settled $1M\n");
    expect(rules()).toEqual([
      "HACKATHON.md:no-unstoppable",
      "README.md:no-firewall-title",
      "docs/PLAN.md:no-x402",
    ]);
  });

  it("allows firewall in body text and quoted rule statements", () => {
    put("README.md", "Not a firewall: a gate.\nNever use \"firewall\" in a title; never cite `x402` figures.\n");
    expect(rules()).toEqual([]);
  });

  it("a quoted rule statement does not exempt the rest of the line (review finding M0-CR3)", () => {
    put("README.md", "Not a \"firewall\": Intents are unstoppable and x402 settled $1M\n");
    expect(rules()).toEqual(["README.md:no-unstoppable", "README.md:no-x402"]);
  });

  it("skips docs/internal and docs/audits", () => {
    put("docs/internal/a.md", "# firewall\nx402 unstoppable\n");
    put("docs/audits/A2.md", "x402\n");
    expect(rules()).toEqual([]);
  });

  it("is case-insensitive", () => {
    put("README.md", "## Firewall for agents\nUNSTOPPABLE\nX402\n");
    expect(rules()).toEqual(["README.md:no-firewall-title", "README.md:no-unstoppable", "README.md:no-x402"]);
  });
});

describe("command line (review finding M0-CR1)", () => {
  it("still runs and fails when the repository path contains a space", () => {
    const spaced = join(root, "my repo");
    mkdirSync(join(spaced, "apps/x"), { recursive: true });
    cpSync(resolve(import.meta.dirname, ".."), join(spaced, "scripts"), { recursive: true });
    writeFileSync(join(spaced, "apps/x/a.ts"), "el.innerHTML = x;\n");
    const r = spawnSync("node", [join(spaced, "scripts/lint-banned.mjs"), spaced], { encoding: "utf8" });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/no-innerhtml/);
  });

  it("does not follow symlinks out of the tree", () => {
    put("apps/x/ok.ts", "el.textContent = x;\n");
    const outside = mkdtempSync(join(tmpdir(), "outside-"));
    writeFileSync(join(outside, "bad.ts"), "eval(s)\n");
    spawnSync("ln", ["-s", outside, join(root, "apps/x/link")]);
    expect(rules()).toEqual([]);
    rmSync(outside, { recursive: true, force: true });
  });
});

describe("Rust contract rules (audit M0-05)", () => {
  it("flags env::panic_str and clippy allows outside the test module, including after it", () => {
    put("contracts/gate/src/lib.rs", [
      "pub fn a() { near_sdk::env::panic_str(\"x\") }",
      "#[cfg(test)]",
      "mod tests {",
      "    fn t() { near_sdk::env::panic_str(\"ok in tests\") }",
      "}",
      "#[allow(clippy::unwrap_used)]",
      "pub fn b() { env::abort() }",
    ].join("\n") + "\n");
    expect(lint(root).map((f) => `${f.line}:${f.rule}`).sort()).toEqual(["1:no-contract-panic-call", "6:no-lint-allow", "7:no-contract-panic-call"]);
  });
});
