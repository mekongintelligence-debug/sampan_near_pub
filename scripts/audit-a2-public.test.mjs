// Independent audit A2 (docs/audits/A2.md): the exact public tree (git ls-files minus
// scripts/public-tree.json) against Gate 1. "A2-NN ..." tests assert the REQUIRED behaviour and
// FAIL while the finding is open; "control: ..." tests pass now. Names that must not be public
// are read at run time from private files or built from parts, so this file names none of them.
import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const cfg = JSON.parse(readFileSync(resolve(ROOT, "scripts/public-tree.json"), "utf8"));
const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: ROOT, encoding: "utf8" }).split("\0").filter(Boolean);
const isPublic = (f) => !cfg.exclude.some((e) => (e.endsWith("/") ? f.startsWith(e) : f === e));
const publicFiles = tracked.filter(isPublic).filter((f) => existsSync(resolve(ROOT, f)));
const textOf = (f) => {
  const b = readFileSync(resolve(ROOT, f));
  return b.includes(0) ? null : b.toString("utf8");
};
const hits = (needle) => publicFiles.filter((f) => !f.startsWith("scripts/audit-a2-") && (textOf(f) ?? "").includes(needle));

/** Other hackathon entries named in the private competitor note (first table column only). */
function otherEntries() {
  const p = resolve(ROOT, "docs/competitors.md");
  if (!existsSync(p)) return [];
  const sec = readFileSync(p, "utf8").split("## Hackathon entries close to it")[1]?.split("\n## ")[0] ?? "";
  const names = [];
  for (const line of sec.split("\n")) {
    if (!line.startsWith("| ") || line.startsWith("| Entry") || line.startsWith("|---")) continue;
    const cell = line.split("|")[1].trim();
    const linked = [...cell.matchAll(/\[([^\]]+)\]/g)].map((m) => m[1]);
    names.push(...(linked.length ? linked : cell.split(",").map((s) => s.trim())));
  }
  // Single dictionary words that are also this project's own vocabulary cannot be told apart.
  return names.filter((n) => n.length >= 5 && !/^[A-Z]?[a-z]+$/.test(n));
}

describe("A2-04 the public tree and Gate 1", () => {
  it("control: docs/competitors.md and docs/internal/ are excluded", () => {
    expect(isPublic("docs/competitors.md")).toBe(false);
    expect(isPublic("docs/internal/x.md")).toBe(false);
  });
  it("control: the private competitor note names other entries (so the next test has something to look for)", () => {
    expect(otherEntries().length).toBeGreaterThan(3);
  });
  it("A2-04 no public file names another hackathon entry", () => {
    const found = otherEntries().flatMap((n) => hits(n).map((f) => `${f}: entry #${otherEntries().indexOf(n) + 1}`));
    expect(found).toEqual([]);
  });
  it("A2-04 no public file carries the GitHub organisation handle, even in part", () => {
    const fragment = ["intelli", "gence-de", "bug"].join(""); // built from parts on purpose
    expect(hits(fragment)).toEqual([]);
  });
});
