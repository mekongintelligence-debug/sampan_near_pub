// Regression tests for audit finding A2F-01 (High): generated graph output (graphify-out/) named
// private documents and their headings, and was tracked, so it would have become public.
// prepublish-check must now fail on graph output and on any public file that repeats a heading of,
// or names a path inside, material that scripts/public-tree.json excludes.
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const COPY = ["scripts/prepublish-check.mjs", "scripts/lint-banned.mjs", "scripts/secrets-scan.sh", ".gitleaks.toml"];
const EXCLUDE = ["docs/internal/", "docs/private-plan.md", "graphify-out/", "scripts/prepublish-check.mjs"];
const HEADING = "Settlement timing and fee schedule";

function run(extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), "a2f01-"));
  for (const f of COPY) {
    mkdirSync(dirname(join(dir, f)), { recursive: true });
    copyFileSync(resolve(ROOT, f), join(dir, f));
  }
  const files = {
    "scripts/public-tree.json": JSON.stringify({ decided: true, exclude: EXCLUDE }),
    "README.md": "# Demo\n\nSee [the disclosures](HACKATHON.md).\n",
    "HACKATHON.md": "# Hackathon disclosures\n- Team name: Demo\n",
    "docs/internal/notes.md": "internal only\n",
    "docs/private-plan.md": `# Plan\n\n## ${HEADING}\n\nprivate\n`,
    ...extra,
  };
  for (const [f, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, f)), { recursive: true });
    writeFileSync(join(dir, f), text);
  }
  spawnSync("git", ["init", "-q"], { cwd: dir });
  spawnSync("git", ["add", "-A", "-f"], { cwd: dir });
  const r = spawnSync(process.execPath, [join(dir, "scripts/prepublish-check.mjs")], { cwd: dir, encoding: "utf8" });
  return { status: r.status, out: r.stdout + r.stderr };
}

describe("A2F-01: private structure must not reach the public tree", () => {
  it("control: a clean tree with private files excluded is ready", () => {
    const r = run();
    expect(r.status, r.out).toBe(0);
  });

  it("A2F-01 graph output outside the excluded folder fails", () => {
    const r = run({ "tools/graphify-out/graph.json": "{}\n" });
    expect(r.status, r.out).toBe(1);
    expect(r.out).toMatch(/graphify output/);
  });

  it("A2F-01 a graph file kept under another name fails (GRAPH_REPORT.md)", () => {
    const r = run({ "docs/GRAPH_REPORT.md": "# Report\n" });
    expect(r.status, r.out).toBe(1);
  });

  it("A2F-01 a public file repeating a heading of an excluded document fails", () => {
    const r = run({ "docs/report.md": `# Report\n\n## ${HEADING}\n\ntext\n` });
    expect(r.status, r.out).toBe(1);
    expect(r.out).toMatch(/repeats a heading of docs\/private-plan\.md/);
  });

  it("A2F-01 a generated JSON listing an excluded heading fails", () => {
    const r = run({ "docs/graph.txt.json": JSON.stringify({ nodes: [{ label: HEADING }] }) });
    expect(r.status, r.out).toBe(1);
  });

  it("A2F-01 a public file naming a path inside an excluded folder fails", () => {
    const r = run({ "docs/audit.md": "# Audit\n\nSee docs/internal/notes.md\n" });
    expect(r.status, r.out).toBe(1);
  });

  it("control: a short generic heading shared with a private document is not a leak", () => {
    const r = run({ "docs/private-plan.md": "# Plan\n\n## Overview\n", "docs/readme2.md": "# Other\n\n## Overview\n" });
    expect(r.status, r.out).toBe(0);
  });
});
