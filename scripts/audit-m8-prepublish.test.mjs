// Audit M8 (independent): exploit tests for scripts/prepublish-check.mjs.
// Each "M8-NN ..." test asserts the REQUIRED behaviour, so it fails while its finding is open.
// "control: ..." tests pass now and must keep passing.
//
// Each test builds a small throw-away git repository that holds the real check script, the
// banned-pattern lint, the secrets scan and its config, plus a minimal public tree that passes
// every check. One file is then added or changed, and the check is run on that repository.
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const COPY = ["scripts/prepublish-check.mjs", "scripts/lint-banned.mjs", "scripts/secrets-scan.sh", ".gitleaks.toml"];

// The check script names the phrase in its own header (M8-09), so the harness keeps it out of
// the tree it checks.
function repo(extra = {}, exclude = ["docs/internal/", "scripts/prepublish-check.mjs"]) {
  const dir = mkdtempSync(join(tmpdir(), "audit-m8-pp-"));
  for (const f of COPY) {
    mkdirSync(dirname(join(dir, f)), { recursive: true });
    copyFileSync(resolve(ROOT, f), join(dir, f));
  }
  const files = {
    "scripts/public-tree.json": JSON.stringify({ decided: true, exclude }),
    "README.md": "# Demo\n\nSee [the disclosures](HACKATHON.md).\n",
    "HACKATHON.md": "# Hackathon disclosures\n- Team name: Demo\n",
    "docs/internal/notes.md": "internal only\n",
    ...extra,
  };
  for (const [f, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, f)), { recursive: true });
    writeFileSync(join(dir, f), text);
  }
  const git = (...a) => spawnSync("git", a, { cwd: dir, encoding: "utf8" });
  git("init", "-q");
  git("add", "-A");
  return dir;
}

function check(dir, ...args) {
  const r = spawnSync(process.execPath, [join(dir, "scripts/prepublish-check.mjs"), ...args], { cwd: dir, encoding: "utf8" });
  return { status: r.status, out: r.stdout + r.stderr };
}

const MI = ["Mekong", "Intelligence"].join(" "); // built at run time so this file does not trip the check itself

describe("audit M8: prepublish-check", () => {
  it("control: a minimal clean public tree is ready to publish", () => {
    const r = check(repo());
    expect(r.out).toMatch(/Ready to publish/);
    expect(r.status).toBe(0);
  });

  it("control: the internal-material phrase in a Markdown file blocks publishing", () => {
    const r = check(repo({ "docs/plan.md": `Owned by ${MI}.\n` }));
    expect(r.status).toBe(1);
  });

  it("M8-02 the internal-material phrase in a shell script blocks publishing", () => {
    const r = check(repo({ "scripts/setup.sh": `#!/bin/sh\n# maintained by ${MI}\n` }));
    expect(r.status, r.out).toBe(1);
  });

  it("M8-02 the internal-material phrase in a file without an extension (Makefile, git hook) blocks publishing", () => {
    const r = check(repo({ Makefile: `# ${MI} build\nall:\n\ttrue\n` }));
    expect(r.status, r.out).toBe(1);
  });

  it("M8-02 the organisation's name written as one word (its GitHub handle) blocks publishing", () => {
    const handle = ["mekong", "intelligence"].join("") + "-debug";
    const r = check(repo({ "README.md": `# Demo\n\nClone: https://github.com/${handle}/repo\n\nSee [the disclosures](HACKATHON.md).\n` }));
    expect(r.status, r.out).toBe(1);
  });

  it("M8-03 a title with banned wording in docs/audits/ blocks publishing (audit reports are in the public tree)", () => {
    const r = check(repo({ "docs/audits/M9.md": "# Audit of the payment " + "fire" + "wall\n" }));
    expect(r.status, r.out).toBe(1);
  });

  it("M8-04 a reference-style Markdown link to an excluded file is reported as broken", () => {
    const r = check(repo({ "README.md": "# Demo\n\nSee [the notes][n].\n\n[n]: docs/internal/notes.md\n" }));
    expect(r.status, r.out).toBe(1);
  });

  it("M8-04 an HTML link in Markdown to an excluded file is reported as broken", () => {
    const r = check(repo({ "README.md": '# Demo\n\n<a href="docs/internal/notes.md">notes</a>\n' }));
    expect(r.status, r.out).toBe(1);
  });

  it("M8-05 --export writes nothing when the tree is not ready to publish", () => {
    const dir = repo({ "docs/plan.md": `Owned by ${MI}.\n` });
    const dest = join(mkdtempSync(join(tmpdir(), "audit-m8-export-")), "public");
    const r = check(dir, "--export", dest);
    expect(r.status).toBe(1);
    expect(existsSync(dest), "a failing tree was exported").toBe(false);
  });
});
