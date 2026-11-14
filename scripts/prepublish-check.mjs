#!/usr/bin/env node
// Pre-publish check (M9 / A2): what would become public, and is it safe to publish?
//   node scripts/prepublish-check.mjs            check the would-be public tree (exit 1 on any problem)
//   node scripts/prepublish-check.mjs --export <dir>   also copy that tree to <dir> (fresh history is made by a person)
//
// The public tree is every file git tracks, minus the paths in scripts/public-tree.json
// (the Gate 1 decision, docs/gates.md; the lead fills it in by 12 Nov). Checks on that tree:
//  1. nothing from docs/internal/ and no mention of the company that runs the project (the phrase,
//     spaced or as one word, e.g. its GitHub handle), in any text file;
//  2. banned wording and unsafe patterns (scripts/lint-banned.mjs);
//  3. secrets (scripts/secrets-scan.sh --dir on the exported copy);
//  4. every relative link in Markdown files resolves inside the public tree;
//  5. HACKATHON.md has no unfilled `[__]` fields;
//  6. A2F-01: no graphify output in the public tree, and no public file names a path, or repeats a
//     Markdown heading, of a file that scripts/public-tree.json excludes.
// It never publishes, pushes or posts anything. A person does that (CLAUDE.md).
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, normalize, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const cfg = JSON.parse(readFileSync(resolve(ROOT, "scripts/public-tree.json"), "utf8"));
const problems = [];
const say = (ok, text) => { if (!ok) problems.push(text); console.log(`${ok ? "OK  " : "FAIL"}  ${text}`); };

const tracked = spawnSync("git", ["ls-files", "-z"], { cwd: ROOT, encoding: "utf8" }).stdout.split("\0").filter(Boolean);
const excluded = (f) => cfg.exclude.some((p) => (p.endsWith("/") ? f.startsWith(p) : f === p));
const files = tracked.filter((f) => !excluded(f) && existsSync(resolve(ROOT, f)));
console.log(`public tree: ${files.length} of ${tracked.length} tracked files (excluded by scripts/public-tree.json: ${tracked.length - files.length})`);
if (cfg.decided !== true) say(false, "the Gate 1 decision is not recorded yet (scripts/public-tree.json \"decided\": false); the tree below is the draft");

// 1. internal material
say(!files.some((f) => f.startsWith("docs/internal/")), "nothing from docs/internal/ is in the public tree");
// The phrase is built at run time so this file does not contain it (M8-09). Every text file is
// read, whatever its extension (M8-02); a file with a NUL byte counts as binary.
const PHRASE = new RegExp(["mek", "ong"].join("") + "[\\s_-]*" + ["intel", "ligence"].join(""), "i");
const mi = files.filter((f) => {
  const buf = readFileSync(resolve(ROOT, f));
  return !buf.includes(0) && PHRASE.test(buf.toString("utf8"));
});
say(mi.length === 0, `no mention of the company that runs the project in the public tree${mi.length ? `: ${mi.slice(0, 5).join(", ")}` : ""}`);

// Copy the tree to a scratch directory for the tools that scan a directory.
const out = mkdtempSync(join(tmpdir(), "public-tree-"));
for (const f of files) {
  mkdirSync(dirname(join(out, f)), { recursive: true });
  cpSync(resolve(ROOT, f), join(out, f));
}

// 2. banned wording and unsafe patterns
const lint = spawnSync(process.execPath, [resolve(ROOT, "scripts/lint-banned.mjs"), out, "--public"], { encoding: "utf8" }); // audit reports included (M8-03)
say(lint.status === 0, `banned wording and unsafe patterns: ${(lint.stdout + lint.stderr).trim().split("\n").slice(-1)[0]}`);

// 3. secrets
const sec = spawnSync(resolve(ROOT, "scripts/secrets-scan.sh"), ["--dir", out], { cwd: ROOT, encoding: "utf8" });
say(sec.status === 0, `secrets scan of the public tree${sec.status === 0 ? "" : `: ${(sec.stdout + sec.stderr).trim().split("\n").slice(-2).join(" ")}`}`);

// 4. relative links in Markdown
const set = new Set(files);
const broken = [];
for (const f of files.filter((x) => x.endsWith(".md"))) {
  // Code spans and fenced blocks show syntax, not links.
  const text = readFileSync(resolve(ROOT, f), "utf8").replace(/```[\s\S]*?```/g, "").replace(/`[^`\n]*`/g, "");
  // Inline links, reference definitions and HTML href/src (M8-04).
  const targets = [
    ...[...text.matchAll(/\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)].map((m) => m[1]),
    ...[...text.matchAll(/^\s{0,3}\[[^\]]+\]:\s*<?([^\s>]+)>?/gm)].map((m) => m[1]),
    ...[...text.matchAll(/\b(?:href|src)\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]),
  ];
  for (const raw of targets) {
    const m = [null, raw];
    const target = m[1].split("#")[0];
    if (!target || /^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith("//")) continue; // external or anchor-only
    let decoded;
    try { decoded = decodeURIComponent(target); } catch { broken.push(`${f} -> ${raw}`); continue; }
    // A leading "/" means the repository root, as GitHub renders it.
    const p = normalize(decoded.startsWith("/") ? decoded.slice(1) : join(dirname(f), decoded)).replace(/\/$/, "");
    if (!set.has(p) && !files.some((x) => x.startsWith(p + "/"))) broken.push(`${f} -> ${m[1]}`);
  }
}
say(broken.length === 0, `relative links resolve inside the public tree${broken.length ? `: ${broken.slice(0, 6).join("; ")}` : ""}`);

// 5. disclosures filled in
const hk = set.has("HACKATHON.md") ? readFileSync(resolve(ROOT, "HACKATHON.md"), "utf8") : "";
const blanks = (hk.match(/\[__\]/g) ?? []).length;
say(hk !== "" && blanks === 0, `HACKATHON.md is present and complete${blanks ? ` (${blanks} unfilled fields)` : ""}`);

// 6. leaks of excluded material (A2F-01). Generated graphs (graphify-out/) list the headings and
// paths of every document, so they must never be public. A path or heading of an excluded file
// appearing in a public file means private structure leaked. This script and the config that
// lists the excluded paths are the only places allowed to name them.
const GRAPH_OUTPUT = /(^|\/)graphify-out(\/|$)|(^|\/)(graph\.json|graph\.html|GRAPH_REPORT\.md)$/;
const graphFiles = files.filter((f) => GRAPH_OUTPUT.test(f));
say(graphFiles.length === 0, `no graphify output in the public tree${graphFiles.length ? `: ${graphFiles.slice(0, 5).join(", ")}` : ""}`);
const SELF = new Set(["scripts/prepublish-check.mjs", "scripts/public-tree.json"]);
// Paths under an excluded directory (docs/internal/...) must never be named. Excluded single files
// (CLAUDE.md, docs/MILESTONES.md) are named by ordinary public docs today, so those are listed as
// a warning only; headings, which carry the private structure, always fail.
const secretPaths = new Set();
const namedPaths = new Set(cfg.exclude.filter((p) => !p.endsWith("/")));
const secretHeadings = new Map();
for (const f of tracked.filter((t) => excluded(t) && existsSync(resolve(ROOT, t)))) {
  if (cfg.exclude.some((p) => p.endsWith("/") && f.startsWith(p))) secretPaths.add(f);
  if (!f.endsWith(".md")) continue;
  for (const m of readFileSync(resolve(ROOT, f), "utf8").replace(/```[\s\S]*?```/g, "").matchAll(/^#{1,6}[ \t]+(\S.*?)[ \t#]*$/gm)) {
    if (m[1].length >= 20) secretHeadings.set(m[1], f);
  }
}
const leaks = [];
for (const f of files) {
  if (SELF.has(f)) continue;
  const buf = readFileSync(resolve(ROOT, f));
  if (buf.includes(0)) continue;
  const text = buf.toString("utf8");
  for (const p of secretPaths) if (text.includes(p)) leaks.push(`${f} names ${p}`);
  // A heading line is compared whole; short, generic headings (under 20 characters) are ignored.
  if (f.endsWith(".md") || f.endsWith(".json")) for (const [h, src] of secretHeadings) if (new RegExp(`^(#{1,6}[ \\t]+)?${h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[ \\t#]*$|"${h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`, "m").test(text)) leaks.push(`${f} repeats a heading of ${src}`);
}
const warned = files.filter((f) => !SELF.has(f) && !readFileSync(resolve(ROOT, f)).includes(0) && [...namedPaths].some((p) => readFileSync(resolve(ROOT, f), "utf8").includes(p)));
if (warned.length) console.log(`NOTE  ${warned.length} public file(s) name an excluded single file (links may dangle once published): ${warned.slice(0, 4).join(", ")}${warned.length > 4 ? ", ..." : ""}`);
say(leaks.length === 0, `no path or heading of an excluded file appears in the public tree${leaks.length ? `: ${leaks.slice(0, 40).join("; ")}` : ""}`);

const i = process.argv.indexOf("--export");
if (i > 0 && process.argv[i + 1] && problems.length) {
  console.log("not exported: the tree is not ready to publish (M8-05)");
} else if (i > 0 && process.argv[i + 1]) {
  cpSync(out, resolve(process.argv[i + 1]), { recursive: true });
  console.log(`exported the public tree to ${process.argv[i + 1]} (no git history; a person creates the public repository)`);
}
rmSync(out, { recursive: true, force: true });
console.log(problems.length ? `\n${problems.length} problem(s): not ready to publish` : "\nReady to publish (a person publishes).");
process.exit(problems.length ? 1 : 0);
