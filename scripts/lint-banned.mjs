#!/usr/bin/env node
// Banned-pattern lint. Part of `make check` and `make security`.
// Finds unsafe code patterns and banned wording that other tools do not cover.
// Usage: node scripts/lint-banned.mjs [rootDir]   (exit 1 on any finding)
//
// In a git checkout it lints the files git tracks or would add (so ignored build
// output is skipped wherever it lives); elsewhere it walks the tree.
import { readdirSync, readFileSync, lstatSync, statSync, realpathSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { join, relative, sep } from "node:path";

// Directories never linted, at any depth.
const SKIP_ANYWHERE = new Set(["node_modules", ".git", ".pnpm-store"]);
// Directories skipped only at the repository root (data and build output).
// `fixtures/` holds attack strings and test vectors: data, never linted.
const SKIP_AT_ROOT = new Set(["fixtures", "target", "dist", "coverage"]);

const CODE_EXT = /\.(c|m)?[jt]sx?$|\.html?$/;
const TEST_FILE = /\.(test|spec)\.(c|m)?[jt]sx?$/;

// --- JavaScript / TypeScript / HTML in apps/ and packages/ --------------------------
const HTML_SINK = /(\.|\[\s*["'`])(innerHTML|outerHTML|srcdoc)(["'`]\s*\])?\s*(\+|\|\||\?\?|&&)?=(?!=)|\b(innerHTML|outerHTML|srcdoc)\s*:|insertAdjacentHTML\s*\(|setHTMLUnsafe\s*\(|createContextualFragment\s*\(|document\.write(ln)?\s*\(/;
const CODE_RULES = [
  { id: "no-innerhtml", re: HTML_SINK, why: "render untrusted text with textContent only" },
  { id: "no-eval", re: /(^|[^\w$])eval\s*\)?\s*\(|\.eval\s*\(|\bnew\s+Function\s*\(|(^|[^\w$.])Function\s*\(|\bset(Timeout|Interval)\s*\(\s*["'`]/, why: "no dynamic code execution" },
];

// --- Rust contract source (outside #[cfg(test)]) -----------------------------------
// Clippy forbids most panics (contracts/gate/src/lib.rs); these are the ones it cannot
// see, because near-sdk's generated code uses them.
const RUST_RULES = [
  { id: "no-contract-panic-call", re: /\benv::(panic_str|abort)\s*\(/, why: "contract code must not panic; return a refusal" },
  { id: "no-lint-allow", re: /#!?\[\s*allow\s*\(\s*clippy::/, why: "do not silence clippy in contract code" },
];

// --- Wording in public documents ----------------------------------------------------
const W = { firewall: /\bfirewall\b/i };
const WORD_RULES = [
  { id: "no-unstoppable", re: /\bunstoppable\b/i, why: "never call Intents unstoppable" },
  { id: "no-x402", re: /\bx402\b/i, why: "never cite x402 figures" },
  { id: "no-agent-volume", re: /\bagent(ic)?[- ](commerce |payment |transaction )?volumes?\b/i, why: "never cite agent volume figures" },
];
const QUOTED_RULE_WORD = /"(firewall|unstoppable|x402|agent volume)"|`(firewall|unstoppable|x402|agent volume)`/gi;

function walk(root, dir = root, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP_ANYWHERE.has(name)) continue;
    if (dir === root && SKIP_AT_ROOT.has(name)) continue;
    const p = join(dir, name);
    const st = lstatSync(p);
    if (st.isSymbolicLink()) {
      // Lint a symlinked file's content; never follow symlinked directories (loops).
      if (existsSync(p) && statSync(p).isFile()) out.push(p);
      continue;
    }
    if (st.isDirectory()) walk(root, p, out);
    else out.push(p);
  }
  return out;
}

function gitFiles(root) {
  const r = spawnSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { cwd: root, encoding: "utf8" });
  if (r.status !== 0) return null;
  const top = spawnSync("git", ["rev-parse", "--show-toplevel"], { cwd: root, encoding: "utf8" });
  if (top.status !== 0 || realpathSync(top.stdout.trim()) !== realpathSync(root)) return null;
  return r.stdout.split("\0").filter(Boolean)
    .filter((rel) => !rel.split("/").some((part) => SKIP_ANYWHERE.has(part)) && !SKIP_AT_ROOT.has(rel.split("/")[0]))
    .map((rel) => join(root, rel))
    .filter((p) => existsSync(p) && statSync(p).isFile());
}

function kindOf(rel, publicTree = false) {
  const inApp = /^(apps|packages)\//.test(rel);
  // In a public tree (prepublish-check, M8-03) audit reports are published, so they are linted too.
  const internal = publicTree ? /^docs\/internal\//.test(rel) : /^docs\/(internal|audits)\//.test(rel);
  return {
    code: inApp && CODE_EXT.test(rel) && !TEST_FILE.test(rel),
    rust: /^contracts\/.+\/src\/.+\.rs$/.test(rel),
    // Every Markdown file is public except internal notes and audit reports;
    // app HTML pages are public too (their titles and visible text).
    words: (/\.md$/i.test(rel) && !internal) || (inApp && /\.html?$/.test(rel)),
  };
}

// Marks the lines of each `#[cfg(test)]` item (attribute through its closing brace),
// so code after a test module is still linted.
function testLines(lines) {
  const mark = new Array(lines.length).fill(false);
  for (let i = 0; i < lines.length; i++) {
    if (!/#\[cfg\(test\)\]/.test(lines[i])) continue;
    let depth = 0, opened = false, j = i;
    for (; j < lines.length; j++) {
      mark[j] = true;
      for (const ch of lines[j]) {
        if (ch === "{") { depth++; opened = true; } else if (ch === "}") depth--;
      }
      if (opened && depth <= 0) break;
      if (!opened && j > i && /;\s*$/.test(lines[j])) break; // e.g. #[cfg(test)] use x;
    }
    i = j;
  }
  return mark;
}

function headings(text) {
  // Markdown ATX and setext headings, HTML headings and page titles.
  const lines = text.split("\n");
  const out = [];
  lines.forEach((line, i) => {
    if (/^\s{0,3}#{1,6}\s/.test(line)) out.push([i, line]);
    if (/^\s{0,3}(=+|-+)\s*$/.test(line) && i > 0 && lines[i - 1].trim()) out.push([i - 1, lines[i - 1]]);
    for (const m of line.matchAll(/<(h[1-6]|title)\b[^>]*>(.*?)<\/\1>/gi)) out.push([i, m[2]]);
  });
  return out;
}

// --- Attack text stays in fixtures/attacks/ (CLAUDE.md; audit M4-07) -----------------
// Fragments of every attack-labelled page, minus anything a control page also says, must
// not appear in any other file. Placeholders split fragments; short pieces are ignored.
const ATTACK_DIR = "fixtures/attacks";
const MIN_FRAGMENT = 24;
function jsonFiles(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (lstatSync(p).isDirectory()) jsonFiles(p, out);
    else if (name.endsWith(".json")) out.push(p);
  }
  return out;
}
function fragments(page) {
  return page.split(/\{\{[A-Z_]+\}\}|[\n.!?:"<>]/).map((x) => x.trim()).filter((x) => x.length >= MIN_FRAGMENT);
}
export function attackFragments(root) {
  const attack = new Set(), control = new Set();
  for (const f of jsonFiles(join(root, ATTACK_DIR))) {
    let v;
    try { v = JSON.parse(readFileSync(f, "utf8")); } catch { continue; }
    if (typeof v?.page !== "string") continue;
    for (const x of fragments(v.page)) (v.label === "attack" ? attack : control).add(x);
  }
  return [...attack].filter((x) => ![...control].some((c) => c.includes(x) || x.includes(c)));
}

export function lint(root, { publicTree = false } = {}) {
  const findings = [];
  const add = (rel, i, r) => findings.push({ file: rel, line: i + 1, rule: r.id, why: r.why });
  const files = gitFiles(root) ?? walk(root);
  const attackText = attackFragments(root);
  for (const file of files) {
    const rel = relative(root, file).split(sep).join("/");
    if (attackText.length && !rel.startsWith(ATTACK_DIR + "/") && statSync(file).size < 2_000_000) {
      const text = readFileSync(file, "utf8");
      if (attackText.some((x) => text.includes(x))) {
        const i = text.split("\n").findIndex((l) => attackText.some((x) => l.includes(x)));
        add(rel, Math.max(i, 0), { id: "no-attack-text-outside-fixtures", why: "attack strings live only in fixtures/attacks/" });
      }
    }
    const k = kindOf(rel, publicTree);
    if (!k.code && !k.rust && !k.words) continue;
    const text = readFileSync(file, "utf8");
    const lines = text.split("\n");

    if (k.code) {
      // Join lines so an assignment split across lines is still seen.
      const flat = text.replace(/\s*\n\s*/g, " ");
      for (const r of CODE_RULES) {
        let hit = false;
        lines.forEach((line, i) => { if (r.re.test(line)) { add(rel, i, r); hit = true; } });
        if (!hit && r.re.test(flat)) add(rel, 0, r);
      }
    }

    if (k.rust) {
      const inTest = testLines(lines);
      for (const r of RUST_RULES) lines.forEach((line, i) => { if (!inTest[i] && r.re.test(line)) add(rel, i, r); });
    }

    if (k.words) {
      // A quoted word may appear where a rule is stated, but never inside a title.
      for (const [i, h] of headings(text)) {
        if (W.firewall.test(h)) add(rel, i, { id: "no-firewall-title", why: "never use \"firewall\" in a title" });
      }
      for (const r of WORD_RULES) {
        lines.forEach((line, i) => { if (r.re.test(line.replace(QUOTED_RULE_WORD, ""))) add(rel, i, r); });
      }
    }
  }
  return findings;
}

// Compare as URLs of the real path, so paths with spaces, % or symlinks still run the lint.
const isMain = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
if (isMain) {
  const args = process.argv.slice(2);
  const root = args.find((x) => !x.startsWith("--")) ?? process.cwd();
  const findings = lint(root, { publicTree: args.includes("--public") });
  for (const f of findings) console.error(`${f.file}:${f.line}  ${f.rule}  (${f.why})`);
  if (findings.length) {
    console.error(`lint-banned: ${findings.length} finding(s)`);
    process.exit(1);
  }
  console.log("lint-banned: no findings");
}
