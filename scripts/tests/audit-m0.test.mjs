// Independent audit of milestone M0 (docs/audits/M0.md). Exploit tests.
//
// Each test asserts the SECURE behaviour, so it FAILS while its finding is open and
// passes once the finding is fixed. Positive controls (named "control") must pass now:
// they prove the harness can tell a pass from a fail, so the exploit tests are not vacuous.
//
// All keys below are random, built at runtime, and never printed. gitleaks always runs
// with --redact. Nothing here touches the real repository's git state or the network,
// except M0-04 which queries the npm registry exactly as `make security` does.
import { describe, it, expect, beforeAll } from "vitest";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, cpSync, existsSync,
  symlinkSync, chmodSync,
} from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { lint } from "../lint-banned.mjs";

const ROOT = resolve(import.meta.dirname, "../..");
const PATH = `${join(homedir(), ".local/bin")}:${process.env.PATH}`;
const ENV = { ...process.env, PATH };

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58 = (n) => [...randomBytes(n)].map((x) => B58[x % 58]).join("");
// A NEAR ed25519 secret key as near-cli, near-api-js and the wallets print it.
const nearSecret = () => `ed25519:${b58(88)}`;
const nearPublic = () => `ed25519:${b58(44)}`;
// RSA-shaped fake that the default gitleaks rules DO detect (same shape as security-baseline).
const fakePem = () => ["-----BEGIN", " RSA PRIVATE KEY-----\n", "MIIEowIBAAKCAQEA" + "q".repeat(60) + "\n",
  "-----END", " RSA PRIVATE KEY-----\n"].join("");
const ALLOW = "gitleaks" + ":allow";

const tmp = (p) => mkdtempSync(join(tmpdir(), `audit-m0-${p}-`));
const put = (root, rel, text) => {
  const p = join(root, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, text);
  return p;
};
const run = (cmd, args, opts = {}) => spawnSync(cmd, args, { encoding: "utf8", env: ENV, ...opts });

// Author's note (fix of M0-01/M0-02): every scan in the project now goes through
// scripts/secrets-scan.sh (Makefile, hook, CI), so these tests exercise that entry point
// instead of calling gitleaks directly. Exit 1 = leak found or input refused.
const SCAN = join(ROOT, "scripts/secrets-scan.sh");
function gitleaksDir(dir) {
  const r = run(SCAN, ["--dir", dir]);
  expect(r.error, "secrets-scan.sh must run").toBeUndefined();
  return r.status;
}

// A scratch git repository with the M0 secret controls copied in: .gitignore, .gitleaks.toml,
// the pre-commit hook and the banned-pattern lint it calls.
function scratchRepo() {
  const dir = tmp("repo");
  for (const f of [".gitignore", ".gitleaks.toml", ".githooks/pre-commit", "scripts/lint-banned.mjs", "scripts/secrets-scan.sh"]) {
    mkdirSync(dirname(join(dir, f)), { recursive: true });
    cpSync(join(ROOT, f), join(dir, f));
  }
  chmodSync(join(dir, ".githooks/pre-commit"), 0o755);
  chmodSync(join(dir, "scripts/secrets-scan.sh"), 0o755);
  const git = (...a) => run("git", ["-c", "user.name=audit", "-c", "user.email=audit@example.invalid", "-c", "commit.gpgsign=false", ...a], { cwd: dir });
  git("init", "-q");
  git("config", "core.hooksPath", ".githooks");
  git("add", "-A");
  expect(git("commit", "-q", "-m", "controls").status).toBe(0);
  return { dir, git };
}

// ---------------------------------------------------------------------------------------
describe("M0-01 NEAR private keys pass every secret control (S7)", () => {
  it("control: gitleaks with the repo config detects an RSA-shaped key", () => {
    const d = tmp("gl");
    try { put(d, "a.txt", fakePem()); expect(gitleaksDir(d)).toBe(1); } finally { rmSync(d, { recursive: true, force: true }); }
  });

  const cases = {
    "near-cli credentials file": () => JSON.stringify({ account_id: "agent.sampan.testnet", public_key: nearPublic(), private_key: nearSecret() }),
    "environment file": () => `NEAR_PRIVATE_KEY=${nearSecret()}\n`,
    "quoted env var": () => `export AGENT_SECRET_KEY="${nearSecret()}"\n`,
    "source constant": () => `const agentKey = "${nearSecret()}";\n`,
  };
  for (const [name, make] of Object.entries(cases)) {
    it(`M0-01: gitleaks detects a NEAR ed25519 secret key in a ${name}`, () => {
      const d = tmp("gl");
      try { put(d, "leak.txt", make()); expect(gitleaksDir(d), `${name} not detected`).toBe(1); } finally { rmSync(d, { recursive: true, force: true }); }
    });
  }

  it("control: the pre-commit hook blocks an RSA-shaped key", () => {
    const { dir, git } = scratchRepo();
    try {
      put(dir, "notes.txt", fakePem());
      git("add", "notes.txt");
      expect(git("commit", "-q", "-m", "leak").status).not.toBe(0);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("M0-01: a near-cli credentials file cannot be committed (gitignore + pre-commit + history scan)", () => {
    const { dir, git } = scratchRepo();
    try {
      // `cp ~/.near-credentials/testnet/agent.sampan.testnet.json .` then `git add -A`
      put(dir, "agent.sampan.testnet.json", JSON.stringify({ account_id: "agent.sampan.testnet", public_key: nearPublic(), private_key: nearSecret() }));
      git("add", "-A");
      const committed = git("commit", "-q", "-m", "add agent").status === 0;
      // Author's note: the original assertion also required the history scan to find the key
      // in this same run, which cannot hold once .gitignore stops it being committed at all.
      // The layers are now tested separately: ignored, blocked by the hook when forced,
      // and found by the history scan when the hook is bypassed.
      const forcedAdd = git("add", "-f", "agent.sampan.testnet.json").status === 0;
      const hookBlocks = git("commit", "-q", "-m", "force add agent").status !== 0;
      git("commit", "-q", "--no-verify", "-m", "bypass hook");
      const historyScan = run(join(dir, "scripts/secrets-scan.sh"), ["--history"], { cwd: dir }).status;
      expect({ committed, forcedAdd, hookBlocks, historyScanFound: historyScan === 1 })
        .toEqual({ committed: false, forcedAdd: true, hookBlocks: true, historyScanFound: true });
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

// ---------------------------------------------------------------------------------------
describe("M0-02 unmanaged gitleaks suppression and blind spots", () => {
  const variants = {
    "an inline allow comment": (d) => put(d, "k.txt", fakePem().replace("-----\n", `----- ${ALLOW}\n`)),
    "base64 encoding": (d) => put(d, "k.b64", Buffer.from(fakePem()).toString("base64") + "\n"),
    "a .tar.gz archive": (d) => {
      const src = tmp("src"); put(src, "k.txt", fakePem());
      run("tar", ["-czf", join(d, "keys.tgz"), "-C", src, "k.txt"]);
      rmSync(src, { recursive: true, force: true });
    },
  };
  for (const [name, plant] of Object.entries(variants)) {
    it(`M0-02: gitleaks still detects a key hidden by ${name}`, () => {
      const d = tmp("gl");
      try { plant(d); expect(gitleaksDir(d), `key hidden by ${name} not detected`).toBe(1); } finally { rmSync(d, { recursive: true, force: true }); }
    });
  }

  it("M0-02: a committed .gitleaksignore cannot silence the history scan", () => {
    const { dir, git } = scratchRepo();
    try {
      put(dir, "notes.txt", fakePem());
      git("add", "notes.txt");
      git("commit", "-q", "--no-verify", "-m", "leak");
      const rep = join(dir, "..", `${dir.split("/").pop()}-report.json`);
      run("gitleaks", ["detect", "--no-banner", "--redact", "--source", ".", "--report-format", "json", "--report-path", rep], { cwd: dir });
      const fps = JSON.parse(readFileSync(rep, "utf8")).map((f) => f.Fingerprint);
      rmSync(rep, { force: true });
      expect(fps.length).toBeGreaterThan(0); // control: the key is found before the ignore file exists
      put(dir, ".gitleaksignore", fps.join("\n") + "\n");
      git("add", ".gitleaksignore");
      git("commit", "-q", "-m", "tidy");
      const r = run(join(dir, "scripts/secrets-scan.sh"), ["--history"], { cwd: dir });
      expect(r.status, "history scan passed although a key is in history").toBe(1);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

// ---------------------------------------------------------------------------------------
describe("M0-03 .gitignore misses common key and credential files", () => {
  const paths = [
    "agent.sampan.testnet.json", // near-cli credential file name (~/.near-credentials/<net>/<account>.json)
    "testnet/gate.sampan.testnet.json",
    ".envrc", // direnv
    ".cargo/credentials.toml", // crates.io token, and .cargo/ is already tracked
    "id_ed25519",
    "id_rsa",
    "wallet.keystore",
    "agent.key.json",
  ];
  for (const p of paths) {
    it(`M0-03: ${p} is git-ignored`, () => {
      const r = run("git", ["check-ignore", "-q", "--no-index", p], { cwd: ROOT });
      expect(r.status, `${p} must be ignored`).toBe(0);
    });
  }
});

// ---------------------------------------------------------------------------------------
describe("M0-04 pnpm audit --prod audits none of the installed packages", () => {
  it("M0-04: the Makefile's pnpm audit covers every package in pnpm-lock.yaml", () => {
    const line = readFileSync(join(ROOT, "Makefile"), "utf8").split("\n").find((l) => /^\s*pnpm audit\b/.test(l));
    expect(line, "Makefile runs pnpm audit").toBeTruthy();
    const args = line.trim().split(/\s+/).slice(1).filter((a) => !/^--audit-level$|^low$/.test(a));
    const scoped = run("pnpm", [...args, "--json"], { cwd: ROOT });
    const full = run("pnpm", ["audit", "--json"], { cwd: ROOT });
    const total = (r) => JSON.parse(r.stdout).metadata.totalDependencies;
    expect(total(full), "control: full audit sees the dev toolchain").toBeGreaterThan(10);
    expect(total(scoped), "packages audited by make security").toBe(total(full));
  }, 120_000);
});

// ---------------------------------------------------------------------------------------
describe("M0-05 contract no-panic / no-unwrap lints are bypassable and host-only", () => {
  // Copy the Cargo workspace and run exactly the Makefile's clippy command on it, with
  // one probe function added to the contract per case. Uses the repo's target dir so the
  // dependency build is shared (only the scratch crate is rebuilt).
  let ws;
  // Author's note (fix of M0-05): run every clippy command in the Makefile's `clippy`
  // target (host and wasm) plus the banned-pattern lint, which owns the contract rules
  // clippy cannot apply to near-sdk's generated code (env::panic_str, local allows).
  const CLIPPYS = readFileSync(join(ROOT, "Makefile"), "utf8").split("\n")
    .filter((l) => /^\tcargo clippy /.test(l))
    .map((l) => l.trim().split(/\s+/).slice(1).flatMap((a) => (a === "--" ? ["-q", "--"] : [a])));
  beforeAll(() => {
    ws = tmp("ws");
    for (const f of ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "clippy.toml"]) cpSync(join(ROOT, f), join(ws, f));
    cpSync(join(ROOT, "contracts/gate"), join(ws, "contracts/gate"), { recursive: true });
    // Author's note (M2): the workspace now also has crates/formats; copy it so the
    // scratch workspace builds. Probes still go into the gate contract.
    // Skip the cargo-fuzz crate (and its large build output); it is excluded from the workspace.
    cpSync(join(ROOT, "crates/formats"), join(ws, "crates/formats"), { recursive: true, filter: (src) => !src.includes("/fuzz") });
    mkdirSync(join(ws, "fixtures"), { recursive: true });
    return () => rmSync(ws, { recursive: true, force: true });
  });
  const lib = () => readFileSync(join(ROOT, "contracts/gate/src/lib.rs"), "utf8");
  const clippyWith = (probe) => {
    writeFileSync(join(ws, "contracts/gate/src/lib.rs"), `${lib()}\npub mod probe {\n${probe}\n}\n`);
    expect(CLIPPYS.length).toBe(2);
    for (const args of CLIPPYS) {
      const r = run("cargo", args, { cwd: ws, env: { ...ENV, CARGO_TARGET_DIR: join(ROOT, "target") } });
      expect(r.error, "cargo must be installed").toBeUndefined();
      if (r.status !== 0) return r.status;
    }
    return lint(ws).length ? 1 : 0;
  };

  it("control: a plain unwrap in contract code fails clippy", () => {
    expect(clippyWith("pub fn f(x: Option<u8>) -> u8 { x.unwrap() }")).not.toBe(0);
  }, 600_000);

  const probes = {
    "#[allow(clippy::unwrap_used)] on contract code": "#[allow(clippy::unwrap_used)]\npub fn f(x: Option<u8>) -> u8 { x.unwrap() }",
    "near_sdk::require! (a panic)": "pub fn f(x: u8) { near_sdk::require!(x > 0, \"refused\"); }",
    "assert! (a panic)": "pub fn f(x: u8) { assert!(x > 0); }",
    "slice indexing (a panic)": "pub fn f(v: &[u8]) -> u8 { v[0] }",
    "unreachable! (a panic)": "pub fn f() { unreachable!() }",
    "env::panic_str (a panic)": "pub fn f() { near_sdk::env::panic_str(\"refused\") }",
    "unwrap in wasm32-only code": "#[cfg(target_arch = \"wasm32\")]\npub fn f(x: Option<u8>) -> u8 { x.unwrap() }",
  };
  for (const [name, probe] of Object.entries(probes)) {
    it(`M0-05: make clippy + banned lint reject ${name}`, () => {
      expect(clippyWith(probe), `${name} passed clippy`).not.toBe(0);
    }, 600_000);
  }
});

// ---------------------------------------------------------------------------------------
describe("M0-06 banned-pattern lint: code rules can be bypassed", () => {
  const flagged = (rel, text) => {
    const d = tmp("lint");
    try { put(d, rel, text); return lint(d).length > 0; } finally { rmSync(d, { recursive: true, force: true }); }
  };
  const cases = {
    "eval through a property": ["apps/checker/src/a.ts", "globalThis.eval(s);\n"],
    "indirect eval": ["apps/checker/src/a.ts", "(0, eval)(s);\n"],
    "Function constructor without new": ["apps/checker/src/a.ts", "Function(s)();\n"],
    "setTimeout with a string": ["apps/checker/src/a.ts", "setTimeout(s, 0);\nsetTimeout(\"run()\", 0);\n"],
    "logical assignment to innerHTML": ["apps/checker/src/a.ts", "el.innerHTML ||= x;\n"],
    "nullish assignment to innerHTML": ["apps/checker/src/a.ts", "el.innerHTML ??= x;\n"],
    "Object.assign innerHTML": ["apps/checker/src/a.ts", "Object.assign(el, { innerHTML: x });\n"],
    "assignment split across lines": ["apps/checker/src/a.ts", "el.innerHTML\n  = x;\n"],
    "setHTMLUnsafe": ["apps/checker/src/a.ts", "el.setHTMLUnsafe(x);\n"],
    "iframe srcdoc": ["apps/checker/src/a.ts", "frame.srcdoc = x;\n"],
    "createContextualFragment": ["apps/checker/src/a.ts", "document.createRange().createContextualFragment(x);\n"],
    "a .cjs file": ["apps/checker/src/a.cjs", "el.innerHTML = x;\n"],
    "a .cts file": ["packages/receipt/src/a.cts", "eval(s);\n"],
    "a source dir named fixtures": ["apps/checker/src/fixtures/render.ts", "el.innerHTML = x;\n"],
    "a source dir named coverage": ["packages/receipt/src/coverage/report.ts", "eval(s);\n"],
  };
  for (const [name, [rel, text]] of Object.entries(cases)) {
    it(`M0-06: flags ${name}`, () => { expect(flagged(rel, text), `${name} not flagged`).toBe(true); });
  }

  it("M0-06: lints a symlinked source file whose target is outside apps/ and packages/", () => {
    const d = tmp("lint");
    try {
      put(d, "lib/render.ts", "el.innerHTML = x;\n");
      mkdirSync(join(d, "apps/checker/src"), { recursive: true });
      symlinkSync("../../../lib/render.ts", join(d, "apps/checker/src/render.ts"));
      expect(lint(d).length, "symlinked source not linted").toBeGreaterThan(0);
    } finally { rmSync(d, { recursive: true, force: true }); }
  });
});

// ---------------------------------------------------------------------------------------
describe("M0-07 banned-pattern lint: wording rules can be bypassed", () => {
  const flagged = (rel, text) => {
    const d = tmp("lint");
    try { put(d, rel, text); return lint(d).length > 0; } finally { rmSync(d, { recursive: true, force: true }); }
  };
  const W = "fire" + "wall";
  const cases = {
    "a quoted banned word in a heading": ["README.md", `# A "${W}" for agent payments\n`],
    "a setext heading": ["README.md", `Agent payment ${W}\n==================\n`],
    "an HTML heading in a doc": ["README.md", `<h1>Agent payment ${W}</h1>\n`],
    "a page title in a public app": ["apps/checker/index.html", `<title>Agent payment ${W}</title>\n`],
    "examples/README.md": ["examples/README.md", "Intents are unstopp" + "able.\n"],
    "contracts/gate/README.md": ["contracts/gate/README.md", "Intents are unstopp" + "able.\n"],
    "a root CONTRIBUTING.md": ["CONTRIBUTING.md", "x4" + "02 settled $1M\n"],
  };
  for (const [name, [rel, text]] of Object.entries(cases)) {
    it(`M0-07: flags banned wording in ${name}`, () => { expect(flagged(rel, text), `${name} not flagged`).toBe(true); });
  }
});

// ---------------------------------------------------------------------------------------
describe("M0-08 security-baseline tests pass on a weakened repository", () => {
  // Copy the files the baseline test reads, apply one weakening, and run the REAL
  // security-baseline test against the copy. The test must fail on the weakened copy.
  const VITEST = join(ROOT, "node_modules/vitest/vitest.mjs");
  const FILES = [".github", ".githooks", "pnpm-workspace.yaml", "package.json", "Cargo.toml", "clippy.toml",
    "rust-toolchain.toml", "deny.toml", ".cargo/audit.toml", "contracts/gate", "vitest.config.mjs",
    "scripts/tests/security-baseline.test.mjs", "scripts/lint-banned.mjs"];
  const baseline = (testName, mutate) => {
    const d = tmp("mut");
    try {
      for (const f of FILES) cpSync(join(ROOT, f), join(d, f), { recursive: true });
      symlinkSync(join(ROOT, "node_modules"), join(d, "node_modules"));
      if (mutate) mutate(d);
      const env = Object.fromEntries(Object.entries(ENV).filter(([k]) => !k.startsWith("VITEST")));
      const r = run("node", [VITEST, "run", "--root", d, "scripts/tests/security-baseline.test.mjs", "-t", testName], { cwd: d, env });
      const out = r.stdout + r.stderr;
      return { passed: /\b1 passed\b/.test(out) && r.status === 0, failed: /\b1 failed\b/.test(out) };
    } finally { rmSync(d, { recursive: true, force: true }); }
  };
  const edit = (d, rel, fn) => writeFileSync(join(d, rel), fn(readFileSync(join(d, rel), "utf8")));

  it("control: the harness runs a baseline test and sees it pass on an unmodified copy", () => {
    expect(baseline("read-only repository permissions")).toEqual({ passed: true, failed: false });
  }, 120_000);

  const mutations = {
    "a job granting permissions: write-all": ["read-only repository permissions",
      (d) => edit(d, ".github/workflows/ci.yml", (t) => t.replace("    runs-on: ubuntu-24.04", "    permissions: write-all\n    runs-on: ubuntu-24.04"))],
    // Author's note: the hook now calls scripts/secrets-scan.sh, so the mutation comments that out.
    "the hook's secrets scan commented out": ["runs gitleaks on staged",
      (d) => edit(d, ".githooks/pre-commit", (t) => t.replace(/^scripts\/secrets-scan\.sh --staged/m, "# scripts/secrets-scan.sh --staged"))],
    "build scripts allowed through package.json pnpm.onlyBuiltDependencies": ["allows no dependency build scripts",
      (d) => edit(d, "package.json", (t) => t.replace('"private": true,', '"private": true,\n  "pnpm": { "onlyBuiltDependencies": ["esbuild"] },'))],
    "build scripts allowed through onlyBuiltDependenciesFile": ["allows no dependency build scripts",
      (d) => { edit(d, "pnpm-workspace.yaml", (t) => t + "onlyBuiltDependenciesFile: allow-builds.json\n"); writeFileSync(join(d, "allow-builds.json"), '["esbuild"]'); }],
    "overflow checks disabled for the gate package": ["release builds keep overflow checks",
      (d) => edit(d, "Cargo.toml", (t) => t + "\n[profile.release.package.sampan-gate]\noverflow-checks = false\n")],
    "the gate crate dropping the workspace lints": ["clippy denies unwrap and expect outside tests",
      (d) => edit(d, "contracts/gate/Cargo.toml", (t) => t.replace(/\[lints\]\s*\nworkspace = true\n/, ""))],
  };
  for (const [name, [testName, mutate]] of Object.entries(mutations)) {
    it(`M0-08: baseline test "${testName}" fails with ${name}`, () => {
      expect(baseline(testName, mutate), `baseline test still green with ${name}`).toEqual({ passed: false, failed: true });
    }, 120_000);
  }
});

// ---------------------------------------------------------------------------------------
describe("M0-09 npm runs dependency install scripts under the repo's .npmrc", () => {
  it("M0-09: `npm install` in a project with this .npmrc does not run a dependency postinstall", () => {
    const d = tmp("npm");
    try {
      const marker = join(d, "RAN");
      put(d, "dep/package.json", JSON.stringify({ name: "dep", version: "1.0.0",
        scripts: { postinstall: `node -e "require('fs').writeFileSync('${marker}', 'x')"` } }));
      cpSync(join(ROOT, ".npmrc"), join(d, "app/.npmrc"));
      put(d, "app/package.json", JSON.stringify({ name: "app", private: true, dependencies: { dep: "file:../dep" } }));
      const r = run("npm", ["install", "--offline", "--no-audit", "--no-fund"], { cwd: join(d, "app") });
      expect(r.status, `npm install failed: ${r.stderr}`).toBe(0);
      expect(existsSync(marker), "dependency postinstall ran").toBe(false);
    } finally { rmSync(d, { recursive: true, force: true }); }
  }, 120_000);
});

// ---------------------------------------------------------------------------------------
describe("M0-10 vitest silently skips common test file names", () => {
  const VITEST = join(ROOT, "node_modules/vitest/vitest.mjs");
  const vitestWith = (failingRel) => {
    const d = tmp("vt");
    try {
      cpSync(join(ROOT, "vitest.config.mjs"), join(d, "vitest.config.mjs"));
      symlinkSync(join(ROOT, "node_modules"), join(d, "node_modules"));
      put(d, "scripts/tests/ok.test.mjs", 'import { it, expect } from "vitest"; it("ok", () => expect(1).toBe(1));\n');
      put(d, failingRel, 'import { it, expect } from "vitest"; it("must fail", () => expect(1).toBe(2));\n');
      const env = Object.fromEntries(Object.entries(ENV).filter(([k]) => !k.startsWith("VITEST")));
      return run("node", [VITEST, "run", "--root", d], { cwd: d, env }).status;
    } finally { rmSync(d, { recursive: true, force: true }); }
  };
  it("control: a failing packages/**/*.test.ts fails the run", () => {
    expect(vitestWith("packages/receipt/src/a.test.ts")).not.toBe(0);
  }, 60_000);
  for (const rel of ["packages/receipt/src/a.test.mts", "packages/mandate/src/a.test.js", "apps/checker/src/a.test.tsx", "apps/checker/src/a.spec.ts"]) {
    it(`M0-10: a failing ${rel.split("/").pop()} fails the run`, () => {
      expect(vitestWith(rel), `${rel} was never run`).not.toBe(0);
    }, 60_000);
  }
});

// ---------------------------------------------------------------------------------------
describe("M0-11 setup-env trusts any gitleaks on PATH that prints the pinned version", () => {
  it("M0-11: a different gitleaks build on PATH is replaced by the checksum-verified download", () => {
    const d = tmp("setup");
    try {
      const stub = (name, body) => { const p = put(d, `bin/${name}`, `#!/bin/sh\n${body}\n`); chmodSync(p, 0o755); };
      stub("gitleaks", 'echo "8.24.20"'); // not the pinned 8.24.2, but contains it
      stub("cargo-audit", 'echo "cargo-audit 0.22.2"');
      stub("cargo-deny", 'echo "cargo-deny 0.20.2"');
      for (const t of ["rustup", "cargo", "corepack", "pnpm", "git"]) stub(t, "exit 0");
      stub("curl", `touch "${join(d, "CURL_CALLED")}"; exit 1`);
      const r = spawnSync("bash", [join(ROOT, "scripts/setup-env.sh")], { cwd: d, encoding: "utf8",
        env: { HOME: d, PATH: `${join(d, "bin")}:/usr/bin:/bin`, BIN_DIR: join(d, "local") } });
      expect(existsSync(join(d, "CURL_CALLED")), `setup-env kept the unverified gitleaks (exit ${r.status})`).toBe(true);
    } finally { rmSync(d, { recursive: true, force: true }); }
  });
});

// ---------------------------------------------------------------------------------------
describe("M0-12 pre-commit hook runs less than docs/SECURITY.md 3.6 requires", () => {
  it("M0-12: the hook runs cargo audit, cargo deny and pnpm audit as well as gitleaks", () => {
    const hook = readFileSync(join(ROOT, ".githooks/pre-commit"), "utf8").split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
    expect(hook).toMatch(/cargo audit/);
    expect(hook).toMatch(/cargo deny/);
    expect(hook).toMatch(/pnpm audit/);
  });
});
