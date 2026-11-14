// Security baseline for the repository set-up (M0). These tests guard settings that
// a later change could silently weaken: secrets scanning, ignored key files,
// install-script policy, pinned CI actions and release overflow checks.
import { describe, it, expect } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, readdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "../..");
const read = (rel) => readFileSync(join(ROOT, rel), "utf8");

describe("secrets", () => {
  it("the project secrets scan finds a planted fake private key", () => {
    const dir = mkdtempSync(join(tmpdir(), "leak-"));
    try {
      // Built at runtime so this test file itself contains no key-shaped string.
      const fake = ["-----BEGIN", " RSA PRIVATE KEY-----\n",
        "MIIEowIBAAKCAQEA" + "q".repeat(60) + "\n",
        "-----END", " RSA PRIVATE KEY-----\n"].join("");
      writeFileSync(join(dir, "leak.pem.txt"), fake);
      const r = spawnSync(join(ROOT, "scripts/secrets-scan.sh"), ["--dir", dir], { encoding: "utf8" });
      expect(r.error, "gitleaks must be installed (scripts/setup-env.sh)").toBeUndefined();
      expect(r.status).toBe(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("key and environment files are git-ignored", () => {
    for (const p of [".env", ".env.local", "near-credentials/key.json", "agent.key", "id.pem", "keys/x.json", "neardev/dev-account.env",
      "agent.sampan.testnet.json", ".envrc", ".cargo/credentials.toml", "id_ed25519", "wallet.keystore", "agent.key.json"]) {
      const r = spawnSync("git", ["check-ignore", "-q", "--no-index", p], { cwd: ROOT });
      expect(r.status, `${p} must be ignored`).toBe(0);
    }
  });

  it("the pre-commit hook runs gitleaks on staged changes", () => {
    // Ignore comments, so a commented-out scan does not count (M0-08).
    const hook = read(".githooks/pre-commit").split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
    expect(hook).toMatch(/^\s*scripts\/secrets-scan\.sh --staged\s*$/m);
    expect(hook).toMatch(/^set -e$/m);
  });

  it("the pre-commit hook's dependency checks use flags the installed tools accept", () => {
    // Regression for the M2 commit: an unknown cargo-deny flag broke every commit that staged Cargo.lock.
    const hook = read(".githooks/pre-commit");
    for (const line of hook.split("\n").map((l) => l.trim()).filter((l) => /^cargo (audit|deny)\b/.test(l))) {
      const args = line.split(/\s+/).slice(1);
      const help = spawnSync("cargo", [...args.filter((a) => a !== "--no-fetch" && a !== "--offline" && a !== "--locked" && !a.startsWith("--deny") && a !== "warnings"), "--help"], { cwd: ROOT, encoding: "utf8" });
      expect(help.status, line).toBe(0);
      const r = spawnSync("cargo", args, { cwd: ROOT, encoding: "utf8" });
      expect(r.stderr, line).not.toMatch(/unexpected argument/);
    }
  }, 120_000);

  it("the Makefile and CI only scan secrets through scripts/secrets-scan.sh", () => {
    for (const f of ["Makefile", ".githooks/pre-commit", ".github/workflows/ci.yml"]) {
      const code = read(f).split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
      expect(code, `${f} calls gitleaks directly`).not.toMatch(/^\s*gitleaks\b/m);
    }
  });
});

describe("supply chain", () => {
  it("pnpm allows no dependency build scripts", () => {
    const ws = read("pnpm-workspace.yaml");
    expect(ws).toMatch(/onlyBuiltDependencies:\s*\[\s*\]/);
    // Other ways to re-enable build scripts must be absent (M0-08).
    expect(ws).not.toMatch(/onlyBuiltDependenciesFile|neverBuiltDependencies|dangerouslyAllowAllBuilds/);
    const pkg = JSON.parse(read("package.json"));
    expect(pkg.pnpm ?? {}, "package.json pnpm settings").toEqual({});
    expect(read(".npmrc")).toMatch(/^ignore-scripts=true$/m);
  });

  it("every GitHub Action is pinned to a full commit SHA", () => {
    const dir = join(ROOT, ".github/workflows");
    for (const f of readdirSync(dir)) {
      const uses = [...read(`.github/workflows/${f}`).matchAll(/uses:\s*([^\s#]+)/g)].map((m) => m[1]);
      expect(uses.length).toBeGreaterThan(0);
      for (const u of uses) expect(u, `${f}: ${u}`).toMatch(/@[0-9a-f]{40}$/);
    }
  });

  it("workflows run with read-only repository permissions", () => {
    for (const f of readdirSync(join(ROOT, ".github/workflows"))) {
      const wf = read(`.github/workflows/${f}`);
      expect(wf).toMatch(/permissions:\s*\n\s+contents:\s*read/);
      // No workflow or job may grant write access anywhere (M0-08).
      expect(wf, `${f} grants write access`).not.toMatch(/write-all|:\s*write\b/);
    }
  });

  it("cargo-deny only allows crates.io as a source", () => {
    const deny = read("deny.toml");
    expect(deny).toMatch(/unknown-registry\s*=\s*"deny"/);
    expect(deny).toMatch(/unknown-git\s*=\s*"deny"/);
  });
});

describe("advisory ignores stay out of the contract", () => {
  it("ignored advisories never reach the contract build", () => {
    // Crates whose advisories are ignored in .cargo/audit.toml and deny.toml because
    // they are test-harness only. If any appears in the wasm build, this fails.
    // The crates are named next to each ignore in .cargo/audit.toml ("# <crate> ...").
    const crates = [...read(".cargo/audit.toml").matchAll(/"RUSTSEC-\d{4}-\d{4}",\s*#\s*([\w-]+)/g)].map((m) => m[1]);
    expect(crates.length, "every ignore names its crate").toBe([...read(".cargo/audit.toml").matchAll(/"RUSTSEC-/g)].length);
    // A misspelt crate name must not pass vacuously (M0-13): each must be in the lockfile.
    for (const c of crates) expect(read("Cargo.lock"), `${c} is not in Cargo.lock`).toMatch(new RegExp(`^name = "${c}"$`, "m"));
    for (const krate of crates) {
      const r = spawnSync("cargo", ["tree", "-q", "--locked", "-i", krate, "--target", "wasm32-unknown-unknown", "-e", "normal,build", "-p", "sampan-gate"], { cwd: ROOT, encoding: "utf8" });
      // Pass only if the crate is absent from the wasm graph: either cargo succeeds with
      // empty output (crate exists only in the host test graph), or the crate is not in
      // the lockfile at all ("did not match any packages"). Any other failure is a fail.
      expect(r.error, "cargo must be installed").toBeUndefined();
      expect(r.stdout.trim(), `${krate} must not be in the contract build`).toBe("");
      const absent = r.status === 0 || /did not match any packages/.test(r.stderr);
      expect(absent, `cargo tree for ${krate} failed unexpectedly: ${r.stderr}`).toBe(true);
    }
  }, 120_000);

  it("every audit ignore has a matching cargo-deny entry with a reason", () => {
    const audit = [...read(".cargo/audit.toml").matchAll(/"(RUSTSEC-\d{4}-\d{4})"/g)].map((m) => m[1]).sort();
    const deny = [...read("deny.toml").matchAll(/id = "(RUSTSEC-\d{4}-\d{4})", reason = "[^"]+"/g)].map((m) => m[1]).sort();
    expect(deny).toEqual(audit);
  });
});

describe("Rust safety settings", () => {
  it("release builds keep overflow checks", () => {
    expect(read("Cargo.toml")).toMatch(/\[profile\.release\][^[]*overflow-checks\s*=\s*true/);
    // No profile override for any package, and no override in .cargo/config (M0-08).
    for (const f of ["Cargo.toml", "contracts/gate/Cargo.toml", ".cargo/config.toml", ".cargo/config"]) {
      if (existsSync(join(ROOT, f))) expect(read(f), f).not.toMatch(/overflow-checks\s*=\s*false|CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS/i);
    }
  });

  it("clippy denies unwrap and expect outside tests", () => {
    // Every workspace member must inherit the workspace lints (M0-08).
    const members = [...read("Cargo.toml").matchAll(/members\s*=\s*\[([^\]]*)\]/g)][0][1].match(/"([^"]+)"/g).map((m) => m.slice(1, -1));
    for (const m of members) expect(read(`${m}/Cargo.toml`), `${m} drops the workspace lints`).toMatch(/\[lints\]\s*\nworkspace\s*=\s*true/);
    const cargo = read("Cargo.toml");
    expect(cargo).toMatch(/unwrap_used\s*=\s*"deny"/);
    expect(cargo).toMatch(/expect_used\s*=\s*"deny"/);
    expect(read("clippy.toml")).toMatch(/allow-unwrap-in-tests\s*=\s*true/);
  });

  it.each(["contracts/gate/src/lib.rs", "crates/formats/src/lib.rs"])("%s forbids panics, unchecked arithmetic and indexing outside tests (M0-CR5, M0-05)", (file) => {
    const lib = read(file);
    const attr = lib.match(/#!\[cfg_attr\(\s*not\(test\),\s*forbid\(([^)]*)\)\s*\)\]/);
    expect(attr, "crate-level forbid attribute").toBeTruthy();
    for (const l of ["unwrap_used", "expect_used", "panic", "unreachable", "indexing_slicing", "arithmetic_side_effects", "disallowed_macros"]) {
      expect(attr[1]).toMatch(new RegExp(`clippy::${l}\\b`));
    }
    expect(read("clippy.toml")).toMatch(/near_sdk::require/);
  });

  it("the toolchain is pinned", () => {
    expect(read("rust-toolchain.toml")).toMatch(/channel\s*=\s*"\d+\.\d+\.\d+"/);
  });
});

describe("banned-pattern lint runs clean on the repository", () => {
  it("has no findings", () => {
    const out = execFileSync("node", ["scripts/lint-banned.mjs"], { cwd: ROOT, encoding: "utf8" });
    expect(out).toMatch(/no findings/);
  });
});
