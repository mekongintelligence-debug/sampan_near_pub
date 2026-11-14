#!/usr/bin/env node
// Starts the M4 agent process isolated from the operator (audit M4-02, M4-CR3):
//  - its own unprivileged OS user (`sampan-agent`), so it cannot read the launcher's
//    /proc/<pid>/environ (which holds the operator's key) or the operator's .secrets/;
//  - an allow-listed environment with no credential of any kind;
//  - a private temporary directory, owned by that user, holding only the agent's
//    function-call key, the public demo state and a copy of the TLS CA bundle.
// The operator copies the agent's results file back into docs/ afterwards.
//   node scripts/m4/agent-env.mjs attack | direct | probe --key <file>
import { spawnSync } from "node:child_process";
import { chownSync, copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const AGENT_USER = "sampan-agent";
const ALLOW = ["PATH", "LANG", "LC_ALL", "TZ", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "NODE_USE_ENV_PROXY", "NODE_OPTIONS"];
const ROOT = resolve(import.meta.dirname, "../..");

/** The allow-listed environment: nothing that could hold a credential. */
export function agentEnv(env = process.env) {
  const out = {};
  for (const k of ALLOW) if (env[k] !== undefined) out[k] = env[k];
  return out;
}

/** uid/gid of the agent user, created on first use. Only root can start a process as
 *  another user; anywhere else the launcher refuses rather than share the operator's user. */
export function agentIdentity() {
  if (typeof process.getuid !== "function" || process.getuid() !== 0) {
    throw new Error(`refusing to start the agent: run the launcher as root so the agent runs as the separate user ${AGENT_USER} (it must not share the operator's OS user, audit M4-02)`);
  }
  const id = (flag) => spawnSync("id", [flag, AGENT_USER], { encoding: "utf8" });
  if (id("-u").status !== 0) {
    const r = spawnSync("useradd", ["--system", "--no-create-home", "--shell", "/usr/sbin/nologin", AGENT_USER], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`could not create the ${AGENT_USER} user`);
  }
  return { uid: Number(id("-u").stdout.trim()), gid: Number(id("-g").stdout.trim()) };
}

/** Spawn options for any agent process: separate user plus allow-listed environment. */
export function agentSpawnOptions(extraEnv = {}) {
  const { uid, gid } = agentIdentity();
  return { uid, gid, env: { ...agentEnv(), ...extraEnv } };
}

/** Run apps/agent-demo/src/run.ts as the agent. `files.key` defaults to the setup key. */
export function runAgent(args, { key = join(ROOT, ".secrets/agent-fc.key"), state = join(ROOT, ".secrets/m4-state.json"), out = null, stdio = "pipe" } = {}) {
  const { uid, gid } = agentIdentity();
  const dir = mkdtempSync(join(tmpdir(), "sampan-agent-"));
  try {
    chownSync(dir, uid, gid);
    const own = (name, from, mode = 0o600) => {
      const p = join(dir, name);
      if (from) copyFileSync(from, p); else writeFileSync(p, "");
      chownSync(p, uid, gid);
      spawnSync("chmod", [mode.toString(8), p]);
      return p;
    };
    const env = { HOME: dir };
    for (const k of ["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"]) {
      if (process.env[k] && existsSync(process.env[k])) env[k] = own(`ca-${k}.pem`, process.env[k], 0o644);
    }
    const resultFile = own("results.json", null);
    const passKey = existsSync(key) ? own("agent.key", key) : join(dir, "missing.key");
    const run = resolve(ROOT, "apps/agent-demo/src/run.ts");
    const r = spawnSync(process.execPath, [run, ...args, "--key", passKey, "--state", own("state.json", state), "--out", resultFile],
      { uid, gid, cwd: dir, env: { ...agentEnv(), ...env }, encoding: "utf8", stdio });
    if (out) {
      const text = readFileSync(resultFile, "utf8");
      if (text.trim()) writeFileSync(out, text);
    }
    return r;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2];
  const out = mode === "attack" || mode === "direct" ? join(ROOT, `docs/m4-${mode}-results.json`) : null;
  const r = runAgent(process.argv.slice(2), { out, stdio: "inherit" });
  process.exit(r.status ?? 1);
}
