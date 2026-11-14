// Independent audit M4 (docs/audits/M4.md): exploit tests and positive controls for the
// agent demo, its launcher and its report scripts.
//
// Each "M4-NN ..." test asserts the REQUIRED behaviour, so it FAILS while finding M4-NN is
// open. Tests named "control: ..." are positive controls and pass today.
//
// No test here touches a network or a real key. The harness copies the author's scripts
// into a temporary tree and runs them unchanged against a fake JSON-RPC (a `fetch`
// replacement loaded with --import that refuses every other URL). Keys are throwaway
// KeyPair.fromRandom values that never exist on any chain. Attack page text is never
// printed or copied into this file: fixtures are copied as files and read as data.
import { describe, it, expect, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { KeyPair } from "near-api-js";
import { agentEnv, agentSpawnOptions } from "./agent-env.mjs";
import { lint } from "../lint-banned.mjs";

const ROOT = resolve(import.meta.dirname, "../..");
const FIX = join(ROOT, "fixtures/attacks/agent-demo");
const ACC = {
  gate: "gate-m3.audit-m4.testnet", token: "token.audit-m4.testnet", agent: "agent.audit-m4.testnet",
  payee: "payee2-m3.audit-m4.testnet", attacker: "attacker-m4.audit-m4.testnet", fakeToken: "fake-usdc.testnet",
};
const MH = "ab".repeat(32);
const HASH = "1".repeat(32); // base58 of 32 zero bytes
const trees = [];
afterAll(() => { for (const t of trees) rmSync(t, { recursive: true, force: true }); });

// --- fake RPC ---------------------------------------------------------------------
const MOCK = `
import { readFileSync } from "node:fs";
const plan = JSON.parse(readFileSync(process.env.AUDIT_M4_PLAN, "utf8"));
let n = 0;
const ok = (result) => ({ jsonrpc: "2.0", id: "1", result });
globalThis.fetch = async (url, init) => {
  if (String(url) !== "https://rpc.testnet.near.org") throw new Error("audit harness: network refused " + url);
  const req = JSON.parse(init.body);
  let body;
  if (req.method === "query" && req.params.request_type === "view_access_key") {
    body = ok({ nonce: 1, permission: { FunctionCall: { receiver_id: plan.gate, method_names: ["purchase"], allowance: "200000000000000000000000" } }, block_height: 1, block_hash: "${HASH}" });
  } else if (req.method === "query" && req.params.request_type === "view_access_key_list") {
    body = ok({ keys: [], block_height: 1, block_hash: "${HASH}" });
  } else if (req.method === "block") {
    body = ok({ author: "x.testnet", header: { hash: "${HASH}", height: 1, timestamp: 1, timestamp_nanosec: "1", prev_hash: "${HASH}" }, chunks: [] });
  } else if (req.method === "send_tx") {
    const r = plan.sendTx[n++];
    body = r && r.error ? { jsonrpc: "2.0", id: "1", error: r.error } : ok(r ? r.result : null);
  } else {
    body = { jsonrpc: "2.0", id: "1", error: { code: -32000, message: "audit harness: unsupported " + req.method, data: "unsupported" } };
  }
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
};
`;

function tree() {
  const t = mkdtempSync(join(tmpdir(), "audit-m4-"));
  trees.push(t);
  for (const p of ["apps/agent-demo/src/run.ts", "apps/agent-demo/src/fixtures.ts", "apps/agent-demo/src/safety.ts",
    "scripts/m1/safety.mjs", "scripts/m4/setup.mjs", "scripts/m4/write-report.mjs", "scripts/m4/agent-env.mjs"]) {
    mkdirSync(join(t, p, ".."), { recursive: true });
    cpSync(join(ROOT, p), join(t, p));
  }
  cpSync(join(ROOT, "packages/mandate/src"), join(t, "packages/mandate/src"), { recursive: true });
  cpSync(FIX, join(t, "fixtures/attacks/agent-demo"), { recursive: true });
  symlinkSync(join(ROOT, "node_modules"), join(t, "node_modules"), "dir");
  mkdirSync(join(t, ".secrets"), { mode: 0o700 });
  mkdirSync(join(t, "docs"));
  writeFileSync(join(t, ".secrets/agent-fc.key"), KeyPair.fromRandom("ed25519").toString() + "\n", { mode: 0o600 });
  writeFileSync(join(t, ".secrets/m4-state.json"), JSON.stringify({ ...ACC, mandateHash: MH }));
  writeFileSync(join(t, "mock-rpc.mjs"), MOCK);
  return t;
}

function run(t, script, args, sendTx, extraEnv = {}) {
  const plan = join(t, "plan.json");
  writeFileSync(plan, JSON.stringify({ gate: ACC.gate, sendTx }));
  return spawnSync(process.execPath, ["--import", pathToFileURL(join(t, "mock-rpc.mjs")).href, join(t, script), ...args], {
    cwd: t, encoding: "utf8", timeout: 60_000, env: { PATH: process.env.PATH, AUDIT_M4_PLAN: plan, ...extraEnv },
  });
}

const b64 = (s) => Buffer.from(s).toString("base64");
const ev = (o) => "EVENT_JSON:" + JSON.stringify(o);
function txResult({ ret, logs = [], failure }) {
  const status = failure ? { Failure: failure } : { SuccessValue: b64(JSON.stringify(ret)) };
  return {
    result: {
      final_execution_status: "FINAL", status, transaction: { hash: "AuditTx" + Math.random().toString(36).slice(2, 10) },
      transaction_outcome: { id: HASH, block_hash: HASH, proof: [], outcome: { logs: [], receipt_ids: [], gas_burnt: 0, tokens_burnt: "0", executor_id: ACC.agent, status: { SuccessReceiptId: HASH } } },
      receipts_outcome: [{ id: HASH, block_hash: HASH, proof: [], outcome: { logs, receipt_ids: [], gas_burnt: 0, tokens_burnt: "0", executor_id: ACC.gate, status: failure ? { Failure: failure } : { SuccessValue: "" } } }],
    },
  };
}
const RULES = ["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"];
function decided(decision, failing, payoutStatus) {
  const ret = JSON.stringify({ decision, anchored: true, order_id: "cd".repeat(32), core_hash: "ef".repeat(32) });
  const logs = [ev({ standard: "sampan", version: "1.0.0", event: "receipt", data: [{ core_hash: "ef".repeat(32), core: { rules: RULES.map((id) => ({ id, pass: !failing.includes(id) })) } }] })];
  if (payoutStatus) logs.push(ev({ standard: "sampan", version: "1.0.0", event: "payout", data: [{ mandate_hash: MH, order_id: "cd".repeat(32), status: payoutStatus }] }));
  return txResult({ ret, logs });
}
/** Gate outcomes for the labelled suite in the order run.ts submits it (sorted, attacks first). */
function suiteOutcomes(payoutStatus) {
  const all = readdirSync(FIX).filter((f) => f.endsWith(".json")).sort().map((f) => JSON.parse(readFileSync(join(FIX, f), "utf8")));
  const ordered = [...all.filter((f) => f.label === "attack"), ...all.filter((f) => f.label === "control")];
  // Author adaptation (M4-08): every expected release (controls and known misses) gets a payout.
  return ordered.map((f) => decided(f.expected.decision, f.expected.failing, f.expected.decision === "release" ? payoutStatus : null));
}
const rpcInvalidTx = (inner) => ({ error: { name: "HANDLER_ERROR", code: -32000, message: "Server error", cause: { name: "INVALID_TRANSACTION", info: {} }, data: { TxExecutionError: { InvalidTxError: inner } } } });
const receiverMismatch = rpcInvalidTx({ InvalidAccessKeyError: { ReceiverMismatch: { ak_receiver: ACC.gate, tx_receiver: ACC.token } } });
const otherError = { error: { code: -32000, message: "Server error", name: "HANDLER_ERROR", cause: { name: "INTERNAL_ERROR", info: {} }, data: "audit" } };

// --- M4-02 ------------------------------------------------------------------------
describe("M4-02 the agent process can reach the operator's key", () => {
  it.runIf(process.platform === "linux")("M4-02: a process started with agentEnv() cannot read a credential held by the process that started it", () => {
    // The launcher (agent-env.mjs, started by pnpm) holds the operator's full environment and
    // starts the agent as the same OS user. Model that with a synthetic canary only.
    const launcher = `
      import { spawnSync } from "node:child_process";
      import { agentSpawnOptions } from ${JSON.stringify(pathToFileURL(join(ROOT, "scripts/m4/agent-env.mjs")).href)};
      const child = "const fs = require('node:fs'); let seen = false; try { seen = fs.readFileSync('/proc/' + process.ppid + '/environ', 'utf8').includes('AUDIT_M4_CANARY_PRIVATE_KEY=canary-not-a-key'); } catch {} process.stdout.write(String(seen));";
      // Author adaptation after the fix: the launcher starts the agent with agentSpawnOptions()
      // (separate OS user plus allow-listed environment), not with agentEnv() alone.
      const r = spawnSync(process.execPath, ["-e", child], { ...agentSpawnOptions(), encoding: "utf8" });
      process.stdout.write(r.stdout);`;
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", launcher], {
      encoding: "utf8", env: { PATH: process.env.PATH, AUDIT_M4_CANARY_PRIVATE_KEY: "canary-not-a-key" },
    });
    expect(r.stdout.trim(), "agent could read the launcher's credential").toBe("false");
  });
  it("control: agentEnv() itself passes no credential variable", () => {
    expect(Object.keys(agentEnv({ PATH: "/bin", AUDIT_M4_CANARY_PRIVATE_KEY: "x" }))).toEqual(["PATH"]);
  });
});

// --- M4-03 ------------------------------------------------------------------------
function report(direct, attackRows) {
  const t = tree();
  const attack = { date: "d", gate: ACC.gate, agent: ACC.agent, mandateHash: MH, summary: { attacks: 1, attacksRefused: 1, controls: 0, controlsReleased: 0, falsePositives: 0 }, rows: attackRows };
  writeFileSync(join(t, "docs/m4-attack-results.json"), JSON.stringify(attack));
  writeFileSync(join(t, "docs/m4-direct-results.json"), JSON.stringify({ date: "d", agent: ACC.agent, rows: direct }));
  writeFileSync(join(t, "docs/m4-edge-results.json"), JSON.stringify({ date: "d", agent: ACC.agent, results: [] }));
  const r = spawnSync(process.execPath, [join(t, "scripts/m4/write-report.mjs")], { encoding: "utf8", env: { PATH: process.env.PATH } });
  return { status: r.status, page: existsSync(join(t, "docs/m4-testnet.md")) ? readFileSync(join(t, "docs/m4-testnet.md"), "utf8") : "" };
}
const okAttack = { id: "inj-01-swapped-payee", label: "attack", decision: "refuse", failing: ["R8"], coreHash: "ef".repeat(32), tx: "https://testnet.nearblocks.io/txns/X", asExpected: true };

describe("M4-03 the evidence page states expectations, not outcomes", () => {
  it("M4-03: a direct-call row that was NOT refused is not published as 'refused by the protocol'", () => {
    const failed = { action: "token.ft_transfer without deposit", expected: "refused: does not match|ReceiverMismatch|receiver", asExpected: false, tx: "https://testnet.nearblocks.io/txns/LEAK", detail: "{\"transferred\":true}" };
    const { status, page } = report([failed], [okAttack]);
    const row = page.split("\n").find((l) => l.startsWith("| token.ft_transfer without deposit"));
    expect(status !== 0 || !row || !row.includes("refused by the protocol"), row).toBe(true);
  });
  it("M4-03b: an unanchored or unexpected refusal is not covered by 'Every refusal is anchored'", () => {
    const bad = { ...okAttack, coreHash: null, asExpected: false, decision: "error", failing: [] };
    const { status, page } = report([], [bad]);
    expect(status !== 0 || !page.includes("Every refusal is anchored")).toBe(true);
  });
  it("control: a clean result set generates the page", () => {
    const { status, page } = report([{ action: "send NEAR", expected: "refused: full access", asExpected: true, tx: "", detail: "Access key requires full access" }], [okAttack]);
    expect(status).toBe(0);
    expect(page).toContain("| send NEAR | refused by the protocol |");
  });
});

// --- M4-04 ------------------------------------------------------------------------
describe("M4-04 outcome classifiers accept failures that are not the protocol's refusal", () => {
  const direct = (step3) => {
    const t = tree();
    const steps = [decided("release", [], "done"), otherError, step3, otherError, otherError, otherError, otherError, otherError, otherError, otherError];
    const r = run(t, "apps/agent-demo/src/run.ts", ["direct"], steps);
    const res = JSON.parse(readFileSync(join(t, "docs/m4-direct-results.json"), "utf8"));
    return { r, row: res.rows.find((x) => x.action === "token.ft_transfer without deposit") };
  };
  it("M4-04: a call that reached the token and failed there is not reported as refused by the protocol", () => {
    // The transaction executed on the token (a key that can reach it), which then panicked.
    const executed = txResult({ failure: { ActionError: { index: 0, kind: { FunctionCallError: { ExecutionError: "Smart contract panicked: The account receiver_id is not registered" } } } } });
    const { row } = direct(executed);
    expect(row.asExpected, row.detail).toBe(false);
  });
  it("control: the protocol's ReceiverMismatch refusal is reported as expected", () => {
    const { row } = direct(receiverMismatch);
    expect(row.asExpected, row.detail).toBe(true);
  });
  // edge-cases.mjs needs the operator key and the network, so its classifiers are read from
  // the source, exactly as written, and applied to messages the demo itself can produce.
  const src = readFileSync(join(ROOT, "scripts/m4/edge-cases.mjs"), "utf8");
  const classifier = (marker) => {
    const line = src.split("\n").find((l) => l.includes(marker));
    const m = line.match(/\/((?:[^/\\]|\\.)+)\/([a-z]*)\.test\(/);
    return new RegExp(m[1], m[2]);
  };
  it("M4-04b: 'allowance exhausted' is not satisfied by the agent's own pre-flight refusal", () => {
    // safety.ts's message when a key has no allowance at all: the protocol was never asked.
    expect(classifier('record("allowance exhausted').test("refusing to run: the agent key has no allowance limit")).toBe(false);
  });
  it("M4-04c: 'after removal' is not satisfied by unrelated not-found or unknown errors", () => {
    const re = classifier('record("after removal');
    for (const msg of ["Unknown invalid access key error", "https://rpc.testnet.near.org Not Found", "account agent.x.testnet does not exist while viewing"]) {
      expect(re.test(msg), msg).toBe(false);
    }
    expect(re.test("Access key ed25519:[key] does not exist at block height 1"), "control").toBe(true);
  });
});

// --- M4-05 ------------------------------------------------------------------------
describe("M4-05 a control is counted as released without checking that the payee was paid", () => {
  const attack = (payout) => {
    const t = tree();
    const r = run(t, "apps/agent-demo/src/run.ts", ["attack"], suiteOutcomes(payout));
    return { r, res: JSON.parse(readFileSync(join(t, "docs/m4-attack-results.json"), "utf8")) };
  };
  it("M4-05: controls whose payout failed are not reported as released", () => {
    const { r, res } = attack("failed");
    expect(res.summary.controlsReleased).toBe(0);
    expect(r.status).not.toBe(0);
  });
  it("control: the suite with paid controls is all as expected (harness check)", () => {
    const { r, res } = attack("done");
    expect(r.status, r.stderr).toBe(0);
    // Author adaptation (M4-08): the suite now also holds two labelled known misses.
    expect(res.summary).toEqual({ attacks: 6, attacksRefused: 6, knownMisses: 2, knownMissesReleased: 2, controls: 3, controlsReleased: 3, falsePositives: 0 });
    expect(r.stdout).not.toMatch(/UNEXPECTED/);
  });
});

// --- M4-06 ------------------------------------------------------------------------
describe("M4-06 teardown leaves the agent's key file on disk", () => {
  it("M4-06: setup --teardown removes .secrets/agent-fc.key", () => {
    const t = tree();
    const throwaway = KeyPair.fromRandom("ed25519").toString(); // never on any chain
    const r = run(t, "scripts/m4/setup.mjs", ["--teardown"], [], { NEAR_TESTNET_ACCOUNT_ID: "audit-m4.testnet", NEAR_TESTNET_PRIVATE_KEY: throwaway });
    expect(r.status, r.stderr).toBe(0);
    expect(existsSync(join(t, ".secrets/agent-fc.key"))).toBe(false);
  });
});

// --- M4-07 ------------------------------------------------------------------------
describe("M4-07 nothing keeps attack text inside fixtures/attacks/", () => {
  it("M4-07: the banned-pattern lint flags attack page text copied into a document", () => {
    const t = mkdtempSync(join(tmpdir(), "audit-m4-lint-"));
    trees.push(t);
    cpSync(FIX, join(t, "fixtures/attacks/agent-demo"), { recursive: true });
    const page = JSON.parse(readFileSync(join(FIX, "inj-01-swapped-payee.json"), "utf8")).page;
    mkdirSync(join(t, "docs"));
    writeFileSync(join(t, "docs/notes.md"), "# Notes\n\n" + page + "\n");
    const findings = lint(t);
    expect(findings.some((f) => f.file === "docs/notes.md"), JSON.stringify(findings.map((f) => f.rule))).toBe(true);
  });
});
