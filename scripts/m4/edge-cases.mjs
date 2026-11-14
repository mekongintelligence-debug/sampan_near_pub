#!/usr/bin/env node
// M4 edge cases (docs/SECURITY.md 6, M4), testnet only, run by the operator after setup:
//   1. gas allowance exhausted: a function-call key with a tiny allowance cannot purchase;
//   2. key removed mid-demo: the agent's purchase works, the operator deletes the key, the
//      next purchase fails.
// The agent runs as a separate process without the operator's secrets (as in demo:attack).
import { runAgent } from "./agent-env.mjs";
import { writeFileSync, readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { Account, JsonRpcProvider, KeyPair } from "near-api-js";
import { assertTestnet, redact, testnetKeyFromEnv, installRedactingErrorHandlers } from "../m1/safety.mjs";

installRedactingErrorHandlers();
const RPC = "https://rpc.testnet.near.org";
const ROOT = resolve(import.meta.dirname, "../..");
const st = JSON.parse(readFileSync(resolve(ROOT, ".secrets/m4-state.json"), "utf8"));
assertTestnet({ networkId: "testnet", rpcUrl: RPC, accounts: [process.env.NEAR_TESTNET_ACCOUNT_ID, st.agent, st.gate] });
const operator = new Account(st.agent, new JsonRpcProvider({ url: RPC }), testnetKeyFromEnv());
const link = (h) => `https://testnet.nearblocks.io/txns/${h}`;
const results = [];

function probe(keyFile) {
  // Separate OS user, allow-listed environment (M4-02, M4-CR3).
  const r = runAgent(["probe"], { key: keyFile });
  const line = (r.stdout ?? "").split("\n").find((l) => l.startsWith("PROBE "));
  return line ? JSON.parse(line.slice(6)) : { ok: false, error: redact(r.stderr ?? "").slice(0, 300) };
}
function record(name, ok, detail, tx = "") {
  results.push({ case: name, asExpected: ok, detail: redact(detail).slice(0, 240), tx });
  console.log(`${ok ? "AS EXPECTED" : "UNEXPECTED "}  ${name}${tx ? "  " + tx : ""}  (${redact(detail).slice(0, 120)})`);
}
async function withKey(allowance, fn) {
  const kp = KeyPair.fromRandom("ed25519");
  const file = resolve(ROOT, `.secrets/edge-${Date.now()}.key`);
  writeFileSync(file, kp.toString() + "\n", { mode: 0o600 });
  const pub = kp.getPublicKey().toString();
  const add = await operator.addFunctionCallAccessKey({ publicKey: pub, contractId: st.gate, methodNames: ["purchase"], allowance });
  try { await fn(file, pub, add.transaction.hash); }
  finally {
    rmSync(file, { force: true });
    // Never leave a live key behind if a step threw before deleting it (M4-CR6).
    await operator.deleteKey(pub).catch(() => {});
  }
}

// 1. Allowance too small from the start (1e18 yocto): the protocol refuses before execution.
//    (Using up an allowance mid-demo is the same check at a later point; not run, audit M4-09.)
await withKey(10n ** 18n, async (file, pub, addTx) => {
  const p = probe(file);
  record("operator adds a key whose allowance is too small from the start", true, "added", link(addTx));
  // Evidence is the protocol's refusal text: no transaction is included (audit M4-03, M4-09).
  record("allowance exhausted (too small for one purchase): refused by the protocol before execution", !p.ok && !p.tx && /Not enough allowance for access key/.test(p.error), p.error || JSON.stringify(p.ret));
  const del = await operator.deleteKey(pub);
  record("operator removes the tiny-allowance key", true, "deleted", link(del.transaction.hash));
});

// 2. Key removed mid-demo. The allowance must cover the protocol's pessimistic gas price for the
//    prepaid 150 Tgas (0.1 NEAR was refused on testnet); 0.25 NEAR works.
await withKey(250n * 10n ** 21n, async (file, pub) => {
  const before = probe(file);
  record("before removal: the agent's valid purchase is released", before.ok && before.ret?.decision === "release", JSON.stringify(before.ret ?? before.error), before.tx ? link(before.tx) : "");
  const del = await operator.deleteKey(pub);
  record("operator deletes the agent key mid-demo", true, "deleted", link(del.transaction.hash));
  await new Promise((r) => setTimeout(r, 3000));
  const after = probe(file);
  record("after removal: the agent cannot act", !after.ok && !after.tx && /Access key \S+ does not exist at block height/.test(after.error), after.error || JSON.stringify(after.ret));
});

writeFileSync(resolve(ROOT, "docs/m4-edge-results.json"), JSON.stringify({ date: new Date().toISOString(), agent: st.agent, results }, null, 2) + "\n");
const bad = results.filter((r) => !r.asExpected);
console.log(bad.length ? `\n${bad.length} unexpected outcome(s)` : "\nM4 edge cases: all outcomes as expected");
process.exit(bad.length ? 1 : 0);
