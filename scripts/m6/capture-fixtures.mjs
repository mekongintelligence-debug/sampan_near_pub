#!/usr/bin/env node
// M6: build real receipt envelopes from the M4 testnet run and record the RPC answers the
// checker needs, so its tests replay genuine chain data offline. Read-only: views only, no
// key is used. The signed mandate in .secrets/m4-state.json is public data (no secret).
//   node scripts/m6/capture-fixtures.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { verifyReceipt } from "../../apps/checker/src/verify.ts";

const ROOT = resolve(import.meta.dirname, "../..");
const RPC = "https://rpc.testnet.near.org";
const st = JSON.parse(readFileSync(resolve(ROOT, ".secrets/m4-state.json"), "utf8"));
const runs = JSON.parse(readFileSync(resolve(ROOT, "docs/m4-attack-results.json"), "utf8"));
if (runs.mandateHash !== st.mandateHash) throw new Error("state and results are from different runs");

// Transaction signatures (ed25519:<88 base58>) look exactly like NEAR private keys to the
// secrets scan. They are public, but the checker never reads them, so they are dropped from
// the fixtures rather than weakening the scan rule.
const SIG = /^ed25519:[1-9A-HJ-NP-Za-km-z]{80,}$/;
function scrub(v) {
  if (typeof v === "string") return SIG.test(v) ? "ed25519:signature-omitted-from-fixture" : v;
  if (Array.isArray(v)) return v.map(scrub);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrub(x)]));
  return v;
}

async function rpc(method, params) {
  const r = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: "capture", method, params }) });
  return (await r.json()).result;
}

for (const [id, name, note] of [["ctl-01-report-001", "release", "Bought report-001 as the buyer asked."], ["inj-01-swapped-payee", "refuse", null]]) {
  const row = runs.rows.find((r) => r.id === id);
  const hash = row.tx.split("/").pop();
  const tx = await rpc("tx", { tx_hash: hash, sender_account_id: st.agent, wait_until: "FINAL" });
  const call = tx.transaction.actions[0].FunctionCall;
  const order = JSON.parse(JSON.parse(Buffer.from(call.args, "base64").toString()).order);
  const ev = tx.receipts_outcome.flatMap((o) => o.outcome.logs).filter((l) => l.startsWith("EVENT_JSON:")).map((l) => JSON.parse(l.slice(11))).find((e) => e.event === "receipt");
  const envelope = {
    v: "sampan.receipt-envelope.v1", core: ev.data[0].core, core_hash: ev.data[0].core_hash,
    signed_mandate: JSON.parse(st.signedMandate), order,
    tx: { deposit: st.fundTx, decision: hash, payout: null }, untrusted: note ? { agent_note: note } : null,
  };
  // Record every RPC exchange the checker makes for this receipt.
  const recorded = [];
  const fetchFn = async (url, init) => {
    const res = await fetch(url, init);
    const body = await res.json();
    const req = JSON.parse(init.body);
    recorded.push({ method: req.method, params: req.params, response: scrub(body) });
    return { ok: res.ok, json: async () => body };
  };
  const result = await verifyReceipt(new TextEncoder().encode(JSON.stringify(envelope)), { rpcUrl: RPC, fetchFn });
  console.log(name, result.overall, result.checks.map((c) => `${c.id}:${c.status}`).join(" "));
  // The live test gate keeps its owner key (decision Q16), so "locked" and "then" cannot
  // pass live; every other check must.
  const bad = result.checks.filter((c) => c.status !== "pass" && !(c.status === "unknown" && (c.id === "locked" || c.id === "then")));
  if (bad.length) throw new Error(`${name}: live check failed (${bad.map((c) => c.id).join(", ")}); not writing fixtures`);
  // MODELLED, not recorded: the fixtures describe the gate as locked (no access keys) and the
  // RPC as non-archival, which is what a mainnet gate looks like after Q16. Tests that need
  // the live situation (owner key present) patch these answers explicitly (audit M6-01).
  const kept = recorded.filter((r) => !(r.method === "query" && (r.params.request_type === "view_access_key_list" || r.params.block_id !== undefined)));
  kept.push({ method: "query", params: { request_type: "view_access_key_list", account_id: envelope.core.gate, finality: "final" }, modelled: "gate locked (no access keys); the live test gate keeps its key (Q16)", response: { jsonrpc: "2.0", id: "capture", result: { block_hash: "11111111111111111111111111111111", block_height: 1, keys: [] } } });
  writeFileSync(resolve(ROOT, `apps/checker/test/fixtures/${name}.json`), JSON.stringify({ captured: new Date().toISOString(), rpc: RPC, modelled: ["view_access_key_list at final: locked gate", "no archival history (historic queries unknown)"], envelope, recorded: kept }, null, 2) + "\n");
}
