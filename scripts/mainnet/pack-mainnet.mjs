#!/usr/bin/env node
// After the person-run mainnet purchases: pack the two example receipts from chain data only
// (READ-ONLY, NEAR's archival mainnet RPC) and write them to examples/mainnet/.
//   node scripts/mainnet/pack-mainnet.mjs
// Inputs (written by the person-run scripts; account names and transaction hashes only):
//   examples/mainnet-gate.json                 the gate
//   examples/mainnet-proof/record.json         the release after the lock (runbook step 7b)
//   examples/mainnet-proof/refusal-mandate.json the refusal example (runbook step 8)
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { packReceipt } from "../../packages/receipt/src/pack.ts";
import { USDC } from "./deploy-gate.mjs";

const ROOT = resolve(import.meta.dirname, "../..");
const RPC = "https://archival-rpc.mainnet.near.org";
const read = (f) => JSON.parse(readFileSync(resolve(ROOT, f), "utf8"));
const fetchTx = async (hash, sender) => {
  const r = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: "pack", method: "EXPERIMENTAL_tx_status", params: { tx_hash: hash, sender_account_id: sender, wait_until: "FINAL" } }) });
  return (await r.json()).result ?? null;
};

const gate = read("examples/mainnet-gate.json").gate;
const out = resolve(ROOT, "examples/mainnet");
mkdirSync(out, { recursive: true });
let packed = 0;

// The release: the decision is in the NEAR transaction that delivered the payment (1Click).
if (existsSync(resolve(ROOT, "examples/mainnet-proof/record.json"))) {
  const rec = read("examples/mainnet-proof/record.json");
  let env = null;
  for (const { hash } of rec.near_txs ?? []) {
    try {
      env = await packReceipt({ gate, token: USDC, decisionTx: hash, mandateTx: rec.register_tx, depositTx: hash, orderId: rec.order_id }, fetchTx);
      break;
    } catch { /* not the decision transaction; try the next */ }
  }
  if (!env) { console.error("STOP: no NEAR transaction in record.json holds the gate's decision for this order"); process.exit(1); }
  writeFileSync(resolve(out, "direct-checkout-release.json"), JSON.stringify(JSON.parse(env.text), null, 2) + "\n");
  console.log(`release packed: ${env.core.decision}, payout ${env.tx.payout ? "in the same transaction" : "not recorded"}`);
  packed++;
}

// The refusal: the agent's purchase transaction.
if (existsSync(resolve(ROOT, "examples/mainnet-proof/refusal-mandate.json"))) {
  const r = read("examples/mainnet-proof/refusal-mandate.json");
  if (!r.refuse_tx) { console.error("STOP: refusal-mandate.json has no refuse_tx yet"); process.exit(1); }
  const env = await packReceipt({ gate, token: USDC, decisionTx: r.refuse_tx, mandateTx: r.register_tx, depositTx: r.fund_tx ?? null }, fetchTx);
  writeFileSync(resolve(out, "agent-refusal.json"), JSON.stringify(JSON.parse(env.text), null, 2) + "\n");
  console.log(`refusal packed: ${env.core.decision}`);
  packed++;
}
console.log(packed ? `\n${packed} receipt(s) in examples/mainnet/. Check them: pnpm dry-run` : "nothing to pack yet");
