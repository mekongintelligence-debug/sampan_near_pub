#!/usr/bin/env node
// After the person-run mainnet deploy and lock: add the gate to the checker's known gates
// (apps/checker/src/gates.ts), but only after reading mainnet (final, READ-ONLY) that the gate
// runs the reviewed code, has no access keys, and is configured for native USDC on mainnet.
// It never signs anything. Claude Code may run it; a person reviews the resulting diff.
//   node scripts/mainnet/add-known-gate.mjs            (reads examples/mainnet-gate.json)
//
// Why not add the entry before: until the team owns the account, someone else could create that
// name and deploy the open-source reviewed code with their own settings; the checker would then
// call it a known Sampan gate.
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { MAINNET_RPC, REVIEWED_CODE_HASH, USDC } from "./deploy-gate.mjs";

const GATES = resolve(import.meta.dirname, "../../apps/checker/src/gates.ts");

/** Problems with the gate as read from mainnet; empty means it may be listed. */
export function checkListable({ account, keys, config, totals }) {
  const p = [];
  if (account?.code_hash !== REVIEWED_CODE_HASH) p.push(`the gate runs ${account?.code_hash ?? "no code"}, not the reviewed ${REVIEWED_CODE_HASH}`);
  if (!Array.isArray(keys) || keys.length !== 0) p.push("the gate still has access keys: lock it first");
  if (config?.network !== "mainnet" || config?.token !== USDC) p.push("the gate is not configured for native USDC on mainnet");
  if (totals?.stopped !== false) p.push("the gate is stopped");
  return p;
}

/**
 * A2F-02: the first block height at which the gate's key list is empty, given a height `h` at which
 * it is known to be empty. A delete-keys transaction may remove keys in steps, so the block of the
 * last receipt of one transaction is not enough: the lock height is where the list BECOMES empty.
 * `isEmptyAt(height)` returns true or false (false also when the account does not exist yet) and
 * throws when the RPC cannot answer for that height (not an archival node): that stops the script.
 */
export async function firstEmptyHeight(isEmptyAt, h) {
  if (!Number.isSafeInteger(h) || h <= 1) throw new Error("bad lock height");
  if (!(await isEmptyAt(h))) throw new Error("the key list is not empty at the lock block");
  let hi = h; // empty at hi
  let step = 1;
  let lo = hi - step; // find a height that is not empty
  while (lo >= 1 && (await isEmptyAt(lo))) { hi = lo; step *= 2; lo = hi - step; }
  if (lo < 1) { lo = 0; if (await isEmptyAt(1)) throw new Error("the key list is empty from the first block: not a gate that was locked"); lo = 1; }
  while (hi - lo > 1) {
    const mid = Math.floor((lo + hi) / 2);
    if (await isEmptyAt(mid)) hi = mid; else lo = mid;
  }
  return hi;
}

/** The checker's gates.ts with the mainnet entry added (idempotent). */
export function withMainnetGate(source, gate, lockedAtBlock) {
  if (!/^[a-z0-9_-]+(\.[a-z0-9_-]+)*\.near$/.test(gate)) throw new Error("not a named .near account");
  if (!Number.isSafeInteger(lockedAtBlock) || lockedAtBlock <= 0) throw new Error("the lock block height is required (A2-01)");
  if (source.includes(`account: "${gate}"`)) return source;
  const entry = `mainnet: [
    {
      account: "${gate}",
      codeHashes: ["${REVIEWED_CODE_HASH}"], // reviewed in audit A1R; deployed and locked by the person-run runbook
      token: "${USDC}", // native USDC on NEAR
      label: "Sampan Trust checkout gate (mainnet, USDC)",
      lockedAtBlock: ${lockedAtBlock}, // the block where the key list became empty: decisions after it ran the reviewed code
    },
  ],`;
  const out = source.replace(/mainnet: \[\],[^\n]*/, entry);
  if (out === source) throw new Error("could not find the empty mainnet list in gates.ts");
  return out;
}

async function main() {
  const rec = JSON.parse(readFileSync(resolve(import.meta.dirname, "../../examples/mainnet-gate.json"), "utf8"));
  const rpc = async (method, params) => {
    const r = await fetch(MAINNET_RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: "add-gate", method, params }) });
    return (await r.json()).result;
  };
  const view = async (m) => {
    const r = await rpc("query", { request_type: "call_function", finality: "final", account_id: rec.gate, method_name: m, args_base64: "e30=" });
    return r?.result ? JSON.parse(Buffer.from(r.result).toString()) : null;
  };
  const account = await rpc("query", { request_type: "view_account", finality: "final", account_id: rec.gate });
  const keys = (await rpc("query", { request_type: "view_access_key_list", finality: "final", account_id: rec.gate }))?.keys;
  const problems = checkListable({ account, keys, config: await view("get_config"), totals: await view("get_totals") });
  if (!rec.lock_tx) problems.push("examples/mainnet-gate.json has no lock_tx: run verify with --lock-tx <hash of the delete-keys transaction>");
  if (problems.length) { console.error("STOP:\n- " + problems.join("\n- ")); process.exit(1); }
  // The lock height: the block in which the delete-keys transaction ran.
  const lt = await rpc("EXPERIMENTAL_tx_status", { tx_hash: rec.lock_tx, sender_account_id: rec.gate, wait_until: "FINAL" });
  const deletes = (lt?.transaction?.actions ?? []).filter((x) => x?.DeleteKey).length;
  if (lt?.transaction?.receiver_id !== rec.gate || deletes === 0) { console.error("STOP: lock_tx is not a delete-keys transaction on the gate"); process.exit(1); }
  const lastBlock = (lt.receipts_outcome ?? []).map((o) => o.block_hash).at(-1) ?? lt.transaction_outcome?.block_hash;
  const txHeight = (await rpc("block", { block_id: lastBlock }))?.header?.height;
  // A2F-02: the lock height is where the key list becomes empty (archival read at block heights),
  // not the block of the last receipt of the transaction.
  const isEmptyAt = async (h) => {
    const r = await fetch(MAINNET_RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: "add-gate", method: "query", params: { request_type: "view_access_key_list", block_id: h, account_id: rec.gate } }) });
    const j = await r.json();
    if (Array.isArray(j?.result?.keys)) return j.result.keys.length === 0;
    if (/does not exist|UnknownAccount/i.test(JSON.stringify(j?.error ?? ""))) return false;
    throw new Error("the RPC node cannot answer for an old block (needs an archival node)");
  };
  const height = await firstEmptyHeight(isEmptyAt, txHeight);
  writeFileSync(GATES, withMainnetGate(readFileSync(GATES, "utf8"), rec.gate, height));
  console.log(`Added ${rec.gate} to apps/checker/src/gates.ts (reviewed code, locked, USDC). Review the diff, then run make check.`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) main().catch((e) => { console.error("error: " + String(e?.message ?? e).slice(0, 200)); process.exit(1); });
