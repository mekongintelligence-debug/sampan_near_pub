#!/usr/bin/env node
// Testnet maintenance (M3): wipe the state of gate-m3.<parent> after a state-layout change,
// so the new gate can be deployed and initialised again (NEAR refuses to delete accounts
// with large state). Deploys the throwaway spikes/gate2/cleaner contract, removes every
// storage key, then deploys the gate wasm. Initialisation is left to testnet-run.mjs.
//   make wasm-release && node scripts/m3/reset-testnet-gate.mjs
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Account, JsonRpcProvider } from "near-api-js";
import { assertTestnet, redact, testnetKeyFromEnv, installRedactingErrorHandlers } from "../m1/safety.mjs";

installRedactingErrorHandlers();
const RPC = "https://rpc.testnet.near.org";
const parent = process.env.NEAR_TESTNET_ACCOUNT_ID;
const gateId = `gate-m3.${parent}`;
assertTestnet({ networkId: "testnet", rpcUrl: RPC, accounts: [parent, gateId] });
const provider = new JsonRpcProvider({ url: RPC });
const gate = new Account(gateId, provider, testnetKeyFromEnv());
const wasm = (p) => readFileSync(resolve(import.meta.dirname, "../..", p));

const keys = async () => {
  const r = await provider.query({ request_type: "view_state", finality: "final", account_id: gateId, prefix_base64: "" });
  return r.values.map((v) => v.key);
};
let ks = await keys();
console.log(`state keys: ${ks.length}`);
const d1 = await gate.deployContract(wasm("spikes/gate2/target/wasm32-unknown-unknown/release/spike_cleaner.wasm"));
console.log("deployed cleaner", d1.transaction.hash);
while (ks.length) {
  const batch = ks.slice(0, 100);
  const r = await gate.callFunctionRaw({ contractId: gateId, methodName: "clean", args: { keys: batch }, gas: 300n * 10n ** 12n });
  console.log("cleaned", Buffer.from(r.status.SuccessValue ?? "", "base64").toString(), r.transaction.hash);
  ks = await keys();
}
const d2 = await gate.deployContract(wasm("target/wasm32-unknown-unknown/release/sampan_gate.wasm"));
console.log("deployed gate", d2.transaction.hash, redact(JSON.stringify(d2.status)).slice(0, 60));
