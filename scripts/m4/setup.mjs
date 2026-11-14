#!/usr/bin/env node
// M4 operator setup (testnet only). Runs with the operator's key (NEAR_TESTNET_PRIVATE_KEY);
// the agent process never does (apps/agent-demo refuses to start if it can see it).
//   node scripts/m4/setup.mjs             add the agent's function-call key, fund a mandate
//   node scripts/m4/setup.mjs --teardown  delete the agent's function-call key
//
// Writes, git-ignored, under .secrets/ (mode 0600):
//   agent-fc.key   the agent's function-call secret key (gate.purchase only)
//   m4-state.json  public facts the agent needs: accounts, mandate hash, its public key
import { mkdirSync, writeFileSync, existsSync, chmodSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { Account, JsonRpcProvider, KeyPair } from "near-api-js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { base58 } from "@scure/base";
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalize, nep413Hash, toBytes, verifySignedMandate } from "../../packages/mandate/src/index.ts";
import { assertTestnet, redact, testnetKeyFromEnv, installRedactingErrorHandlers } from "../m1/safety.mjs";

installRedactingErrorHandlers();
const RPC = "https://rpc.testnet.near.org";
const parent = process.env.NEAR_TESTNET_ACCOUNT_ID;
const id = (p) => `${p}.${parent}`;
const ACC = { gate: id("gate-m3"), token: id("token"), buyer: id("buyer"), agent: id("agent"), payee: id("payee2-m3"), attacker: id("attacker-m4") };
assertTestnet({ networkId: "testnet", rpcUrl: RPC, accounts: [parent, ...Object.values(ACC)] });
const SECRETS = resolve(import.meta.dirname, "../../.secrets");
const KEY_FILE = resolve(SECRETS, "agent-fc.key");
const STATE_FILE = resolve(SECRETS, "m4-state.json");
const provider = new JsonRpcProvider({ url: RPC });
const key = testnetKeyFromEnv();
const as = (a) => new Account(a, provider, key);
const TGAS = (n) => BigInt(n) * 10n ** 12n;
const MILLI = (n) => BigInt(n) * 10n ** 21n;
const link = (h) => `https://testnet.nearblocks.io/txns/${h}`;
const log = (...a) => console.log(redact(a.join(" ")));

/** Delete every function-call key on the agent account that targets the gate (keys left by
 *  earlier or failed runs included); the operator's full-access key stays (M4-CR8). */
async function deleteGateKeys() {
  const list = await provider.query({ request_type: "view_access_key_list", finality: "final", account_id: ACC.agent });
  for (const k of list.keys) {
    const fc = k.access_key.permission?.FunctionCall;
    if (!fc || fc.receiver_id !== ACC.gate) continue;
    const r = await as(ACC.agent).deleteKey(k.public_key);
    log("deleted agent function-call key", link(r.transaction.hash));
  }
}

if (process.argv.includes("--teardown")) {
  await deleteGateKeys();
  rmSync(KEY_FILE, { force: true }); // the key is dead on chain; remove it on disk too (M4-06)
  log("removed .secrets/agent-fc.key");
  process.exit(0);
}
await deleteGateKeys(); // one live agent key at a time

// 1. The agent's function-call key: receiver = gate, methods = [purchase], small allowance.
mkdirSync(SECRETS, { recursive: true, mode: 0o700 });
const fc = KeyPair.fromRandom("ed25519");
const fcPub = fc.getPublicKey().toString();
const add = await as(ACC.agent).addFunctionCallAccessKey({ publicKey: fcPub, contractId: ACC.gate, methodNames: ["purchase"], allowance: MILLI(200) });
log("added agent function-call key (gate.purchase only)", link(add.transaction.hash));

// 2. The buyer signs a mandate for the agent and funds it: items report-001 and report-002,
//    payee payee2-m3, budget 6 tokens (room for the known misses, M4-08), 6 hours. The buyer's mandate key is fresh and dropped.
const sk = ed25519.utils.randomSecretKey();
const mandate = {
  v: "sampan.mandate.v1", network: "testnet", gate: ACC.gate,
  buyer: `near:ed25519:${base58.encode(ed25519.getPublicKey(sk))}`, agent: ACC.agent, asset: ACC.token,
  max_amount: "6000000", payee: ACC.payee, items: ["report-001", "report-002"],
  expiry_ns: String((BigInt(Date.now()) + 6n * 3600_000n) * 1_000_000n), nonce: bytesToHex(randomBytes(32)), refund_to: ACC.buyer,
};
const message = canonicalize(mandate);
const signed = canonicalize({ v: "sampan.signed-mandate.v1", mandate, standard: "nep413", signature: bytesToHex(ed25519.sign(nep413Hash(message, mandate.nonce, mandate.gate), sk)) });
const { mandateHash } = verifySignedMandate(toBytes(signed));
// Since audit A1 the mandate is registered first, with a deposit that pays its storage
// (returned, less what the mandate leaves behind, when it closes); the payment names it by hash.
const cfg = await provider.callFunction({ contractId: ACC.gate, method: "get_config", args: {} });
const deposit = (2400n + BigInt(cfg.max_orders_per_mandate) * 450n) * 10n ** 19n + 2n * BigInt(cfg.registration_deposit);
const reg = await as(ACC.buyer).callFunctionRaw({ contractId: ACC.gate, methodName: "register_mandate", args: { signed_mandate: signed }, deposit, gas: TGAS(30) });
const regRet = JSON.parse(JSON.parse(Buffer.from(reg.status?.SuccessValue ?? "", "base64").toString() || '""') || "{}");
if (regRet.registered !== true) {
  await as(ACC.agent).deleteKey(fcPub);
  throw new Error(`mandate not registered (${String(regRet.reason).slice(0, 40)}); the new agent key was deleted; stop`);
}
const fund = await as(ACC.buyer).callFunctionRaw({
  contractId: ACC.token, methodName: "ft_transfer_call", deposit: 1n, gas: TGAS(250),
  args: { receiver_id: ACC.gate, amount: "6000000", msg: JSON.stringify({ mandate_hash: mandateHash, order: null }) },
});
const view = await provider.callFunction({ contractId: ACC.gate, method: "get_mandate", args: { mandate_hash: mandateHash } });
if (view?.escrow !== "6000000") {
  await as(ACC.agent).deleteKey(fcPub);
  throw new Error("mandate not funded as expected; the new agent key was deleted; stop");
}
log("funded mandate", mandateHash.slice(0, 16) + "…", link(fund.transaction.hash));

// Write the key only once everything else succeeded (M4-CR8).
writeFileSync(KEY_FILE, fc.toString() + "\n", { mode: 0o600 });
chmodSync(KEY_FILE, 0o600);
const state = { gate: ACC.gate, token: ACC.token, agent: ACC.agent, payee: ACC.payee, attacker: ACC.attacker, fakeToken: "fake-usdc.testnet", mandateHash, signedMandate: signed, agentPublicKey: fcPub, fundTx: fund.transaction.hash, keyTx: add.transaction.hash };
writeFileSync(STATE_FILE, JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
log(`state written to .secrets/ (${existsSync(KEY_FILE) ? "key file present, mode 0600" : "key file missing"})`);
