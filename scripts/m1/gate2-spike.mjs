#!/usr/bin/env node
// Gate 2 (M1): can an agent's function-call key reach the gate and nothing else, while the
// gate itself still moves the tokens it holds? Testnet only. Run: node scripts/m1/gate2-spike.mjs
//
// Uses NEAR_TESTNET_ACCOUNT_ID and NEAR_TESTNET_PRIVATE_KEY. Keys stay in memory; the agent's
// function-call key is created fresh for this run and always deleted at the end (finally).
// A "must fail" step only counts if it fails for its stated protocol reason (audit M1-01).
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Account, JsonRpcProvider, KeyPair } from "near-api-js";
import { assertTestnet, redact, testnetKeyFromEnv, installRedactingErrorHandlers } from "./safety.mjs";

installRedactingErrorHandlers();
const RPC = "https://rpc.testnet.near.org";
const parentId = process.env.NEAR_TESTNET_ACCOUNT_ID;
const id = (p) => `${p}.${parentId}`;
const ACC = { token: id("token"), gate: id("gate"), buyer: id("buyer"), merchant: id("merchant"), agent: id("agent") };
assertTestnet({ networkId: "testnet", rpcUrl: RPC, accounts: [parentId, ...Object.values(ACC)] });

const key = testnetKeyFromEnv();
const provider = new JsonRpcProvider({ url: RPC });
const signerPub = KeyPair.fromString(key).getPublicKey().toString();
const as = (accountId, k = key) => new Account(accountId, provider, k);
const NEAR = (n) => BigInt(Math.round(n * 1000)) * 10n ** 21n;
const link = (h) => `https://testnet.nearblocks.io/txns/${h}`;
const log = (...a) => console.log(redact(a.join(" ")));
const results = [];

async function exists(accountId) {
  try { await provider.viewAccount({ accountId }); return true; } catch { return false; }
}

const decodeReturn = (r) => {
  const v = r?.status?.SuccessValue;
  if (!v) return "";
  try { return JSON.parse(Buffer.from(v, "base64").toString("utf8")); } catch { return ""; }
};

/**
 * expect: { ok: true } must succeed; { ok: true, returns: /re/ } must succeed and return a
 * matching value; { ok: false, reason: /re/ } must fail with an error matching the reason.
 */
async function step(name, expect, fn) {
  let outcome, detail = "", tx = "";
  try {
    const r = await fn();
    const hash = r?.transaction?.hash ?? r?.transaction_outcome?.id;
    tx = hash ? link(hash) : "";
    if (r?.status?.Failure) { outcome = "failure"; detail = redact(JSON.stringify(r.status.Failure)).slice(0, 300); }
    else { outcome = "success"; detail = String(decodeReturn(r)).slice(0, 200); }
  } catch (e) {
    outcome = "failure";
    detail = redact(e?.message ?? e).slice(0, 300);
  }
  let asExpected;
  if (expect.ok) asExpected = outcome === "success" && (!expect.returns || expect.returns.test(detail));
  else asExpected = outcome === "failure" && expect.reason.test(detail);
  results.push({ name, expected: expect.ok ? (expect.returns ? `success returning ${expect.returns}` : "success") : `failure: ${expect.reason}`, outcome, asExpected, detail, tx });
  log(`${asExpected ? "PASS" : "UNEXPECTED"}  ${name}: ${outcome}${tx ? "  " + tx : ""}${detail ? "  (" + detail.slice(0, 120) + ")" : ""}`);
}

const parent = as(parentId);
const wasm = (n) => readFileSync(resolve(import.meta.dirname, `../../spikes/gate2/target/wasm32-unknown-unknown/release/${n}.wasm`));

// 1. Sub-accounts (same full-access key as the parent; testnet only).
const funding = { token: 2.5, gate: 2, buyer: 0.5, merchant: 0.3, agent: 0.5 };
for (const [k, n] of Object.entries(funding)) {
  if (await exists(ACC[k])) { log(`exists   ${ACC[k]}`); continue; }
  await step(`create ${ACC[k]}`, { ok: true }, () => parent.createSubAccount({ accountOrPrefix: k, publicKey: signerPub, nearToTransfer: NEAR(n) }));
}

// 2. Deploy and initialise the mock token and the spike gate (initialise only once).
const token = as(ACC.token);
const gate = as(ACC.gate);
await step("deploy token", { ok: true }, () => token.deployContract(wasm("spike_token")));
await step("deploy gate", { ok: true }, () => gate.deployContract(wasm("spike_gate")));
const supply = await provider.callFunction({ contractId: ACC.token, method: "ft_total_supply", args: {} }).catch(() => null);
if (!supply) await step("init token (buyer owns supply)", { ok: true }, () => token.callFunctionRaw({ contractId: ACC.token, methodName: "new", args: { owner_id: ACC.buyer, total_supply: "1000000000" } }));
const agentOfGate = await provider.callFunction({ contractId: ACC.gate, method: "agent", args: {} }).catch(() => null);
if (!agentOfGate) await step("init gate", { ok: true }, () => gate.callFunctionRaw({ contractId: ACC.gate, methodName: "new", args: { token: ACC.token, agent: ACC.agent } }));
else log(`exists   gate initialised (agent ${agentOfGate})`);

// 3. Register storage and fund the gate with tokens (the gate now holds funds).
const buyer = as(ACC.buyer);
for (const a of [ACC.gate, ACC.merchant]) {
  await step(`storage_deposit ${a}`, { ok: true }, () => buyer.callFunctionRaw({ contractId: ACC.token, methodName: "storage_deposit", args: { account_id: a, registration_only: true }, deposit: NEAR(0.0125) }));
}
await step("buyer sends 10 tokens to the gate", { ok: true }, () => buyer.callFunctionRaw({ contractId: ACC.token, methodName: "ft_transfer", args: { receiver_id: ACC.gate, amount: "10000000" }, deposit: 1n }));

// 4. Fresh function-call key for the agent: receiver = gate, method = purchase, small allowance.
const fcKey = KeyPair.fromRandom("ed25519");
const fcPub = fcKey.getPublicKey().toString();
const agentFull = as(ACC.agent);
await step("add agent function-call key (gate.purchase only)", { ok: true }, () => agentFull.addFunctionCallAccessKey({ publicKey: fcPub, contractId: ACC.gate, methodNames: ["purchase"], allowance: NEAR(0.25) }));
const agent = as(ACC.agent, fcKey.toString());

try {
  const bal = async (a) => BigInt(await provider.callFunction({ contractId: ACC.token, method: "ft_balance_of", args: { account_id: a } }));
  const before = await bal(ACC.merchant);

  // 5. The tests.
  await step("A. agent key calls gate.purchase -> gate pays merchant 2.5 tokens", { ok: true }, () => agent.callFunctionRaw({ contractId: ACC.gate, methodName: "purchase", args: { payee: ACC.merchant, amount: "2500000" }, gas: 50n * 10n ** 12n }));
  await new Promise((r) => setTimeout(r, 3000));
  const after = await bal(ACC.merchant);
  const paid = after - before === 2500000n;
  results.push({ name: "A2. merchant balance increased by 2.5 tokens", expected: "success", outcome: paid ? "success" : "failure", asExpected: paid, detail: `${before} -> ${after}`, tx: "" });
  log(`${paid ? "PASS" : "UNEXPECTED"}  A2. merchant balance ${before} -> ${after}`);
  await step("B. agent key calls token.ft_transfer with 1 yocto (must fail)", { ok: false, reason: /Deposit is not allowed with function call|does not match transaction receiver/ }, () => agent.callFunctionRaw({ contractId: ACC.token, methodName: "ft_transfer", args: { receiver_id: ACC.agent, amount: "1" }, deposit: 1n }));
  await step("C. agent key calls token.ft_transfer without deposit (must fail)", { ok: false, reason: /does not match transaction receiver/ }, () => agent.callFunctionRaw({ contractId: ACC.token, methodName: "ft_transfer", args: { receiver_id: ACC.agent, amount: "1" } }));
  await step("D. agent key calls another gate method (must fail)", { ok: false, reason: /does not allow method/ }, () => agent.callFunctionRaw({ contractId: ACC.gate, methodName: "admin_note", args: {} }));
  await step("E. agent key attaches a deposit to gate.purchase (must fail)", { ok: false, reason: /Deposit is not allowed with function call/ }, () => agent.callFunctionRaw({ contractId: ACC.gate, methodName: "purchase", args: { payee: ACC.agent, amount: "1" }, deposit: 1n }));
  await step("F. agent key sends NEAR (must fail)", { ok: false, reason: /requires full access/ }, () => agent.transfer({ receiverId: parentId, amount: 1n }));
  await step("G. agent key adds a full-access key (must fail)", { ok: false, reason: /requires full access/ }, () => agent.addFullAccessKey(KeyPair.fromRandom("ed25519").getPublicKey().toString()));
  await step("H. buyer (not the agent) calls gate.purchase (gate must refuse)", { ok: true, returns: /only the agent/ }, () => buyer.callFunctionRaw({ contractId: ACC.gate, methodName: "purchase", args: { payee: ACC.buyer, amount: "1" } }));
} finally {
  // 6. Always delete the agent's function-call key, even if a step above threw (M1-09).
  await step("delete agent function-call key", { ok: true }, () => agentFull.deleteKey(fcPub));
}

const unexpected = results.filter((r) => !r.asExpected);
console.log("\nRESULTS_JSON " + redact(JSON.stringify(results)));
console.log(unexpected.length ? `\n${unexpected.length} unexpected outcome(s)` : "\nGate 2: all outcomes as expected");
process.exit(unexpected.length ? 1 : 0);
