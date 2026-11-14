#!/usr/bin/env node
// M7 end to end on testnet: purchase -> receipt packed from chain data -> checker verifies it.
//   pnpm e2e          (needs NEAR_TESTNET_ACCOUNT_ID / NEAR_TESTNET_PRIVATE_KEY; testnet only)
//
// Flows, each producing a receipt that is packed only from transaction hashes
// (packages/receipt/src/pack.ts) and verified by the checker's own code (apps/checker):
//   1. direct checkout (agent null): the relayer registers, the payment carries
//      {"mandate_hash","order"} (the 1Click form), the gate releases and pays in one transaction;
//   2. agent release: the agent's function-call key buys within the mandate;
//   3. agent refusal: the agent tries to pay another payee; the refusal is anchored.
// Negative checks: the packer refuses a decision transaction for another order; the checker
// turns a receipt with a swapped decision transaction red; a mandate for mainnet cannot be
// registered on the testnet gate (cross-network replay).
// The test gate keeps its owner key (Q16), so "Nobody can change the gate" and the
// decision-block check are "Cannot verify" on testnet; every other check must pass.
// Writes examples/testnet/*.json (receipt envelopes) and docs/m7-e2e-results.json.
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { Account, JsonRpcProvider, KeyPair } from "near-api-js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { base58 } from "@scure/base";
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalize, nep413Hash, toBytes, verifySignedMandate } from "../../packages/mandate/src/index.ts";
import { packReceipt, PackError } from "../../packages/receipt/src/pack.ts";
import { verifyReceipt } from "../../apps/checker/src/verify.ts";
import { assertTestnet, redact, testnetKeyFromEnv, installRedactingErrorHandlers } from "../m1/safety.mjs";

installRedactingErrorHandlers();
const RPC = "https://rpc.testnet.near.org";
const parentId = process.env.NEAR_TESTNET_ACCOUNT_ID;
const id = (p) => `${p}.${parentId}`;
const ACC = { gate: id("gate-m3"), token: id("token"), buyer: id("buyer"), relayer: id("merchant"), agent: id("agent"), shop: id("payee2-m3"), other: id("merchant") };
assertTestnet({ networkId: "testnet", rpcUrl: RPC, accounts: [parentId, ...Object.values(ACC)] });
const key = testnetKeyFromEnv();
const provider = new JsonRpcProvider({ url: RPC });
const as = (a, k = key) => new Account(a, provider, k);
const TGAS = (n) => BigInt(n) * 10n ** 12n;
const USDC = (n) => BigInt(Math.round(n * 1e6));
const NEAR = (n) => { const [w, f = ""] = String(n).split("."); return BigInt(w + f.padEnd(24, "0").slice(0, 24)); };
const log = (...a) => console.log(redact(a.join(" ")));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const view = (method, args = {}) => provider.callFunction({ contractId: ACC.gate, method, args });
const results = [];
const record = (name, ok, detail = "") => { results.push({ name, ok, detail }); log(`${ok ? "PASS" : "UNEXPECTED"}  ${name}  ${detail}`.slice(0, 260)); };
const ret = (r) => { try { const x = JSON.parse(Buffer.from(r?.status?.SuccessValue ?? "", "base64").toString()); return typeof x === "string" && x.startsWith("{") ? JSON.parse(x) : x; } catch { return null; } };

// The checker's RPC access, and the packer's transaction fetch (final transactions only).
const fetchFn = (url, init) => fetch(url, init);
const fetchTx = async (hash, sender) => {
  const r = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: "e2e", method: "EXPERIMENTAL_tx_status", params: { tx_hash: hash, sender_account_id: sender, wait_until: "FINAL" } }) });
  return (await r.json()).result ?? null;
};
const EXPECTED_UNKNOWN = new Set(["locked", "then"]); // test gate keeps its owner key (Q16)
async function check(name, envText, wantDecision) {
  const res = await verifyReceipt(new TextEncoder().encode(envText), { rpcUrl: RPC, fetchFn });
  const bad = res.checks.filter((c) => c.status !== "pass" && !(c.status === "unknown" && EXPECTED_UNKNOWN.has(c.id)));
  record(`${name}: checker verifies (${res.facts?.decision ?? "?"})`, bad.length === 0 && res.facts?.decision === wantDecision, bad.map((c) => `${c.id}:${c.status}`).join(" ") || res.checks.map((c) => `${c.id}:${c.status}`).join(" "));
  return res;
}

// ---- documents ---------------------------------------------------------------------------
const buyerSk = ed25519.utils.randomSecretKey();
const hex32 = () => bytesToHex(randomBytes(32));
function signedMandate({ agent, maxAmount, items, network = "testnet" }) {
  const mandate = {
    v: "sampan.mandate.v1", network, gate: ACC.gate, buyer: `near:ed25519:${base58.encode(ed25519.getPublicKey(buyerSk))}`, agent, asset: ACC.token,
    max_amount: String(maxAmount), payee: ACC.shop, items, expiry_ns: String((BigInt(Date.now()) + 7_200_000n) * 1_000_000n), nonce: hex32(), refund_to: ACC.buyer,
  };
  const sig = ed25519.sign(nep413Hash(canonicalize(mandate), mandate.nonce, mandate.gate), buyerSk);
  const text = canonicalize({ v: "sampan.signed-mandate.v1", mandate, standard: "nep413", signature: bytesToHex(sig) });
  return { text, hash: verifySignedMandate(toBytes(text)).mandateHash };
}
const orderDoc = (mh, { item, amount, payee = ACC.shop }) => canonicalize({ v: "sampan.order.v1", order_id: hex32(), mandate_hash: mh, item, amount: String(amount), asset: ACC.token, payee });

// Mandates this script registered, so `--close` can close them after expiry (deposits return).
const STATE = resolve(import.meta.dirname, "../../docs/m7-e2e-state.json");
const opened = existsSync(STATE) ? JSON.parse(readFileSync(STATE, "utf8")).open : [];
const remember = (hash) => { opened.push(hash); writeFileSync(STATE, JSON.stringify({ note: "Mandates registered by scripts/m7/e2e.mjs; closed by --close after expiry.", open: opened }, null, 2) + "\n"); };
if (process.argv.includes("--close")) {
  const left = [];
  for (const h of opened) {
    const m = await view("get_mandate", { mandate_hash: h });
    if (!m) continue;
    if (BigInt(m.expiry_ns) > BigInt(Date.now()) * 1_000_000n) { left.push(h); continue; }
    const r = await as(ACC.buyer).callFunctionRaw({ contractId: ACC.gate, methodName: "refund", args: { mandate_hash: h }, gas: TGAS(100) });
    log(`closed ${h.slice(0, 12)}: ${JSON.stringify(ret(r))}`);
    if (await view("get_mandate", { mandate_hash: h })) left.push(h);
  }
  writeFileSync(STATE, JSON.stringify({ note: "Mandates registered by scripts/m7/e2e.mjs; closed by --close after expiry.", open: left }, null, 2) + "\n");
  log(`still open: ${left.length}; gate totals ${JSON.stringify(await view("get_totals"))}`);
  process.exit(0);
}
const cfg = await view("get_config");
const DEPOSIT = (2400n + BigInt(cfg.max_orders_per_mandate) * 450n) * 10n ** 19n + 2n * BigInt(cfg.registration_deposit);
const register = (who, signed) => who.callFunctionRaw({ contractId: ACC.gate, methodName: "register_mandate", args: { signed_mandate: signed.text }, deposit: DEPOSIT, gas: TGAS(30) });
const pay = (signed, amount, order = null) => as(ACC.buyer).callFunctionRaw({ contractId: ACC.token, methodName: "ft_transfer_call", deposit: 1n, gas: TGAS(250), args: { receiver_id: ACC.gate, amount: String(amount), msg: JSON.stringify({ mandate_hash: signed.hash, order }) } });

const fcKey = KeyPair.fromRandom("ed25519");
const fcPub = fcKey.getPublicKey().toString();
const agentFull = as(ACC.agent);
await agentFull.addFunctionCallAccessKey({ publicKey: fcPub, contractId: ACC.gate, methodNames: ["purchase"], allowance: NEAR("0.25") });
const agent = as(ACC.agent, fcKey.toString());
const purchase = (order) => agent.callFunctionRaw({ contractId: ACC.gate, methodName: "purchase", args: { order }, gas: TGAS(150) });

const examples = {};
try {
  // 1. Direct checkout.
  const C = signedMandate({ agent: null, maxAmount: USDC(1), items: ["report-002"] });
  const regC = await register(as(ACC.relayer), C);
  record("1. relayer registers the direct-checkout mandate", ret(regC)?.registered === true, `register tx ${regC.transaction.hash}`);
  remember(C.hash);
  const oc = orderDoc(C.hash, { item: "report-002", amount: USDC(1) });
  const payC = await pay(C, USDC(1), oc);
  record("1. payment with {mandate_hash, order} is used in full", ret(payC) === String(USDC(1)));
  await sleep(4000);
  const envC = await packReceipt({ gate: ACC.gate, token: ACC.token, decisionTx: payC.transaction.hash, mandateTx: regC.transaction.hash, depositTx: payC.transaction.hash }, fetchTx);
  record("1. receipt packed from chain data (release, paid in the same transaction)", envC.core.decision === "release" && envC.tx.payout === payC.transaction.hash);
  await check("1. direct checkout", envC.text, "release");
  examples["direct-checkout-release"] = envC.text;

  // 2 and 3. Agent mandate: one release, one refusal.
  const A = signedMandate({ agent: ACC.agent, maxAmount: USDC(3), items: ["report-001", "report-002"] });
  const regA = await register(as(ACC.buyer), A);
  remember(A.hash);
  const fundA = await pay(A, USDC(3));
  record("2. buyer registers and funds the agent mandate", ret(regA)?.registered === true && ret(fundA) === String(USDC(3)), `register tx ${regA.transaction.hash}, fund tx ${fundA.transaction.hash}`);
  const o1 = orderDoc(A.hash, { item: "report-001", amount: USDC(1) });
  const rel = await purchase(o1);
  record("2. agent buys report-001 within the mandate", ret(rel)?.decision === "release");
  await sleep(4000);
  const envR = await packReceipt({ gate: ACC.gate, token: ACC.token, decisionTx: rel.transaction.hash, mandateTx: regA.transaction.hash, depositTx: fundA.transaction.hash, note: "Bought report-001 as the buyer asked." }, fetchTx);
  await check("2. agent release", envR.text, "release");
  examples["agent-release"] = envR.text;

  const o2 = orderDoc(A.hash, { item: "report-002", amount: USDC(1), payee: ACC.other });
  const ref = await purchase(o2);
  record("3. agent order paying another payee is refused and anchored (R8)", ret(ref)?.decision === "refuse" && ret(ref)?.anchored === true);
  const envF = await packReceipt({ gate: ACC.gate, token: ACC.token, decisionTx: ref.transaction.hash, mandateTx: regA.transaction.hash, depositTx: fundA.transaction.hash }, fetchTx);
  await check("3. agent refusal", envF.text, "refuse");
  examples["agent-refusal"] = envF.text;

  // Negative checks.
  try {
    await packReceipt({ gate: ACC.gate, token: ACC.token, decisionTx: ref.transaction.hash, mandateTx: regC.transaction.hash }, fetchTx);
    record("N1. packer refuses a decision transaction with the wrong mandate", false);
  } catch (e) {
    record("N1. packer refuses a decision transaction with the wrong mandate", e instanceof PackError, e?.code ?? e?.message);
  }
  const swapped = JSON.parse(envR.text);
  swapped.tx.decision = ref.transaction.hash; // the refusal's transaction under the release's receipt
  const resS = await verifyReceipt(new TextEncoder().encode(JSON.stringify(swapped)), { rpcUrl: RPC, fetchFn });
  record("N2. checker: a receipt with another order's decision transaction is red", resS.overall === "invalid", resS.checks.filter((c) => c.status === "fail").map((c) => c.id).join(" "));
  const M = signedMandate({ agent: null, maxAmount: USDC(1), items: ["report-002"], network: "mainnet" });
  const regM = await as(ACC.relayer).callFunctionRaw({ contractId: ACC.gate, methodName: "register_mandate", args: { signed_mandate: M.text }, deposit: DEPOSIT, gas: TGAS(30) });
  record("N3. a mainnet mandate cannot be registered on the testnet gate (cross-network replay)", ret(regM)?.reason === "wrong_network");
} catch (e) {
  record("run completed", false, redact(String(e?.message ?? e)).slice(0, 200));
} finally {
  await agentFull.deleteKey(fcPub).catch(() => record("agent key deleted", false));
  // Always write what happened, also after an error (M7-CR4).
  writeFileSync(resolve(import.meta.dirname, "../../docs/m7-e2e-results.json"), JSON.stringify({ date: new Date().toISOString(), gate: ACC.gate, results }, null, 2) + "\n");
}

const out = resolve(import.meta.dirname, "../../examples/testnet");
mkdirSync(out, { recursive: true });
for (const [name, text] of Object.entries(examples)) writeFileSync(resolve(out, `${name}.json`), JSON.stringify(JSON.parse(text), null, 2) + "\n");
const bad = results.filter((r) => !r.ok);
console.log(bad.length ? `\n${bad.length} unexpected outcome(s)` : "\nM7 end to end: all outcomes as expected");
process.exit(bad.length ? 1 : 0);
