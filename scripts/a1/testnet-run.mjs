#!/usr/bin/env node
// A1: exercise the redesigned gate (audits A1-contract and A1-payments) on testnet. Testnet only.
//   make wasm-release && node scripts/m3/reset-testnet-gate.mjs && node scripts/a1/testnet-run.mjs
//   node scripts/a1/testnet-run.mjs --close     (an hour later: refund and close A and C)
//
// Uses NEAR_TESTNET_ACCOUNT_ID / NEAR_TESTNET_PRIVATE_KEY (in memory only). The buyer's
// mandate key is generated per run and never leaves this process (its public key and the
// mandate hashes are written to docs/a1-testnet-state.json for --close). The merchant
// account plays the Sampan relayer. The agent's function-call key (gate.purchase only) is
// created fresh and always deleted (finally).
import { readFileSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { Account, JsonRpcProvider, KeyPair } from "near-api-js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { base58 } from "@scure/base";
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalize, nep413Hash, toBytes, verifySignedMandate, parseOrder } from "../../packages/mandate/src/index.ts";
import { parseReceiptCore } from "../../packages/receipt/src/index.ts";
import { assertTestnet, redact, testnetKeyFromEnv, installRedactingErrorHandlers } from "../m1/safety.mjs";

installRedactingErrorHandlers();
const RPC = "https://rpc.testnet.near.org";
const parentId = process.env.NEAR_TESTNET_ACCOUNT_ID;
const id = (p) => `${p}.${parentId}`;
const ACC = { gate: id("gate-m3"), token: id("token"), buyer: id("buyer"), relayer: id("merchant"), agent: id("agent"), shop: id("payee2-m3") };
assertTestnet({ networkId: "testnet", rpcUrl: RPC, accounts: [parentId, ...Object.values(ACC)] });

const key = testnetKeyFromEnv();
const provider = new JsonRpcProvider({ url: RPC });
const as = (accountId, k = key) => new Account(accountId, provider, k);
const NEAR = (n) => { const [w, f = ""] = String(n).split("."); return BigInt(w + f.padEnd(24, "0").slice(0, 24)); };
const TGAS = (n) => BigInt(n) * 10n ** 12n;
const USDC = (n) => BigInt(Math.round(n * 1e6));
const link = (h) => `https://testnet.nearblocks.io/txns/${h}`;
const log = (...a) => console.log(redact(a.join(" ")));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
const OUT = resolve(import.meta.dirname, "../../docs/a1-testnet-results.json");
const STATE = resolve(import.meta.dirname, "../../docs/a1-testnet-state.json");

const view = (contractId, method, args = {}) => provider.callFunction({ contractId, method, args });
const nearOf = async (a) => BigInt((await provider.viewAccount({ accountId: a })).amount);
const tokOf = async (a) => BigInt((await view(ACC.token, "ft_balance_of", { account_id: a })) ?? "0");
const decodeReturn = (r) => {
  const v = r?.status?.SuccessValue;
  if (!v) return null;
  try {
    const x = JSON.parse(Buffer.from(v, "base64").toString("utf8"));
    if (typeof x === "string" && x.startsWith("{")) return JSON.parse(x);
    return x;
  } catch { return null; }
};
const eventsOf = (r) => (r?.receipts_outcome ?? []).flatMap((o) => o.outcome.logs)
  .filter((l) => l.startsWith("EVENT_JSON:")).map((l) => JSON.parse(l.slice(11)));

async function step(name, check, fn) {
  let ok = false, detail = "", tx = "", r = null, ret = null;
  try {
    r = await fn();
    tx = r?.transaction?.hash ? link(r.transaction.hash) : "";
    if (r?.status?.Failure) detail = redact(JSON.stringify(r.status.Failure)).slice(0, 300);
    else { ret = decodeReturn(r); detail = JSON.stringify(ret)?.slice(0, 240) ?? ""; ok = await check(ret, r); }
  } catch (e) {
    detail = redact(e?.message ?? e).slice(0, 300);
  }
  results.push({ name, ok, detail, tx });
  log(`${ok ? "PASS" : "UNEXPECTED"}  ${name}${tx ? "  " + tx : ""}  (${detail.slice(0, 160)})`);
  return { r, ret, ok };
}
function record(name, ok, detail) {
  results.push({ name, ok, detail, tx: "" });
  log(`${ok ? "PASS" : "UNEXPECTED"}  ${name}  (${detail})`);
}
function finish(label) {
  const bad = results.filter((r) => !r.ok);
  let prev = {};
  try { prev = JSON.parse(readFileSync(OUT, "utf8")); } catch { /* first run */ }
  prev[label] = { date: new Date().toISOString(), gate: ACC.gate, results };
  writeFileSync(OUT, JSON.stringify(prev, null, 2) + "\n");
  console.log(bad.length ? `\n${bad.length} unexpected outcome(s)` : `\nA1 testnet (${label}): all outcomes as expected`);
  process.exit(bad.length ? 1 : 0);
}

const buyer = as(ACC.buyer);
const relayer = as(ACC.relayer);
const refund = (who, mh, gas = 100) => who.callFunctionRaw({ contractId: ACC.gate, methodName: "refund", args: { mandate_hash: mh }, gas: TGAS(gas) });
const settle = () => sleep(5000);

// ---- --close: an hour later, refund and close the mandates left open -------------------
if (process.argv.includes("--close")) {
  const st = JSON.parse(readFileSync(STATE, "utf8"));
  for (const [name, mh, registrant] of st.open) {
    const before = await nearOf(registrant);
    const tb = await tokOf(ACC.buyer);
    const m = await view(ACC.gate, "get_mandate", { mandate_hash: mh });
    await step(`X. ${name}: a stranger refunds after expiry`, (ret) => ret?.refund === "pending" || ret?.refund === "closed" || ret?.reason === "unknown_mandate", () => refund(as(ACC.agent), mh));
    await settle();
    const back = (await tokOf(ACC.buyer)) - tb;
    record(`X. ${name}: refund_to got escrow plus refund due`, back === BigInt(m?.escrow ?? 0) + BigInt(m?.refund_due ?? 0), `${back}`);
    record(`X. ${name}: closed`, (await view(ACC.gate, "get_mandate", { mandate_hash: mh })) === null, "");
    const got = (await nearOf(registrant)) - before;
    record(`X. ${name}: registrant got part of its deposit back`, got > 0n, `${got} yoctoNEAR`);
  }
  record("X. gate totals", true, JSON.stringify(await view(ACC.gate, "get_totals")));
  finish("close");
}

// ---- documents ---------------------------------------------------------------------------
const buyerSk = ed25519.utils.randomSecretKey();
const buyerPk = ed25519.getPublicKey(buyerSk);
const hex32 = () => bytesToHex(randomBytes(32));
function signedMandate({ agent, payee = ACC.shop, maxAmount, items = ["report-001"], expiryNs, network = "testnet", gate = ACC.gate }) {
  const mandate = {
    v: "sampan.mandate.v1", network, gate, buyer: `near:ed25519:${base58.encode(buyerPk)}`, agent, asset: ACC.token,
    max_amount: String(maxAmount), payee, items, expiry_ns: String(expiryNs), nonce: hex32(), refund_to: ACC.buyer,
  };
  const message = canonicalize(mandate);
  const sig = ed25519.sign(nep413Hash(message, mandate.nonce, mandate.gate), buyerSk);
  const text = canonicalize({ v: "sampan.signed-mandate.v1", mandate, standard: "nep413", signature: bytesToHex(sig) });
  return { text, hash: verifySignedMandate(toBytes(text)).mandateHash, mandate };
}
function orderDoc(mandateHash, { item = "report-001", amount, payee = ACC.shop, orderId = hex32() }) {
  const text = canonicalize({ v: "sampan.order.v1", order_id: orderId, mandate_hash: mandateHash, item, amount: String(amount), asset: ACC.token, payee });
  parseOrder(toBytes(text));
  return { text, orderId };
}

// ---- gate: code, config ------------------------------------------------------------------
const wasm = readFileSync(resolve(import.meta.dirname, "../../target/wasm32-unknown-unknown/release/sampan_gate.wasm"));
const localHash = base58.encode(createHash("sha256").update(wasm).digest());
const chainHash = (await provider.viewAccount({ accountId: ACC.gate })).code_hash;
if (chainHash !== localHash) throw new Error(`gate code ${chainHash} is not the local build ${localHash}; run the reset script first`);
log(`code     ${chainHash} (matches the local release build)`);
const HOUR = 3_600_000_000_000n;
const CONFIG = {
  network: "testnet", token: ACC.token, min_funding: String(USDC(0.1)), max_escrow_per_mandate: String(USDC(20)),
  max_total_escrow: String(USDC(100)), max_mandates: 4, max_orders_per_mandate: 16,
  registration_deposit: String(NEAR("0.00125")), max_lifetime_ns: String(24n * HOUR),
  // Testnet only: the parent account is the guardian. On mainnet it is a named person's
  // hardware wallet, never the deploy key (docs/audits/A1-contract.md, A1C-03).
  guardian: parentId,
};
const gate = as(ACC.gate);
let cfg = await view(ACC.gate, "get_config").catch(() => null);
if (!cfg) {
  await step("init gate (private: only the gate account may)", () => true, () => gate.callFunctionRaw({ contractId: ACC.gate, methodName: "new", gas: TGAS(30), args: { config: { ...CONFIG, max_lifetime_ns: Number(24n * HOUR) } } }));
  cfg = await view(ACC.gate, "get_config").catch(() => null);
}
const norm = (o) => JSON.stringify(Object.keys(o ?? {}).sort().map((k) => [k, String(o[k])]));
if (norm(cfg) !== norm(CONFIG)) throw new Error(`gate config differs from the expected config; stop: ${JSON.stringify(cfg)}`);
log("config   matches the expected config");
const reg = await view(ACC.token, "storage_balance_of", { account_id: ACC.gate });
if (!reg) await step("register gate with the token", () => true, () => buyer.callFunctionRaw({ contractId: ACC.token, methodName: "storage_deposit", args: { account_id: ACC.gate, registration_only: true }, deposit: NEAR("0.0125") }));

// The deposit the gate asks of a registrant: (2,400 + orders x 450) bytes + two registrations.
const byteCost = 10n ** 19n;
const DEPOSIT = (2400n + 16n * 450n) * byteCost + 2n * NEAR("0.00125");
const register = (who, signed, deposit = DEPOSIT) => who.callFunctionRaw({ contractId: ACC.gate, methodName: "register_mandate", args: { signed_mandate: signed.text }, deposit, gas: TGAS(30) });
const pay = (signed, amount, { order = null, byHash = true } = {}) => buyer.callFunctionRaw({
  contractId: ACC.token, methodName: "ft_transfer_call", deposit: 1n, gas: TGAS(250),
  args: { receiver_id: ACC.gate, amount: String(amount), msg: JSON.stringify(byHash ? { mandate_hash: signed.hash, order: order?.text ?? null } : { signed_mandate: signed.text, order: order?.text ?? null }) },
});
const mandate = (mh) => view(ACC.gate, "get_mandate", { mandate_hash: mh });

// ---- agent key ---------------------------------------------------------------------------
const fcKey = KeyPair.fromRandom("ed25519");
const fcPub = fcKey.getPublicKey().toString();
const agentFull = as(ACC.agent);
await step("add agent function-call key (gate.purchase only)", () => true, () => agentFull.addFunctionCallAccessKey({ publicKey: fcPub, contractId: ACC.gate, methodNames: ["purchase"], allowance: NEAR("0.25") }));
const agent = as(ACC.agent, fcKey.toString());
const purchase = (order, gas = 150) => agent.callFunctionRaw({ contractId: ACC.gate, methodName: "purchase", args: { order: order.text }, gas: TGAS(gas) });

/** A1C-07: the smallest prepaid gas the gate accepts, found by stepping up 1 Tgas at a time.
 * Every attempt below it is refused with `insufficient_gas` before any state is written. */
async function atMinimumGas(name, call, from, to) {
  for (let g = from; g <= to; g++) {
    let r;
    try { r = await call(g); } catch (e) { log(`  ${g} Tgas: ${redact(e?.message ?? e).slice(0, 80)}`); continue; }
    const ret = decodeReturn(r);
    if (ret?.reason === "insufficient_gas") continue;
    log(`  ${name}: accepted at ${g} Tgas`);
    return { r, ret, gas: g };
  }
  return { r: null, ret: null, gas: null };
}

const open = [];
try {
  const now = () => BigInt(Date.now()) * 1_000_000n;

  // R. Registration: refusals return the whole deposit and store nothing.
  const relayerBefore = await nearOf(ACC.relayer);
  const tooLong = signedMandate({ agent: ACC.agent, maxAmount: USDC(1), expiryNs: now() + 25n * HOUR });
  await step("R1. lifetime over 24 hours: refused (lifetime_too_long), nothing stored", async (ret) => ret?.reason === "lifetime_too_long" && (await mandate(tooLong.hash)) === null, () => register(relayer, tooLong));
  const mainnet = signedMandate({ agent: ACC.agent, maxAmount: USDC(1), expiryNs: now() + HOUR, network: "mainnet" });
  await step("R2. mandate for mainnet (R2): refused (wrong_network)", (ret) => ret?.reason === "wrong_network", () => register(relayer, mainnet));
  const good = signedMandate({ agent: ACC.agent, maxAmount: USDC(1), expiryNs: now() + HOUR });
  const tampered = { text: good.text.replace(`"max_amount":"${USDC(1)}"`, `"max_amount":"${USDC(9)}"`), hash: good.hash };
  await step("R3. tampered mandate (R1): refused (bad_signature or invalid)", async (ret) => ret?.registered === false && (await mandate(good.hash)) === null, () => register(relayer, tampered));
  await step("R4. deposit below the reservation: refused (deposit_too_small)", (ret) => ret?.reason === "deposit_too_small", () => register(relayer, good, NEAR("0.01")));
  await settle();
  const lost = relayerBefore - (await nearOf(ACC.relayer));
  record("R5. refused registrations returned their deposits (relayer paid gas only)", lost < NEAR("0.01"), `${lost} yoctoNEAR spent on 4 refused calls`);
  await step("R6. not the guardian: stop() is refused (not_guardian)", (ret) => ret?.reason === "not_guardian", () => relayer.callFunctionRaw({ contractId: ACC.gate, methodName: "stop", args: {}, gas: TGAS(10) }));

  // A. Agent mandate registered by the relayer, paid by hash, released at minimum gas.
  const A = signedMandate({ agent: ACC.agent, maxAmount: USDC(5), items: ["report-001", "report-002"], expiryNs: now() + HOUR });
  await step("A1. relayer registers mandate A with the deposit (surplus returned)", async (ret) => ret?.registered === true && (await mandate(A.hash))?.funded === "0", () => register(relayer, A, DEPOSIT + NEAR("0.01")));
  open.push(["A", A.hash, ACC.relayer]);
  await step("A2. buyer pays 5 tokens naming A by hash (the 1Click form)", async () => (await mandate(A.hash))?.escrow === String(USDC(5)), () => pay(A, USDC(5)));
  await step("A3. a payment naming an unknown mandate is handed back in full (used 0)", (ret) => ret === "0", () => pay({ hash: "ab".repeat(32) }, USDC(0.5)));
  const shop0 = await tokOf(ACC.shop);
  const o1 = orderDoc(A.hash, { amount: USDC(2) });
  const minRel = await atMinimumGas("release", (g) => purchase(o1, g), 80, 160);
  record("A4. A1C-07: release accepted at the minimum gas", minRel.ret?.decision === "release" && minRel.ret.anchored === true, `${minRel.gas} Tgas ${minRel.r ? link(minRel.r.transaction.hash) : ""}`);
  await settle();
  const rec1 = await view(ACC.gate, "get_receipt", { mandate_hash: A.hash, order_id: o1.orderId });
  record("A5. A1C-07: the callback ran at minimum gas: payout Done, shop paid 2, nothing pending", rec1?.payout === "Done" && (await tokOf(ACC.shop)) - shop0 === USDC(2), JSON.stringify(rec1));
  const ev = minRel.r ? eventsOf(minRel.r).find((e) => e.event === "receipt") : null;
  record("A6. receipt event re-parses with the TS checker code and equals the anchor", ev ? parseReceiptCore(toBytes(canonicalize(ev.data[0].core))).hash === rec1?.core_hash : false, o1.orderId);

  // F. A1C-07, failure path at minimum gas: a payee the token cannot pay (the gate itself:
  // NEP-141 refuses a transfer to the sender), so the payout fails and the budget is restored.
  const F = signedMandate({ agent: ACC.agent, payee: ACC.gate, maxAmount: USDC(1), expiryNs: now() + 6n * 60_000_000_000n });
  await step("F1. buyer registers mandate F itself (payee: the gate)", (ret) => ret?.registered === true, () => register(buyer, F));
  await step("F2. buyer pays 0.5 tokens with the signed mandate in the message", async () => (await mandate(F.hash))?.escrow === String(USDC(0.5)), () => pay(F, USDC(0.5), { byHash: false }));
  const of = orderDoc(F.hash, { amount: USDC(0.2), payee: ACC.gate });
  const minFail = await atMinimumGas("failing release", (g) => purchase(of, g), 80, 160);
  record("F3. A1C-07: release with a failing payout accepted at the minimum gas", minFail.ret?.decision === "release", `${minFail.gas} Tgas ${minFail.r ? link(minFail.r.transaction.hash) : ""}`);
  await settle();
  const recF = await view(ACC.gate, "get_receipt", { mandate_hash: F.hash, order_id: of.orderId });
  const mF = await mandate(F.hash);
  record("F4. A1C-07: callback at minimum gas marked the payout Failed and restored the budget", recF?.payout === "Failed" && mF?.escrow === String(USDC(0.5)) && mF?.spent === "0", `${JSON.stringify(recF)} ${JSON.stringify(mF)}`);

  // C. Direct checkout (agent null) through the short 1Click message: exact price, refund due.
  const C = signedMandate({ agent: null, maxAmount: USDC(1), items: ["report-002"], expiryNs: now() + HOUR });
  await step("C1. relayer registers the agentless mandate C", (ret) => ret?.registered === true, () => register(relayer, C));
  open.push(["C", C.hash, ACC.relayer]);
  const msgLen = JSON.stringify({ mandate_hash: C.hash, order: orderDoc(C.hash, { amount: USDC(1), item: "report-002" }).text }).length;
  record("C2. the payment message fits 1Click's 1,024-character limit (A1P-01)", msgLen <= 1024, `${msgLen} characters`);
  const partial = orderDoc(C.hash, { amount: USDC(0.5), item: "report-002" });
  await step("C3. an order below the exact price is not decided; the payment becomes refund due", async (ret) => ret === String(USDC(0.5)) && (await mandate(C.hash))?.refund_due === String(USDC(0.5)), () => pay(C, USDC(0.5), { order: partial }));
  const oc = orderDoc(C.hash, { amount: USDC(1), item: "report-002" });
  const shopC = await tokOf(ACC.shop);
  await step("C4. over-delivery of 1.2 for the exact price 1: released, 0.2 more refund due", async (ret) => ret === String(USDC(1.2)) && (await mandate(C.hash))?.refund_due === String(USDC(0.7)), () => pay(C, USDC(1.2), { order: oc }));
  await settle();
  record("C5. shop received exactly 1 token", (await tokOf(ACC.shop)) - shopC === USDC(1), "");
  await step("C6. a second exact-price order in a later payment is not paid (already_paid)", async () => (await mandate(C.hash))?.spent === String(USDC(1)), () => pay(C, USDC(1), { order: orderDoc(C.hash, { amount: USDC(1), item: "report-002" }) }));
  const tb = await tokOf(ACC.buyer);
  await step("C7. before expiry anyone may refund the refund due to refund_to", (ret) => ret?.refund === "pending" && ret.amount === String(USDC(1.7)), () => refund(agentFull, C.hash));
  await settle();
  record("C8. buyer got 1.7 tokens back, never 1Click's account (A1P-02)", (await tokOf(ACC.buyer)) - tb === USDC(1.7), "");

  // F (continued). After expiry: a refund at minimum gas pays refund_to and closes F.
  const wait = Number(BigInt(F.mandate.expiry_ns) / 1_000_000n) - Date.now() + 10_000;
  if (wait > 0) await sleep(wait);
  const buyerNear = await nearOf(ACC.buyer);
  const tb2 = await tokOf(ACC.buyer);
  const minRef = await atMinimumGas("refund", (g) => refund(agentFull, F.hash, g), 70, 160);
  record("F5. A1C-07: refund accepted at the minimum gas", minRef.ret?.refund === "pending", `${minRef.gas} Tgas ${minRef.r ? link(minRef.r.transaction.hash) : ""}`);
  await settle();
  record("F6. buyer got the 0.5 tokens back", (await tokOf(ACC.buyer)) - tb2 === USDC(0.5), "");
  record("F7. the callback at minimum gas closed F", (await mandate(F.hash)) === null, "");
  const back = (await nearOf(ACC.buyer)) - buyerNear;
  record("F8. the registrant (buyer) got its deposit back, less what F leaves behind", back > 0n && back < DEPOSIT, `${back} of ${DEPOSIT} yoctoNEAR`);

  record("Z. gate totals", true, JSON.stringify(await view(ACC.gate, "get_totals")));
} finally {
  await step("delete agent function-call key", () => true, () => agentFull.deleteKey(fcPub));
  writeFileSync(STATE, JSON.stringify({ note: "Mandates left open by scripts/a1/testnet-run.mjs; close with --close after expiry.", open }, null, 2) + "\n");
}
finish("run");
