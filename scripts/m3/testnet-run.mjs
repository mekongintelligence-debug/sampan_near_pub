#!/usr/bin/env node
// M3: deploy the gate contract to testnet and exercise it end to end. Testnet only.
// Evidence script for the contract as built in M3. Since audit A1 the gate needs register_mandate
// first; the redesigned gate is exercised by scripts/a1/testnet-run.mjs.
//   make wasm-release && node scripts/m3/testnet-run.mjs
//
// Uses NEAR_TESTNET_ACCOUNT_ID / NEAR_TESTNET_PRIVATE_KEY (in memory only). The buyer's
// mandate key is generated fresh per run and never leaves this process; the agent's
// function-call key (gate.purchase only) is created fresh and always deleted (finally).
// Reuses the M1 mock token (token.<parent>): the buyer holds its supply.
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { Account, JsonRpcProvider, KeyPair } from "near-api-js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { base58 } from "@scure/base";
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalize, nep413Hash, toBytes, verifySignedMandate, parseOrder } from "../../packages/mandate/src/index.ts";
import { parseReceiptCore, parseEnvelope } from "../../packages/receipt/src/index.ts";
import { assertTestnet, redact, testnetKeyFromEnv, installRedactingErrorHandlers } from "../m1/safety.mjs";

installRedactingErrorHandlers();
const RPC = "https://rpc.testnet.near.org";
const parentId = process.env.NEAR_TESTNET_ACCOUNT_ID;
const id = (p) => `${p}.${parentId}`;
const ACC = { gate: id("gate-m3"), token: id("token"), buyer: id("buyer"), merchant: id("merchant"), agent: id("agent"), shop: id("payee2-m3") };
assertTestnet({ networkId: "testnet", rpcUrl: RPC, accounts: [parentId, ...Object.values(ACC)] });

const key = testnetKeyFromEnv();
const provider = new JsonRpcProvider({ url: RPC });
const signerPub = KeyPair.fromString(key).getPublicKey().toString();
const as = (accountId, k = key) => new Account(accountId, provider, k);
// Exact: milli-NEAR as an integer (0.00125 NEAR is written as "1.25 milli" below, not rounded; run-1 bug).
const NEAR = (n) => { const [w, f = ""] = String(n).split("."); return BigInt(w + f.padEnd(24, "0").slice(0, 24)); };
const TGAS = (n) => BigInt(n) * 10n ** 12n;
const USDC = (n) => BigInt(Math.round(n * 1e6)); // mock token, 6 decimals
const link = (h) => `https://testnet.nearblocks.io/txns/${h}`;
const log = (...a) => console.log(redact(a.join(" ")));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];

const view = (contractId, method, args = {}) => provider.callFunction({ contractId, method, args });
async function exists(accountId) {
  try { await provider.viewAccount({ accountId }); return true; } catch { return false; }
}
const decodeReturn = (r) => {
  const v = r?.status?.SuccessValue;
  if (!v) return null;
  try {
    const x = JSON.parse(Buffer.from(v, "base64").toString("utf8"));
    // The gate returns its decision as a JSON string; ft_transfer_call returns the used amount.
    if (typeof x === "string" && x.startsWith("{")) return JSON.parse(x);
    return x;
  } catch { return null; }
};
const eventsOf = (r) => (r?.receipts_outcome ?? []).flatMap((o) => o.outcome.logs)
  .filter((l) => l.startsWith("EVENT_JSON:")).map((l) => JSON.parse(l.slice(11)));

/** Run a transaction; `check(ret, r)` returns true when the outcome is the expected one. */
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

// ---- documents ---------------------------------------------------------------------------
const buyerSk = ed25519.utils.randomSecretKey();
const buyerPk = ed25519.getPublicKey(buyerSk);
const hex32 = () => bytesToHex(randomBytes(32));

function signedMandate({ agent, payee, maxAmount, items, expiryNs, network = "testnet", gate = ACC.gate }) {
  const mandate = {
    v: "sampan.mandate.v1", network, gate,
    buyer: `near:ed25519:${base58.encode(buyerPk)}`, agent, asset: ACC.token,
    max_amount: String(maxAmount), payee, items, expiry_ns: String(expiryNs), nonce: hex32(), refund_to: ACC.buyer,
  };
  const message = canonicalize(mandate);
  const sig = ed25519.sign(nep413Hash(message, mandate.nonce, mandate.gate), buyerSk);
  const text = canonicalize({ v: "sampan.signed-mandate.v1", mandate, standard: "nep413", signature: bytesToHex(sig) });
  const verified = verifySignedMandate(toBytes(text)); // the checker accepts what the gate gets
  return { text, hash: verified.mandateHash, mandate, sig: bytesToHex(sig) };
}
function orderDoc(mandateHash, { item = "report-001", amount, payee = ACC.shop, asset = ACC.token, orderId = hex32() }) {
  const text = canonicalize({ v: "sampan.order.v1", order_id: orderId, mandate_hash: mandateHash, item, amount: String(amount), asset, payee });
  parseOrder(toBytes(text));
  return { text, orderId };
}

// ---- setup -------------------------------------------------------------------------------
const parent = as(parentId);
const funding = { gate: "3.7", shop: "0.05" };
for (const [k, n] of Object.entries(funding)) {
  if (await exists(ACC[k])) { log(`exists   ${ACC[k]}`); continue; }
  await step(`create ${ACC[k]}`, () => true, () => parent.createSubAccount({ accountOrPrefix: ACC[k].split(".")[0], publicKey: signerPub, nearToTransfer: NEAR(n) }));
}
const gate = as(ACC.gate);
const wasm = readFileSync(resolve(import.meta.dirname, "../../target/wasm32-unknown-unknown/release/sampan_gate.wasm"));
await step("deploy gate (M3 contract)", () => true, () => gate.deployContract(wasm));
// Expected config. The gate reserves worst-case storage per open mandate against its free
// balance (audit M3-05), so the caps are sized to the 3.7 NEAR account (about 0.5 free).
// 16 orders per mandate leave room for refused injections before valid orders (M4-01).
const CONFIG = {
  network: "testnet", token: ACC.token, min_funding: String(USDC(0.1)), max_escrow_per_mandate: String(USDC(20)),
  max_total_escrow: String(USDC(100)), max_mandates: 4, max_orders_per_mandate: 16,
  registration_deposit: String(NEAR("0.00125")),
};
let cfg = await view(ACC.gate, "get_config").catch(() => null);
if (!cfg) {
  await step("init gate (only the gate account may, audit M3-04)", () => true, () => gate.callFunctionRaw({ contractId: ACC.gate, methodName: "new", gas: TGAS(30), args: { config: CONFIG } }));
  cfg = await view(ACC.gate, "get_config").catch(() => null);
}
// Never carry on with a gate someone else initialised (audit M3-04).
const sorted = (o) => JSON.stringify(Object.keys(o ?? {}).sort().map((k) => [k, o[k]]));
if (sorted(cfg) !== sorted(CONFIG)) throw new Error("gate config differs from the expected config; stop");
log("config   matches the expected config");
if (process.argv.includes("--init-only")) process.exit(0); // M4: re-initialise after a reset, keep M3 evidence
const buyer = as(ACC.buyer);
const reg = await view(ACC.token, "storage_balance_of", { account_id: ACC.gate });
if (!reg) await step("register gate with the token", () => true, () => buyer.callFunctionRaw({ contractId: ACC.token, methodName: "storage_deposit", args: { account_id: ACC.gate, registration_only: true }, deposit: NEAR("0.0125") }));

const bal = async (a) => BigInt((await view(ACC.token, "ft_balance_of", { account_id: a })) ?? "0");
const fundTx = (signed, amount, order = null) => buyer.callFunctionRaw({
  contractId: ACC.token, methodName: "ft_transfer_call", deposit: 1n, gas: TGAS(250),
  args: { receiver_id: ACC.gate, amount: String(amount), msg: JSON.stringify({ signed_mandate: signed.text, order: order?.text ?? null }) },
});
const settle = () => sleep(4000);

/** The receipt event in a tx re-parses with the TypeScript checker code and matches the anchor. */
async function checkAnchor(r, order, decision, signed) {
  const ev = eventsOf(r).find((e) => e.event === "receipt" && e.data?.[0]?.order_id === order.orderId);
  if (!ev) return false;
  const { core, hash } = parseReceiptCore(toBytes(canonicalize(ev.data[0].core)));
  const stored = await view(ACC.gate, "get_receipt", { mandate_hash: signed.hash, order_id: order.orderId });
  // The full envelope (as the checker will get it) binds core, signed mandate and order.
  const envelope = {
    v: "sampan.receipt-envelope.v1", core: ev.data[0].core, core_hash: hash,
    signed_mandate: JSON.parse(signed.text), order: JSON.parse(order.text),
    tx: { deposit: null, decision: r.transaction.hash, payout: null }, untrusted: null,
  };
  parseEnvelope(toBytes(JSON.stringify(envelope)));
  return hash === ev.data[0].core_hash && stored?.core_hash === hash && core.decision === decision && stored.decision === decision;
}

// ---- agent key ---------------------------------------------------------------------------
const fcKey = KeyPair.fromRandom("ed25519");
const fcPub = fcKey.getPublicKey().toString();
const agentFull = as(ACC.agent);
await step("add agent function-call key (gate-m3.purchase only)", () => true, () => agentFull.addFunctionCallAccessKey({ publicKey: fcPub, contractId: ACC.gate, methodNames: ["purchase"], allowance: NEAR("0.5") }));
const agent = as(ACC.agent, fcKey.toString());
const purchase = (who, order) => who.callFunctionRaw({ contractId: ACC.gate, methodName: "purchase", args: { order: order.text }, gas: TGAS(150) });

try {
  const nowNs = BigInt(Date.now()) * 1_000_000n;
  const hour = 3_600_000_000_000n;

  // A. Agent mandate: fund, release, refusals.
  const A = signedMandate({ agent: ACC.agent, payee: ACC.shop, maxAmount: USDC(5), items: ["report-001", "report-002"], expiryNs: nowNs + hour });
  await step("A1. buyer funds mandate A with 5 tokens (ft_transfer_call)", async () => (await view(ACC.gate, "get_mandate", { mandate_hash: A.hash }))?.escrow === String(USDC(5)), () => fundTx(A, USDC(5)));
  const B = signedMandate({ agent: ACC.agent, payee: ACC.shop, maxAmount: USDC(5), items: ["report-001"], expiryNs: nowNs + hour });
  await step("A2. fake token: buyer calls ft_on_transfer directly (full amount handed back, nothing stored)",
    async (ret) => ret === String(USDC(5)) && (await view(ACC.gate, "get_mandate", { mandate_hash: B.hash })) === null,
    () => buyer.callFunctionRaw({ contractId: ACC.gate, methodName: "ft_on_transfer", gas: TGAS(100), args: { sender_id: ACC.buyer, amount: String(USDC(5)), msg: JSON.stringify({ signed_mandate: B.text, order: null }) } }));

  const shopBefore = await bal(ACC.shop);
  const o1 = orderDoc(A.hash, { amount: USDC(2) });
  const rel = await step("A3. agent key: purchase 2 tokens for report-001 (release)", (ret) => ret?.decision === "release" && ret.anchored === true, () => purchase(agent, o1));
  await settle();
  const shopAfter = await bal(ACC.shop);
  record("A4. shop received exactly 2 tokens (gate paid its token registration, Q17)", shopAfter - shopBefore === USDC(2), `${shopBefore} -> ${shopAfter}`);
  const rec1 = await view(ACC.gate, "get_receipt", { mandate_hash: A.hash, order_id: o1.orderId });
  record("A5. receipt payout status is done", rec1?.payout === "Done", JSON.stringify(rec1));
  record("A6. receipt event passes the TS checker (core and full envelope) and equals the stored anchor", rel.r ? await checkAnchor(rel.r, o1, "release", A) : false, o1.orderId);

  const o2 = orderDoc(A.hash, { amount: USDC(1), payee: ACC.merchant });
  const ref = await step("A7. agent: order paying a swapped payee (R8) is refused, anchored, no transfer", (ret) => ret?.decision === "refuse" && ret.anchored === true, () => purchase(agent, o2));
  record("A8. refusal receipt anchored and parses", ref.r ? await checkAnchor(ref.r, o2, "refuse", A) : false, o2.orderId);
  const o9 = orderDoc(A.hash, { amount: USDC(4) });
  const r7 = await step("A9. agent: 4 tokens with 3 left (R7) is refused", (ret) => ret?.decision === "refuse", () => purchase(agent, o9));
  record("A9b. R7 refusal observes the 3 tokens held and passes the TS envelope check (M3-X1)", r7.r ? await checkAnchor(r7.r, o9, "refuse", A) : false, o9.orderId);
  await step("A10. agent: item outside the mandate (R9) is refused", (ret) => ret?.decision === "refuse", () => purchase(agent, orderDoc(A.hash, { amount: USDC(1), item: "report-999" })));
  await step("A10b. agent: order in another asset (R6) is refused", (ret) => ret?.decision === "refuse" && ret.anchored === true, () => purchase(agent, orderDoc(A.hash, { amount: USDC(1), asset: "fake-usdc.testnet" })));
  await step("A11. agent: replay of order 1 is refused without state (R4)", (ret) => ret?.reason === "order_used", () => purchase(agent, o1));
  await step("A12. buyer (not the agent) calls purchase: refused without state (R5)", (ret) => ret?.reason === "not_authorised", () => purchase(buyer, orderDoc(A.hash, { amount: USDC(1) })));
  const mA = await view(ACC.gate, "get_mandate", { mandate_hash: A.hash });
  record("A13. mandate A: spent 2, escrow 3", mA?.spent === String(USDC(2)) && mA?.escrow === String(USDC(3)), JSON.stringify(mA));

  // F. Funding refusals: R1 (signature) and R2 (network, gate) fail before anything is stored.
  const good = signedMandate({ agent: ACC.agent, payee: ACC.shop, maxAmount: USDC(1), items: ["report-001"], expiryNs: nowNs + hour });
  const tampered = { text: good.text.replace(`"max_amount":"${USDC(1)}"`, `"max_amount":"${USDC(9)}"`), hash: good.hash };
  await step("F1. tampered mandate (R1): token returns everything (used 0)", async (ret) => ret === "0" && (await view(ACC.gate, "get_mandate", { mandate_hash: good.hash })) === null, () => fundTx(tampered, USDC(0.5)));
  const otherNet = signedMandate({ agent: ACC.agent, payee: ACC.shop, maxAmount: USDC(1), items: ["report-001"], expiryNs: nowNs + hour, network: "mainnet" });
  await step("F2. mandate for mainnet (R2): returned in full", async (ret) => ret === "0" && (await view(ACC.gate, "get_mandate", { mandate_hash: otherNet.hash })) === null, () => fundTx(otherNet, USDC(0.5)));
  const otherGate = signedMandate({ agent: ACC.agent, payee: ACC.shop, maxAmount: USDC(1), items: ["report-001"], expiryNs: nowNs + hour, gate: ACC.merchant });
  await step("F3. mandate for another gate (R2): returned in full", async (ret) => ret === "0" && (await view(ACC.gate, "get_mandate", { mandate_hash: otherGate.hash })) === null, () => fundTx(otherGate, USDC(0.5)));

  // C. Direct checkout: agent null, order delivered with the payment (the 1Click path).
  const C = signedMandate({ agent: null, payee: ACC.shop, maxAmount: USDC(1), items: ["report-002"], expiryNs: nowNs + hour });
  const oc = orderDoc(C.hash, { amount: USDC(1), item: "report-002" });
  const shopC = await bal(ACC.shop);
  const dc = await step("C1. direct checkout: payment carries the order; gate decides and pays in the same transaction", async (ret, r) => ret === String(USDC(1)) && (await checkAnchor(r, oc, "release", C)), () => fundTx(C, USDC(1), oc));
  await settle();
  record("C2. shop received 1 token", (await bal(ACC.shop)) - shopC === USDC(1), dc.ok ? "ok" : "");

  // D. Refund after expiry, triggered by a stranger, paid only to refund_to.
  const dNow = BigInt(Date.now()) * 1_000_000n; // computed here, not at the start of the run (run-1 bug)
  const D = signedMandate({ agent: ACC.agent, payee: ACC.shop, maxAmount: USDC(1), items: ["report-001"], expiryNs: dNow + 75_000_000_000n });
  await step("D1. fund mandate D (expires in 75 s) with 0.5 tokens", async () => (await view(ACC.gate, "get_mandate", { mandate_hash: D.hash }))?.escrow === String(USDC(0.5)), () => fundTx(D, USDC(0.5)));
  const merchant = as(ACC.merchant);
  await step("D2. refund before expiry is refused", (ret) => ret?.reason === "not_expired", () => merchant.callFunctionRaw({ contractId: ACC.gate, methodName: "refund", args: { mandate_hash: D.hash }, gas: TGAS(100) }));
  await sleep(90_000);
  const od = orderDoc(D.hash, { amount: USDC(0.1) });
  const r3 = await step("D2b. agent purchase after expiry (R3) is refused and anchored", (ret) => ret?.decision === "refuse" && ret.anchored === true, () => purchase(agent, od));
  record("D2c. R3 refusal receipt parses and equals the anchor", r3.r ? await checkAnchor(r3.r, od, "refuse", D) : false, od.orderId);
  const buyerBefore = await bal(ACC.buyer);
  await step("D3. after expiry a stranger (merchant) triggers the refund", (ret) => ret?.refund === "pending", () => merchant.callFunctionRaw({ contractId: ACC.gate, methodName: "refund", args: { mandate_hash: D.hash }, gas: TGAS(100) }));
  await settle();
  record("D4. buyer (refund_to) got 0.5 tokens back", (await bal(ACC.buyer)) - buyerBefore === USDC(0.5), "");
  await step("D5. after the refund settled the mandate is closed; a second refund finds nothing", async (ret) => ret?.reason === "unknown_mandate" && (await view(ACC.gate, "get_mandate", { mandate_hash: D.hash })) === null, () => merchant.callFunctionRaw({ contractId: ACC.gate, methodName: "refund", args: { mandate_hash: D.hash }, gas: TGAS(100) }));
  await step("D6. purchase on the closed mandate: refused without state", (ret) => ret?.reason === "unknown_mandate", () => purchase(agent, orderDoc(D.hash, { amount: USDC(0.1) })));

  const totals = await view(ACC.gate, "get_totals");
  record("Z. gate totals", true, JSON.stringify(totals));
} finally {
  await step("delete agent function-call key", () => true, () => agentFull.deleteKey(fcPub));
}

const bad = results.filter((r) => !r.ok);
const out = resolve(import.meta.dirname, "../../docs/m3-testnet-results.json");
writeFileSync(out, JSON.stringify({ date: new Date().toISOString(), gate: ACC.gate, results }, null, 2) + "\n");
console.log(bad.length ? `\n${bad.length} unexpected outcome(s)` : "\nM3 testnet: all outcomes as expected");
process.exit(bad.length ? 1 : 0);
