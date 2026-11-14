#!/usr/bin/env node
// The mainnet refusal example (runbook step 8). FOR A PERSON TO RUN, after the gate is locked.
// An AI agent's function-call key (receiver = the gate, method `purchase` only) tries to pay
// someone other than the signed payee; the gate refuses and anchors the refusal. No money moves
// to anyone but the gate; the 1 USDC funding is refunded to the buyer's NEAR account after expiry.
//
//   node scripts/mainnet-proof/agent-refusal.mjs prepare --buyer 0x<EIP-55> --agent agent.<team>.near --payee <shop>.near
//       prints the mandate text for the buyer to sign (personal_sign)
//   node scripts/mainnet-proof/agent-refusal.mjs register --signature 0x<sig> --registrant relayer.<team>.near
//   node scripts/mainnet-proof/agent-refusal.mjs fund --funder <account>.near        (sends 1 USDC to the gate for this mandate)
//   node scripts/mainnet-proof/agent-refusal.mjs refuse --other <account>.near       (the agent's order pays <other>: refused)
//   node scripts/mainnet-proof/agent-refusal.mjs refund --caller <account>.near      (after expiry: 1 USDC back to the buyer)
//
// Keys are typed at hidden prompts, one per step, and never stored. The agent's key must be a
// function-call key for the gate's `purchase` (add it in your wallet; allowance 0.25 NEAR) and
// is deleted by you afterwards. Everything is written to examples/mainnet-proof/refusal-*.json.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { args, stop, ask, requirePerson } from "../mainnet/cli.mjs";
import { canonicalize, toBytes, verifySignedMandate } from "../../packages/mandate/src/index.ts";
import { USDC, MAINNET_RPC, reservationPerMandate } from "../mainnet/deploy-gate.mjs";
import { buildProofMandate, signedFromSignature, checkGateReady, printable } from "./proof.mjs";

const OUT = resolve(import.meta.dirname, "../../examples/mainnet-proof");
const ACCOUNT = /^(?=.{2,64}$)([a-z\d]+[-_])*[a-z\d]+(\.([a-z\d]+[-_])*[a-z\d]+)*\.near$/;
export const FUND_UNITS = "1000000"; // 1 USDC: the agent's budget, refunded after expiry

/** The order the agent is tricked into: a listed item and amount, but another payee (rule R8). */
export function swappedPayeeOrder(verified, other) {
  const m = verified.mandate;
  if (!ACCOUNT.test(other ?? "") || other === m.payee || other === m.gate) throw new Error("--other must be a named .near account that is neither the payee nor the gate");
  return canonicalize({ v: "sampan.order.v1", order_id: randomBytes(32).toString("hex"), mandate_hash: verified.mandateHash, item: m.items[0], amount: "500000", asset: m.asset, payee: other });
}

/** The gate's answer must be an anchored refusal where R8 (payee) is the ONLY failed rule, so the
 * example shows exactly the swapped payee, not an unfunded or expired mandate (audit M8-08). */
export function isAnchoredPayeeRefusal(ret, receiptEvent) {
  const failed = (receiptEvent?.core?.rules ?? []).filter((r) => r.pass === false).map((r) => r.id);
  return ret?.decision === "refuse" && ret?.anchored === true && failed.length === 1 && failed[0] === "R8";
}

/** The agent's key must be a function-call key for the gate's `purchase` only, with no other
 * method and a small allowance (M8-08). `permission` is view_access_key's permission field. */
export function isPurchaseOnlyKey(permission, gate) {
  const fc = permission?.FunctionCall;
  return !!fc && fc.receiver_id === gate && Array.isArray(fc.method_names) && fc.method_names.length === 1 && fc.method_names[0] === "purchase";
}

const save = (name, v) => { mkdirSync(OUT, { recursive: true }); writeFileSync(resolve(OUT, name), JSON.stringify(v, null, 2) + "\n"); };
const load = (name) => JSON.parse(readFileSync(resolve(OUT, name), "utf8"));
const decode = (r) => { try { const x = JSON.parse(Buffer.from(r?.status?.SuccessValue ?? "", "base64").toString()); return typeof x === "string" && x.startsWith("{") ? JSON.parse(x) : x; } catch { return null; } };

async function main() {
  const a = args(process.argv.slice(2));
  if (!["prepare", "register", "fund", "refuse", "refund"].includes(a.cmd)) stop(["usage: prepare | register | fund | refuse | refund (see the file header)"]);
  requirePerson();
  const { Account, JsonRpcProvider, KeyPair } = await import("near-api-js");
  const provider = new JsonRpcProvider({ url: MAINNET_RPC });
  if ((await provider.viewNodeStatus()).chain_id !== "mainnet") stop(["RPC is not mainnet"]);
  const gateRecord = JSON.parse(readFileSync(resolve(import.meta.dirname, "../../examples/mainnet-gate.json"), "utf8"));
  const gate = gateRecord.gate;
  const view = (c, m, x = {}) => provider.callFunction({ contractId: c, method: m, args: x , blockQuery: { finality: "final" } });
  stop(checkGateReady({
    gateRecord, account: await provider.viewAccount({ accountId: gate, blockQuery: { finality: "final" } }),
    keys: (await provider.viewAccessKeyList({ accountId: gate, finalityQuery: { finality: "final" } })).keys,
    config: await view(gate, "get_config"), usdcStorage: await view(USDC, "storage_balance_of", { account_id: gate }), totals: await view(gate, "get_totals"),
  }));
  const exists = (acc) => provider.viewAccount({ accountId: acc, blockQuery: { finality: "final" } }).then(() => true, () => false);
  const signer = async (acc, what) => new Account(acc, provider, KeyPair.fromString(await ask(`${what} secret key of ${acc} (input hidden): `, { hidden: true })).toString());

  if (a.cmd === "prepare") {
    for (const acc of [a.agent, a.payee, String(a.buyer ?? "").toLowerCase()]) if (!(await exists(acc))) stop([`${acc} does not exist on mainnet`]);
    const r = buildProofMandate({ gate, buyer: a.buyer, payee: a.payee, item: "report-001", items: ["report-001", "report-002"], price: "1", nowMs: Date.now(), nonce: randomBytes(32).toString("hex"), agent: a.agent });
    stop(r.problems);
    save("refusal-mandate.json", { mandate: r.mandate, mandate_hash: r.mandateHash });
    console.log(`Agent mandate ${r.mandateHash}: ${a.agent} may buy report-001 or report-002 from ${a.payee}, up to 1 USDC.\n\nSign EXACTLY this text with the buyer's wallet (personal_sign):\n`);
    console.log(r.message);
    return;
  }
  const prepared = load("refusal-mandate.json");
  if (a.cmd === "register") {
    const { text, verified } = signedFromSignature(prepared.mandate, a.signature);
    if (!ACCOUNT.test(a.registrant ?? "")) stop(["--registrant must be a named .near account"]);
    const cfg = await view(gate, "get_config");
    const acc = await signer(a.registrant, "Registrant's");
    const r = await acc.callFunctionRaw({ contractId: gate, methodName: "register_mandate", args: { signed_mandate: text }, deposit: reservationPerMandate(cfg.max_orders_per_mandate, cfg.registration_deposit), gas: 30n * 10n ** 12n });
    if (decode(r)?.registered !== true) stop([`the gate refused the registration (${printable(decode(r)?.reason, 40)})`]);
    save("refusal-mandate.json", { ...prepared, signed_mandate: text, register_tx: r.transaction.hash });
    console.log(`Registered ${verified.mandateHash}: https://nearblocks.io/txns/${r.transaction.hash}`);
    return;
  }
  if (!prepared.signed_mandate) stop(["register the signed mandate first"]);
  const verified = verifySignedMandate(toBytes(prepared.signed_mandate));
  if (a.cmd === "fund") {
    if (!ACCOUNT.test(a.funder ?? "")) stop(["--funder must be a named .near account holding at least 1 USDC"]);
    // Fund once (M8-08): a re-run must not send a second 1 USDC.
    const before = await view(gate, "get_mandate", { mandate_hash: verified.mandateHash });
    if (!before) stop(["the mandate is not registered (or already closed)"]);
    if (prepared.fund_tx || before.funded !== "0") stop(["this mandate is already funded; nothing sent"]);
    if ((await ask(`Type "fund 1 USDC" to send 1 USDC from ${a.funder} to ${gate} for mandate ${verified.mandateHash.slice(0, 12)}: `)) !== "fund 1 USDC") stop(["not confirmed"]);
    const acc = await signer(a.funder, "Funder's");
    const r = await acc.callFunctionRaw({ contractId: USDC, methodName: "ft_transfer_call", deposit: 1n, gas: 100n * 10n ** 12n, args: { receiver_id: gate, amount: FUND_UNITS, msg: JSON.stringify({ mandate_hash: verified.mandateHash, order: null }) } });
    const m = await view(gate, "get_mandate", { mandate_hash: verified.mandateHash });
    if (m?.escrow !== FUND_UNITS) stop([`the mandate is not funded as expected (escrow ${printable(m?.escrow, 20)})`]);
    save("refusal-mandate.json", { ...prepared, fund_tx: r.transaction.hash });
    console.log(`Funded: https://nearblocks.io/txns/${r.transaction.hash}`);
    return;
  }
  if (a.cmd === "refund") {
    // After expiry anyone may refund: the escrow goes to the buyer's refund account, and the
    // mandate closes, returning the registrant's deposit (M8-08).
    const m = await view(gate, "get_mandate", { mandate_hash: verified.mandateHash });
    if (!m) { console.log("The mandate is already closed; nothing to refund."); return; }
    if (BigInt(m.expiry_ns) > BigInt(Date.now()) * 1_000_000n && m.refund_due === "0") stop([`not expired yet: try after ${new Date(Number(BigInt(m.expiry_ns) / 1_000_000n)).toISOString()}`]);
    if (!ACCOUNT.test(a.caller ?? "")) stop(["--caller must be any named .near account that pays the gas"]);
    const acc = await signer(a.caller, "Caller's");
    const r = await acc.callFunctionRaw({ contractId: gate, methodName: "refund", args: { mandate_hash: verified.mandateHash }, gas: 100n * 10n ** 12n });
    save("refusal-mandate.json", { ...prepared, refund_tx: r.transaction.hash });
    console.log(`Refund ${printable(JSON.stringify(decode(r)), 80)}: https://nearblocks.io/txns/${r.transaction.hash}`);
    return;
  }
  // refuse
  const order = swappedPayeeOrder(verified, a.other);
  const agent = verified.mandate.agent;
  if (!prepared.fund_tx) stop(["fund the mandate first, so the refusal is about the payee only"]);
  console.log(`The agent ${agent} now tries to pay ${a.other} instead of ${verified.mandate.payee}.`);
  const acc = await signer(agent, "Agent's function-call (gate.purchase only)");
  const pub = (await acc.getSigner().getPublicKey()).toString();
  const ak = await provider.viewAccessKey({ accountId: agent, publicKey: pub, finalityQuery: { finality: "final" } }).catch(() => null);
  if (!isPurchaseOnlyKey(ak?.permission, gate)) stop(["that key is not a function-call key for the gate's purchase only; add one in your wallet (receiver = the gate, method purchase)"]);
  const r = await acc.callFunctionRaw({ contractId: gate, methodName: "purchase", args: { order }, gas: 150n * 10n ** 12n });
  const ret = decode(r);
  const ev = (r.receipts_outcome ?? []).flatMap((o) => o.outcome.logs).filter((l) => l.startsWith("EVENT_JSON:")).map((l) => JSON.parse(l.slice(11))).find((e) => e.event === "receipt")?.data?.[0];
  if (!isAnchoredPayeeRefusal(ret, ev)) stop([`expected an anchored refusal naming R8, got ${printable(JSON.stringify(ret), 120)}`]);
  save("refusal-mandate.json", { ...prepared, order, refuse_tx: r.transaction.hash });
  console.log(`Refused and anchored (R8): https://nearblocks.io/txns/${r.transaction.hash}\nNow delete the agent's function-call key in your wallet. The 1 USDC goes back to ${verified.mandate.refund_to} after expiry (anyone can call refund).`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((e) => { console.error("error: " + String(e?.message ?? e).replace(/[1-9A-HJ-NP-Za-km-z]{80,}/g, "[redacted]").slice(0, 300)); process.exit(1); });
}
