#!/usr/bin/env node
// First mainnet purchase through the gate (M5, checklist P-1..P-5 in docs/audits/A1-payments.md).
// FOR A PERSON TO RUN, after audit A1 is signed and the gate is deployed and locked with
// scripts/mainnet/deploy-gate.mjs. Claude Code sessions and CI never run it: it stops without
// an interactive terminal and never reads a key from the environment or a file.
//
//   node scripts/mainnet-proof/proof.mjs prepare  --buyer 0x<EIP-55 address> --payee <shop>.near --item <item> --price 1
//       prints the exact mandate text to sign with the buyer's EVM wallet (personal_sign)
//   node scripts/mainnet-proof/proof.mjs register --signature 0x<65-byte signature> --registrant <account>.near
//       verifies the signature and registers the mandate on the gate (the key is typed at a hidden prompt)
//   node scripts/mainnet-proof/proof.mjs quote
//       dry quote, then a live quote checked field by field; prints the deposit address after a typed confirmation
//   node scripts/mainnet-proof/proof.mjs status
//       follows 1Click and the gate, and records every transaction in examples/mainnet-proof/
//   node scripts/mainnet-proof/proof.mjs refund --caller <account>.near
//       pays what the gate owes back (refund due at once, escrow after expiry) to the buyer's NEAR account
//
// Everything is written to examples/mainnet-proof/ (no key material).
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { args, stop, ask, requirePerson } from "../mainnet/cli.mjs";
import { canonicalize, hashHex, validateMandate, verifySignedMandate, toBytes } from "../../packages/mandate/src/index.ts";
import {
  checkLiveQuote, directOrder, isChecksummedEvm, quoteRequest, quoteStatus, requestQuote, ORIGIN_ASSETS, SETTLEMENT_MARGIN_MS,
} from "../../packages/payments/src/index.ts";
import { USDC, MAINNET_RPC, REVIEWED_CODE_HASH, checkLocked, reservationPerMandate } from "../mainnet/deploy-gate.mjs";

export const MAX_PRICE_UNITS = 2_000_000n; // P-1: at most 2 USDC
const ORIGIN = Object.keys(ORIGIN_ASSETS)[0];
const QUOTE_MS = 60 * 60_000;
const LIFETIME_MS = QUOTE_MS + SETTLEMENT_MARGIN_MS + 30 * 60_000; // 2 hours, within the gate's 24 h
const OUT = resolve(import.meta.dirname, "../../examples/mainnet-proof");
const ACCOUNT = /^(?=.{2,64}$)([a-z\d]+[-_])*[a-z\d]+(\.([a-z\d]+[-_])*[a-z\d]+)*\.near$/;

/** USDC amount text ("1", "0.5") to base units, or null. */
export function priceUnits(text) {
  if (!/^(0|[1-9]\d*)(\.\d{1,6})?$/.test(text ?? "")) return null;
  const [w, f = ""] = text.split(".");
  const u = BigInt(w) * 1_000_000n + BigInt(f.padEnd(6, "0"));
  return u > 0n && u <= MAX_PRICE_UNITS ? u : null;
}

/** P-1, P-2: the mandate for the first purchase, built from checked inputs only. */
export function buildProofMandate({ gate, buyer, payee, item, price, nowMs, nonce, agent = null, items = null }) {
  const p = [];
  if (!ACCOUNT.test(gate ?? "")) p.push("gate must be a named .near account");
  if (!isChecksummedEvm(buyer ?? "")) p.push("--buyer must be the buyer's EIP-55 checksummed EVM address");
  if (!ACCOUNT.test(payee ?? "")) p.push("--payee must be a named .near account");
  if (payee === gate) p.push("--payee must not be the gate");
  const units = priceUnits(price);
  if (units === null) p.push("--price must be more than 0 and at most 2 USDC, with at most 6 decimals");
  const itemList = items ?? [item];
  if (!itemList.every((x) => /^[a-z0-9][a-z0-9._-]{0,63}$/.test(x ?? ""))) p.push("--item must be a short item id (lower case, digits, . _ -)");
  if (agent !== null && (!ACCOUNT.test(agent) || agent === gate || agent === payee)) p.push("--agent must be a named .near account, not the gate or the payee");
  if (p.length) return { problems: p };
  const addr = buyer.toLowerCase();
  const mandate = {
    v: "sampan.mandate.v1", network: "mainnet", gate, buyer: `evm:${addr}`, agent, asset: USDC,
    max_amount: String(units), payee, items: itemList, expiry_ns: String(BigInt(nowMs + LIFETIME_MS) * 1_000_000n),
    nonce, refund_to: addr,
  };
  validateMandate(JSON.parse(canonicalize(mandate)));
  return { problems: [], mandate, message: canonicalize(mandate), mandateHash: hashHex(canonicalize(mandate)) };
}

/** The signed mandate from the wallet's signature; it must be exactly the prepared mandate. */
export function signedFromSignature(mandate, signatureHex) {
  if (!/^0x[0-9a-fA-F]{130}$/.test(signatureHex ?? "")) throw new Error("--signature must be the 65-byte 0x-hex signature from personal_sign");
  const text = canonicalize({ v: "sampan.signed-mandate.v1", mandate, standard: "erc191", signature: signatureHex.slice(2).toLowerCase() });
  const v = verifySignedMandate(toBytes(text)); // throws unless the buyer's key signed exactly this mandate
  if (canonicalize(v.mandate) !== canonicalize(mandate)) throw new Error("the signed mandate differs from the prepared one");
  return { text, verified: v };
}

/** P-3: the typed confirmation binds amount, recipient (gate), refund address, mandate hash and deadline. */
export function confirmationPhrase({ amountIn, gate, refundTo, mandateHash, deadline }) {
  return `pay ${amountIn} to ${gate} refund ${refundTo} mandate ${mandateHash.slice(0, 12)} before ${deadline}`;
}

/** Text from 1Click or the chain, safe to print: no control or escape characters (M5-05). */
export const printable = (v, max = 120) => String(v ?? "").replace(/[^\x20-\x7e]/g, "?").slice(0, max);

/** 1Click statuses after which nothing more will happen to the deposit. */
export const FINAL_STATUSES = new Set(["SUCCESS", "REFUNDED", "FAILED"]);

/** P-5: what the record shows, and whether the person must stop (M5-06). */
export function settlement({ status, receipt, mandate }) {
  const problems = [];
  if (status === "REFUNDED" || status === "FAILED" || status === "INCOMPLETE_DEPOSIT") problems.push(`1Click status ${status}: the deposit did not settle as a purchase`);
  if (status === "SUCCESS" && !receipt) problems.push("1Click delivered, but the gate has no receipt for the order (the order was not decided)");
  if (receipt && receipt.decision !== "release") problems.push("the gate refused the order");
  if (receipt && receipt.payout !== "Done") problems.push(`the payout is ${receipt.payout}, not Done`);
  if (mandate && mandate.refund_due !== "0") problems.push(`refund due to the buyer: ${mandate.refund_due}`);
  return problems;
}

/** The gate must be the reviewed, locked deployment, registered with USDC (D-3, D-5). */
export function checkGateReady({ gateRecord, account, keys, config, usdcStorage, totals, beforeLock = false }) {
  const p = [];
  if (!gateRecord?.gate || !gateRecord?.code_hash) p.push("examples/mainnet-gate.json is missing: deploy with scripts/mainnet/deploy-gate.mjs first");
  // The reviewed hash is a constant in the code, not taken from the record file (M8-11).
  if (gateRecord?.code_hash !== REVIEWED_CODE_HASH) p.push("examples/mainnet-gate.json does not name the reviewed code");
  if (account?.code_hash !== REVIEWED_CODE_HASH) p.push("the gate's code is not the reviewed code");
  // The smoke test before the lock (runbook step 6) may run with the deploy key still present.
  if (!beforeLock) p.push(...checkLocked(keys ?? [{}]));
  if (config?.network !== "mainnet" || config?.token !== USDC) p.push("the gate is not configured for mainnet USDC");
  // D-3 (M5-06): registered with at least USDC's storage minimum of 0.00125 NEAR.
  if (!usdcStorage || !(BigInt(usdcStorage.total ?? "0") >= 1_250_000_000_000_000_000_000n)) p.push("the gate is not registered with USDC (at least 0.00125 NEAR)");
  if (totals?.stopped !== false) p.push("the gate is stopped");
  return p;
}

// ---- person-run flow ------------------------------------------------------------------------
const load = (name) => JSON.parse(readFileSync(resolve(OUT, name), "utf8"));
const save = (name, value) => { mkdirSync(OUT, { recursive: true }); writeFileSync(resolve(OUT, name), JSON.stringify(value, null, 2) + "\n"); };
const link = (h) => `https://nearblocks.io/txns/${h}`;

async function main() {
  const a = args(process.argv.slice(2));
  if (!["prepare", "register", "quote", "status", "refund"].includes(a.cmd)) stop(["usage: prepare | register | quote | status | refund (see the file header)"]);
  requirePerson();

  const { Account, JsonRpcProvider, KeyPair } = await import("near-api-js");
  const provider = new JsonRpcProvider({ url: MAINNET_RPC });
  if ((await provider.viewNodeStatus()).chain_id !== "mainnet") stop(["RPC is not mainnet"]);
  const gateRecord = JSON.parse(readFileSync(resolve(import.meta.dirname, "../../examples/mainnet-gate.json"), "utf8"));
  const gate = gateRecord.gate;
  const view = (contractId, method, x = {}) => provider.callFunction({ contractId, method, args: x , blockQuery: { finality: "final" } });
  stop(checkGateReady({
    gateRecord, account: await provider.viewAccount({ accountId: gate, blockQuery: { finality: "final" } }),
    keys: (await provider.viewAccessKeyList({ accountId: gate, finalityQuery: { finality: "final" } })).keys,
    config: await view(gate, "get_config"), usdcStorage: await view(USDC, "storage_balance_of", { account_id: gate }), totals: await view(gate, "get_totals"),
    beforeLock: a["before-lock"] === "yes",
  }));
  if (a["before-lock"] === "yes") console.log("NOTE: smoke test before the lock: the gate still has its deploy key. Lock it afterwards (runbook step 7).");

  if (a.cmd === "prepare") {
    if (existsSync(resolve(OUT, "mandate.json")) && (await ask("A prepared mandate exists. Type \"replace\" to start over: ")) !== "replace") stop(["kept the existing mandate"]);
    const payeeOk = await provider.viewAccount({ accountId: a.payee ?? "", blockQuery: { finality: "final" } }).then(() => true, () => false);
    if (!payeeOk) stop(["--payee does not exist on mainnet"]);
    // M5-7, P-2: the NEAR refund account (the buyer's own 0x account) must exist.
    const refundAccount = String(a.buyer ?? "").toLowerCase();
    if (!(await provider.viewAccount({ accountId: refundAccount, blockQuery: { finality: "final" } }).then(() => true, () => false))) {
      stop([`the buyer's NEAR refund account ${refundAccount} does not exist yet; create it (fund it with a little NEAR) and check it before signing`]);
    }
    const r = buildProofMandate({ gate, buyer: a.buyer, payee: a.payee, item: a.item, price: a.price, nowMs: Date.now(), nonce: randomBytes(32).toString("hex") });
    stop(r.problems);
    save("mandate.json", { mandate: r.mandate, mandate_hash: r.mandateHash, buyer_display: a.buyer });
    console.log(`Mandate ${r.mandateHash}\nPays ${a.price} USDC to ${a.payee} through ${gate}; refunds on NEAR to ${r.mandate.refund_to}; ends ${new Date(Number(BigInt(r.mandate.expiry_ns) / 1_000_000n)).toISOString()}.`);
    console.log("\nSign EXACTLY this text with the buyer's wallet (personal_sign), then run register:\n");
    console.log(r.message);
    return;
  }

  const prepared = load("mandate.json");
  if (a.cmd === "register") {
    const { text, verified } = signedFromSignature(prepared.mandate, a.signature);
    if (!ACCOUNT.test(a.registrant ?? "")) stop(["--registrant must be the named .near account that pays the refundable deposit"]);
    const cfg = await view(gate, "get_config");
    const deposit = reservationPerMandate(cfg.max_orders_per_mandate, cfg.registration_deposit);
    console.log(`Registering mandate ${verified.mandateHash} with a refundable deposit of ${deposit} yoctoNEAR from ${a.registrant}.`);
    const key = await ask(`Secret key of ${a.registrant} (input hidden): `, { hidden: true });
    const acc = new Account(a.registrant, provider, KeyPair.fromString(key).toString());
    const r = await acc.callFunctionRaw({ contractId: gate, methodName: "register_mandate", args: { signed_mandate: text }, deposit, gas: 30n * 10n ** 12n });
    const ret = JSON.parse(JSON.parse(Buffer.from(r.status?.SuccessValue ?? "", "base64").toString() || '""') || "{}");
    if (ret.registered !== true) stop([`the gate refused the registration (${String(ret.reason).slice(0, 40)})`]);
    save("mandate.json", { ...prepared, signed_mandate: text, register_tx: r.transaction.hash });
    console.log(`Registered: ${link(r.transaction.hash)}`);
    return;
  }

  if (!prepared.signed_mandate) stop(["register the signed mandate first"]);
  const verified = verifySignedMandate(toBytes(prepared.signed_mandate));
  if (!(await view(gate, "get_mandate", { mandate_hash: verified.mandateHash }))) stop(["the mandate is not registered on the gate"]);

  if (a.cmd === "quote") {
    const order = prepared.order ?? directOrder(verified, { orderId: randomBytes(32).toString("hex"), item: verified.mandate.items[0] });
    const params = { verified, orderText: order, originAsset: ORIGIN, refundTo: prepared.buyer_display, deadlineMs: Date.now() + QUOTE_MS };
    const preview = await requestQuote(quoteRequest(params, true), fetch); // P-4: dry first
    if (preview.quote?.amountOut !== verified.mandate.max_amount) stop(["the dry preview does not deliver exactly the signed price (P-4)"]);
    console.log(`Preview: send about ${printable(preview.quote?.amountInFormatted, 20)} USDC on Base; the gate receives exactly ${Number(verified.mandate.max_amount) / 1e6} USDC.`);
    const sent = quoteRequest(params, false);
    const live = await requestQuote(sent, fetch);
    stop(checkLiveQuote(sent, live, verified));
    const phrase = confirmationPhrase({ amountIn: live.quote.amountIn, gate, refundTo: prepared.buyer_display, mandateHash: verified.mandateHash, deadline: live.quote.deadline });
    save("quote.json", { order, request: sent, live, quote_signature_verified: false }); // M5-3
    save("mandate.json", { ...prepared, order });
    if ((await ask(`Type "${phrase}" to show the deposit address: `)) !== phrase) stop(["not confirmed; do not pay"]);
    console.log(`\nSend exactly ${live.quote.amountIn} base units (${Number(live.quote.amountIn) / 1e6} USDC) on Base to:\n${live.quote.depositAddress}\nbefore ${live.quote.deadline}. Then run: node scripts/mainnet-proof/proof.mjs status`);
    return;
  }

  if (a.cmd === "refund") {
    // Refund due is payable at any time; escrow after expiry. Only the buyer's refund account is paid,
    // and a mandate with nothing left closes, returning the registrant's deposit.
    const m = await view(gate, "get_mandate", { mandate_hash: verified.mandateHash });
    if (!m) { console.log("The mandate is already closed; nothing to refund."); return; }
    if (m.refund_due === "0" && BigInt(m.expiry_ns) > BigInt(Date.now()) * 1_000_000n) stop([`nothing is owed yet; escrow can be refunded after ${new Date(Number(BigInt(m.expiry_ns) / 1_000_000n)).toISOString()}`]);
    if (!ACCOUNT.test(a.caller ?? "")) stop(["--caller must be any named .near account that pays the gas"]);
    console.log(`Refund to ${verified.mandate.refund_to}: refund due ${m.refund_due}, escrow ${m.escrow} (escrow only after expiry).`);
    const acc = new Account(a.caller, provider, KeyPair.fromString(await ask(`Secret key of ${a.caller} (input hidden): `, { hidden: true })).toString());
    const r = await acc.callFunctionRaw({ contractId: gate, methodName: "refund", args: { mandate_hash: verified.mandateHash }, gas: 100n * 10n ** 12n });
    console.log(`Refund transaction: ${link(r.transaction.hash)}`);
    return;
  }

  // status (P-5, M5-06): follow until 1Click reaches a final state (at most 3 hours).
  const q = load("quote.json");
  const receiptId = JSON.parse(q.order).order_id;
  let st, receipt, m;
  for (let i = 0; i < 720; i++) {
    st = await quoteStatus(q.live.quote.depositAddress, fetch);
    receipt = await view(gate, "get_receipt", { mandate_hash: verified.mandateHash, order_id: receiptId });
    m = await view(gate, "get_mandate", { mandate_hash: verified.mandateHash });
    console.log(`1Click: ${printable(st?.status, 30)}; gate receipt: ${receipt ? `${receipt.decision}, payout ${receipt.payout}` : "none yet"}`);
    if (FINAL_STATUSES.has(st?.status) && (!receipt || receipt.payout !== "Pending")) break;
    await new Promise((r) => setTimeout(r, 15_000));
  }
  // The gas 1Click attached to ft_on_transfer answers the gas Assumption (A1P-02): read each NEAR tx it names.
  const nearTxs = (st?.swapDetails?.destinationChainTxHashes ?? []).map((t) => String(t?.hash ?? "")).filter((h) => /^[1-9A-HJ-NP-Za-km-z]{43,44}$/.test(h));
  const gas = [];
  for (const hash of nearTxs) {
    const tx = await provider.viewTransactionStatus({ txHash: hash, accountId: gate, waitUntil: "FINAL" }).catch(() => null);
    for (const r of tx?.receipts ?? []) for (const a of r.receipt?.Action?.actions ?? []) if (a.FunctionCall?.method_name === "ft_on_transfer") gas.push({ tx: hash, gas: String(a.FunctionCall.gas) });
  }
  const problems = settlement({ status: st?.status, receipt, mandate: m });
  save("record.json", { gate, mandate_hash: verified.mandateHash, order_id: receiptId, register_tx: prepared.register_tx, near_txs: nearTxs.map((h) => ({ hash: h, link: link(h) })), ft_on_transfer_gas: gas, oneclick_status: st, receipt, mandate: m, problems, checked_at: new Date().toISOString() });
  console.log("Recorded in examples/mainnet-proof/record.json.");
  stop(problems.map((p) => `${p}. Record where the funds went before any further purchase (A1P-02).`));
  console.log("Settled: released and paid out. Add the transactions to docs/gates.md.");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((e) => { console.error("error: " + String(e?.message ?? e).replace(/[1-9A-HJ-NP-Za-km-z]{80,}/g, "[redacted]").slice(0, 300)); process.exit(1); });
}
