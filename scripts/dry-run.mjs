#!/usr/bin/env node
// No-funds path (M8): what a reviewer can run with no wallet, no key and no money.
//   node scripts/dry-run.mjs            dry 1Click quote + check every example receipt on testnet
//   node scripts/dry-run.mjs --offline  check the example receipts' formats only (no network)
//
// 1. Builds a direct-checkout mandate exactly as the checkout widget does (not signed: a dry
//    quote needs only its hash) and asks 1Click for a DRY quote: no deposit address is
//    created, nothing is signed, nothing can be paid.
// 2. Verifies every receipt in examples/ with the checker's own code against the public NEAR
//    RPC (read-only). The test gate keeps an owner key (decision Q16), so on testnet
//    "Nobody can change the gate" and the decision-block check read "Cannot verify".
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { canonicalize, hashHex, toBytes } from "../packages/mandate/src/index.ts";
import { parseEnvelope } from "../packages/receipt/src/index.ts";
import { directOrder, quoteRequest, requestQuote, ORIGIN_ASSETS } from "../packages/payments/src/index.ts";
import { verifyReceipt } from "../apps/checker/src/verify.ts";
// Text from 1Click is printed without control or escape characters (audit M8-14).
const printable = (v, max = 160) => String(v ?? "").replace(/[^\x20-\x7e]/g, "?").slice(0, max);

const offline = process.argv.includes("--offline");
const ROOT = resolve(import.meta.dirname, "..");
let failures = 0;
const say = (ok, text) => { if (!ok) failures++; console.log(`${ok ? "OK  " : "FAIL"}  ${text}`); };

// ---- 1. dry quote ------------------------------------------------------------------------
if (!offline) {
  // A mainnet-shaped mandate for 1 USDC (EXACT_OUTPUT to a gate account). The refund address is
  // a public test address; a dry quote moves nothing.
  const buyer = "0x8ba1f109551bD432803012645Ac136ddd64DBA72";
  // 1Click refuses a quote to an account that does not exist (seen 7 Nov 2026), so the dry
  // quote names the real mainnet gate once it is deployed, and until then the existing `near`
  // account. A dry quote creates no deposit address, so nothing can reach either.
  const gateFile = resolve(ROOT, "examples/mainnet-gate.json");
  const gate = existsSync(gateFile) ? JSON.parse(readFileSync(gateFile, "utf8")).gate : "near";
  const nowMs = Date.now();
  const mandate = {
    v: "sampan.mandate.v1", network: "mainnet", gate, buyer: `evm:${buyer.toLowerCase()}`, agent: null,
    asset: "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1", max_amount: "1000000", payee: "shop.example.near",
    items: ["item-1"], expiry_ns: String(BigInt(nowMs + 2 * 3_600_000) * 1_000_000n), nonce: randomBytes(32).toString("hex"), refund_to: buyer.toLowerCase(),
  };
  const ref = { mandate, mandateHash: hashHex(canonicalize(mandate)) };
  const order = directOrder(ref, { orderId: randomBytes(32).toString("hex"), item: "item-1" });
  const req = quoteRequest({ verified: ref, orderText: order, originAsset: Object.keys(ORIGIN_ASSETS)[0], refundTo: buyer, deadlineMs: nowMs + 3_600_000 }, true);
  say(req.dry === true, "the quote request is a dry request");
  try {
    const q = await requestQuote(req, fetch);
    say(!q.quote?.depositAddress, "1Click answered without a deposit address (nothing can be paid)");
    say(q.quote?.amountOut === "1000000", `the gate would receive exactly 1 USDC (1Click asks about ${printable(q.quote?.amountInFormatted ?? "?", 12)} USDC on Base)`);
  } catch (e) {
    say(false, `dry quote: ${printable(e?.message ?? e)}`);
  }
}

// ---- 2. example receipts -----------------------------------------------------------------
if (!offline) console.log("\nChecking the example receipts against the public NEAR RPC (about 30 s each) ...");
for (const net of ["testnet", "mainnet"]) {
  const dir = resolve(ROOT, "examples", net);
  if (!existsSync(dir)) { console.log(`--    no ${net} examples yet`); continue; }
  for (const f of readdirSync(dir).filter((x) => x.endsWith(".json") && !x.startsWith("mainnet-gate"))) {
    const text = readFileSync(resolve(dir, f), "utf8");
    let env;
    try { env = parseEnvelope(toBytes(JSON.stringify(JSON.parse(text)))); } catch (e) { say(false, `${net}/${f}: not a valid receipt (${e.message})`); continue; }
    if (offline) { say(true, `${net}/${f}: valid ${env.core.decision} receipt (format, hashes, signature)`); continue; }
    // Archival RPC: a regular RPC forgets transactions after about a day, so example receipts
    // would stop verifying (audit M8-01). Archival hosts keep every transaction.
    const rpcUrl = net === "testnet" ? "https://archival-rpc.testnet.near.org" : "https://archival-rpc.mainnet.near.org";
    const r = await verifyReceipt(toBytes(text), { rpcUrl, fetchFn: (u, i) => fetch(u, i) });
    const expected = net === "testnet" ? new Set(["locked", "then"]) : new Set();
    const bad = r.checks.filter((c) => c.status !== "pass" && !(c.status === "unknown" && expected.has(c.id)));
    const verdict = { verified: "Verified", unverifiable: "Cannot verify", invalid: "Not valid" }[r.overall] ?? r.overall;
    console.log(`\n${net}/${f} (${env.core.decision}): checker verdict "${verdict}"`);
    for (const c of r.checks) {
      const mark = c.status === "pass" ? "pass" : c.status === "fail" ? "FAIL" : expected.has(c.id) ? "cannot verify (expected on testnet: the test gate keeps an owner key)" : "cannot verify";
      console.log(`      ${mark.padEnd(4)}  ${c.title}`);
    }
    say(bad.length === 0, `${net}/${f}: ${r.checks.filter((c) => c.status === "pass").length} of ${r.checks.length} checks pass${expected.size ? ", the rest are the expected testnet unknowns" : ""}${bad.length ? `; problems: ${bad.map((c) => `${c.id}:${c.status}`).join(" ")}` : ""}`);
  }
}
console.log(failures ? `\n${failures} problem(s)` : "\nDry run: everything checks out, with no wallet, key or money.");
process.exit(failures ? 1 : 0);
