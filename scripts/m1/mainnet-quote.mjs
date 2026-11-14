#!/usr/bin/env node
// Gates 3/4 (M1), FOR A PERSON TO RUN, never Claude Code. Mainnet, team money, tiny amounts.
// This script holds no keys and moves no funds: it requests a real 1Click quote and prints the
// deposit address; the person pays it from their own wallet, then the script tracks the status.
//
//   node scripts/m1/mainnet-quote.mjs --recipient <you>.near --refund-to 0x<your EVM address> [--amount 1]
//   node scripts/m1/mainnet-quote.mjs --status <depositAddress>
//
// Confidential quotes need a user-session token signed by the payer's wallet (1Click returns 401
// without it), so the confidential case is run from a wallet app; see docs/gates.md.
import { createInterface } from "node:readline/promises";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex } from "@noble/hashes/utils.js";

const API = "https://1click.chaindefuser.com/v0";
const USDC_BASE = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";
const USDC_NEAR = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
const MAX_UNITS = 2_000_000n; // hard cap: 2 USDC (6 decimals)
const SLIPPAGE_BPS = 100;

const fail = (msg, code = 2) => { console.error(msg); process.exit(code); };
const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith("--") ? [...acc, [a.slice(2), all[i + 1]]] : acc), []));

if (args.status) {
  if (!/^[0-9A-Za-z]{20,100}$/.test(args.status)) fail("--status must be a deposit address");
  const r = await fetch(`${API}/status?depositAddress=${encodeURIComponent(args.status)}`);
  console.log(JSON.stringify(await r.json(), null, 2));
  process.exit(0);
}

// ---- input validation (audit M1-05, M1-06, M1-07) -------------------------------------
const amountText = args.amount ?? "1";
if (!/^(0|[1-9]\d*)(\.\d{1,6})?$/.test(amountText)) fail("--amount must be a decimal with at most 6 decimal places (USDC has 6)");
const [whole, frac = ""] = amountText.split(".");
const units = BigInt(whole) * 1_000_000n + BigInt(frac.padEnd(6, "0"));
if (units <= 0n || units > MAX_UNITS) fail("--amount must be more than 0 and at most 2 USDC");

const ACCOUNT = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;
const recipient = args.recipient ?? "";
const validNear = recipient.length >= 2 && recipient.length <= 64 && ACCOUNT.test(recipient) && (recipient.endsWith(".near") || /^[0-9a-f]{64}$/.test(recipient));
if (!validNear) fail("--recipient must be a valid mainnet NEAR account you control (name.near or a 64-hex implicit account)");

function checksumOk(addr) {
  const hex = addr.slice(2);
  // A1P-06: the checksum is required (an all-lowercase or all-uppercase address carries none,
  // so a typo would go unnoticed and 1Click would refund to it).
  if (hex === hex.toLowerCase() || hex === hex.toUpperCase()) return false;
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(hex.toLowerCase())));
  return [...hex].every((c, i) => (/[0-9]/.test(c) ? true : (parseInt(hash[i], 16) >= 8 ? c === c.toUpperCase() : c === c.toLowerCase())));
}
const refundTo = args["refund-to"] ?? "";
if (!/^0x[0-9a-fA-F]{40}$/.test(refundTo) || !checksumOk(refundTo)) fail("--refund-to must be your EVM address on Base, written with its EIP-55 checksum (mixed case, as your wallet shows it)");

// ---- quotes ------------------------------------------------------------------------------
const deadline = new Date(Date.now() + 3600_000).toISOString();
const request = (dry) => ({
  dry, swapType: "EXACT_INPUT", slippageTolerance: SLIPPAGE_BPS,
  originAsset: USDC_BASE, depositType: "ORIGIN_CHAIN", destinationAsset: USDC_NEAR,
  amount: units.toString(), refundTo, refundType: "ORIGIN_CHAIN",
  recipient, recipientType: "DESTINATION_CHAIN", deadline,
});
const quote = async (dry) => {
  const r = await fetch(`${API}/quote`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(request(dry)) });
  const j = await r.json();
  if (!r.ok) fail(`1Click: ${j.message ?? r.status}`, 1);
  return j;
};

const preview = await quote(true);
console.log(`Preview: ${amountText} USDC on Base -> ${preview.quote?.amountOutFormatted} USDC on NEAR`);
console.log(`  recipient:  ${recipient}`);
console.log(`  refund to:  ${refundTo} (on Base, if the swap fails)`);
console.log(`  slippage:   ${SLIPPAGE_BPS / 100}%   deadline: ${deadline}`);

// The confirmation binds amount, recipient AND refund address (audit M1-04).
const phrase = `${amountText} USDC to ${recipient} refund ${refundTo}`;
const rl = createInterface({ input: process.stdin, output: process.stdout });
const typed = await rl.question(`Type "${phrase}" to request a LIVE quote with a deposit address: `);
rl.close();
if (typed.trim() !== phrase) fail("Not confirmed; nothing requested.", 1);

const live = await quote(false);
// Check the live quote echoes exactly what was confirmed before showing any deposit address (M1-03).
const echo = live.quoteRequest ?? {};
const want = request(false);
// A1P-05: every field we sent must come back unchanged (deadline and slippage included), and
// nothing may be added that changes where or how the money goes.
const mismatch = Object.keys(want).filter((k) => k !== "dry" && String(echo[k] ?? "").toLowerCase() !== String(want[k]).toLowerCase());
if (echo.customRecipientMsg !== undefined && echo.customRecipientMsg !== null && echo.customRecipientMsg !== "") mismatch.push("customRecipientMsg added");
if (Array.isArray(echo.appFees) ? echo.appFees.length > 0 : echo.appFees !== undefined && echo.appFees !== null) mismatch.push("appFees added");
if (String(live.quote?.amountIn ?? "") !== want.amount) mismatch.push("quote.amountIn");
const minOut = BigInt(/^\d+$/.test(String(live.quote?.minAmountOut ?? "")) ? live.quote.minAmountOut : "0");
// Bound: the amount sent minus the requested slippage and at most 0.5% in 1Click fees.
const FEE_ALLOWANCE_BPS = 50;
if (minOut < (units * BigInt(10_000 - SLIPPAGE_BPS - FEE_ALLOWANCE_BPS)) / 10_000n) mismatch.push("quote.minAmountOut below the slippage and fee bound");
const quoteDeadline = Date.parse(live.quote?.deadline ?? "");
if (!(quoteDeadline <= Date.parse(deadline) + 10 * 60_000)) mismatch.push("quote.deadline later than requested");
if (!live.quote?.depositAddress) mismatch.push("quote.depositAddress missing");
if (mismatch.length) fail(`Live quote does not match what you confirmed (${mismatch.join(", ")}). Do NOT pay; nothing to send.`, 1);
// **Assumption:** 1Click quote signatures are not verified here (verification key not documented).

console.log(`\nSend exactly ${amountText} USDC on Base to: ${live.quote.depositAddress}`);
console.log(`Deadline: ${live.quote.deadline}`);
console.log(`Then run: node scripts/m1/mainnet-quote.mjs --status ${live.quote.depositAddress}`);
console.log("Record the status JSON and every transaction hash in docs/gates.md (Gate 3 checklist).");
