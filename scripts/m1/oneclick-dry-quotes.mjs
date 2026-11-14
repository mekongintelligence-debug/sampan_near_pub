#!/usr/bin/env node
// M1: which 1Click quote variants are accepted for our flow? Dry quotes only (`dry: true`):
// no deposit address is created and no funds can move. No API key (decision Q20).
// Run: node scripts/m1/oneclick-dry-quotes.mjs
const API = "https://1click.chaindefuser.com/v0/quote";
const USDC_BASE = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";
const USDC_NEAR = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
const REFUND = "0x8ba1f109551bd432803012645ac136ddd64dba72"; // placeholder, dry run only
// Placeholder recipient for dry runs; it must be an existing NEAR account (1Click returns a
// server error for unknown accounts). A real run uses the gate contract.
const RECIPIENT = "wrap.near";

const base = {
  dry: true, swapType: "EXACT_INPUT", slippageTolerance: 100,
  originAsset: USDC_BASE, depositType: "ORIGIN_CHAIN", destinationAsset: USDC_NEAR,
  amount: "1000000", refundTo: REFUND, refundType: "ORIGIN_CHAIN", recipient: RECIPIENT,
  deadline: new Date(Date.now() + 3600_000).toISOString(),
};
const variants = {
  "public, delivered to a NEAR account (ft_transfer)": { recipientType: "DESTINATION_CHAIN" },
  "public, delivered with ft_transfer_call + order message (customRecipientMsg)": { recipientType: "DESTINATION_CHAIN", customRecipientMsg: '{"order_id":"00"}' },
  "public, kept inside Intents (recipientType INTENTS)": { recipientType: "INTENTS" },
  "confidentiality basic, delivered to a NEAR account": { recipientType: "DESTINATION_CHAIN", confidentiality: "basic" },
  "confidentiality basic + customRecipientMsg": { recipientType: "DESTINATION_CHAIN", confidentiality: "basic", customRecipientMsg: '{"order_id":"00"}' },
  "confidentiality advanced, delivered to a NEAR account": { recipientType: "DESTINATION_CHAIN", confidentiality: "advanced" },
  "recipient inside Confidential Intents (recipientType CONFIDENTIAL_INTENTS)": { recipientType: "CONFIDENTIAL_INTENTS" },
};

const out = [];
for (const [name, extra] of Object.entries(variants)) {
  const res = await fetch(API, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...base, ...extra }) });
  const body = await res.json().catch(() => ({}));
  const q = body.quote ?? {};
  const row = { name, http: res.status, accepted: res.ok, amountOut: q.amountOutFormatted ?? null, fee: body.quoteRequest?.appFees ?? null, message: res.ok ? "" : (body.message ?? JSON.stringify(body)).slice(0, 200) };
  out.push(row);
  console.log(`${row.accepted ? "ACCEPTED" : "REJECTED"} ${res.status}  ${name}${row.amountOut ? `  (1 USDC -> ${row.amountOut})` : ""}${row.message ? `  ${row.message}` : ""}`);
}
console.log("\nRESULTS_JSON " + JSON.stringify(out));
