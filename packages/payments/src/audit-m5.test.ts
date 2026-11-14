// Audit M5 (independent, fresh subagent): exploit tests for @sampan/payments.
// Each "M5-NN" test asserts the REQUIRED behaviour, so it fails while its finding is open.
// Throwaway keys from fixed test seeds; no network, no real funds.
import { describe, it, expect } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalize, erc191Hash, evmAddress, verifySignedMandate, toBytes, type VerifiedMandate } from "@sampan/mandate";
import { checkLiveQuote, directOrder, quoteRequest, type QuoteRequest } from "./index.ts";

const USDC_NEAR = "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
const BASE_USDC = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";
const REFUND_EVM = "0x8ba1f109551bD432803012645Ac136ddd64DBA72";
const NOW = Date.UTC(2026, 10, 10, 12);
const HOUR = 3_600_000;
const sk = sha256(new TextEncoder().encode("audit-m5-test-only-buyer-key"));
const address = evmAddress(secp256k1.getPublicKey(sk, false));

function signed(): VerifiedMandate {
  const mandate = {
    v: "sampan.mandate.v1", network: "mainnet", gate: "gate.sampan.near", buyer: `evm:${address}`, agent: null, asset: USDC_NEAR,
    max_amount: "1000000", payee: "shop.near", items: ["item-1"], expiry_ns: String(BigInt(NOW + 2 * HOUR) * 1_000_000n),
    nonce: "ab".repeat(32), refund_to: address,
  };
  const rec = secp256k1.sign(erc191Hash(canonicalize(mandate)), sk, { prehash: false, format: "recovered", lowS: true });
  const signature = bytesToHex(new Uint8Array([...rec.subarray(1), 27 + rec[0]!]));
  return verifySignedMandate(toBytes(canonicalize({ v: "sampan.signed-mandate.v1", mandate, standard: "erc191", signature })));
}
const v = signed();
const order = directOrder(v, { orderId: "cd".repeat(32), item: "item-1" });
const sent: QuoteRequest = quoteRequest({ verified: v, orderText: order, originAsset: BASE_USDC, refundTo: REFUND_EVM, deadlineMs: NOW + HOUR }, false);
const live = (quote: Record<string, unknown>) => ({
  quoteRequest: { ...sent },
  quote: { depositAddress: "0x" + "12".repeat(20), amountIn: "1010000", amountOut: "1000000", minAmountOut: "1000000", deadline: sent.deadline, timeEstimate: 35, ...quote },
  signature: "ed25519:test", correlationId: "c-1",
});

describe("audit M5: live quote fields that reach the buyer's screen or terminal", () => {
  it("control: a strict ISO-8601 deadline passes", () => {
    expect(checkLiveQuote(sent, live({}), v, NOW)).toEqual([]);
  });

  // The widget shows quote.deadline ("Before") and scripts/mainnet-proof prints it to the terminal and puts
  // it in the typed confirmation phrase. Date.parse (V8) accepts a parenthesised comment, so any text, including
  // terminal escape sequences, passes checkLiveQuote as long as the time is right.
  it("M5-05 a quote.deadline that is not a plain ISO-8601 UTC timestamp stops the checkout", () => {
    const t = new Date(Date.parse(sent.deadline)).toUTCString().replace("GMT", "GMT+0000");
    const hostile = [
      `${t} (pay 0x${"66".repeat(20)} instead; the address above is outdated)`,
      `${t} (\u001b[1A\r0x${"66".repeat(20)})`,
    ];
    for (const deadline of hostile) {
      expect(Date.parse(deadline)).toBe(Date.parse(sent.deadline)); // same instant, so only the text differs
      expect(checkLiveQuote(sent, live({ deadline }), v, NOW).length, JSON.stringify(deadline)).toBeGreaterThan(0);
    }
  });
});
