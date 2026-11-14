// M5 abuse cases for the 1Click side of the direct checkout (docs/SECURITY.md 6 "M5", and
// docs/audits/A1-payments.md, M5-1 to M5-10). Throwaway keys from fixed test seeds; no network.
import { describe, it, expect } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalize, erc191Hash, evmAddress, verifySignedMandate, toBytes, type VerifiedMandate } from "@sampan/mandate";
import {
  attributionMessage, checkLiveQuote, toChecksumEvm, directOrder, evmRefundAccount, isChecksummedEvm, quoteRequest, quoteStatus, requestQuote,
  ONECLICK_API, ONECLICK_MSG_LIMIT, SETTLEMENT_MARGIN_MS, PaymentError, type QuoteRequest,
} from "./index.ts";

const USDC_NEAR = "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
const BASE_USDC = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";
const REFUND_EVM = "0x8ba1f109551bD432803012645Ac136ddd64DBA72"; // EIP-55 test address
const NOW = Date.UTC(2026, 10, 10, 12);
const HOUR = 3_600_000;

const sk = sha256(new TextEncoder().encode("m5-test-only-buyer-key"));
const address = evmAddress(secp256k1.getPublicKey(sk, false));

function signed(over: Record<string, unknown> = {}): VerifiedMandate {
  const mandate = {
    v: "sampan.mandate.v1", network: "mainnet", gate: "gate.sampan.near", buyer: `evm:${address}`, agent: null, asset: USDC_NEAR,
    max_amount: "1000000", payee: "shop.near", items: ["item-1"], expiry_ns: String(BigInt(NOW + 2 * HOUR) * 1_000_000n),
    nonce: "ab".repeat(32), refund_to: address, ...over,
  };
  const rec = secp256k1.sign(erc191Hash(canonicalize(mandate)), sk, { prehash: false, format: "recovered", lowS: true });
  const signature = bytesToHex(new Uint8Array([...rec.subarray(1), 27 + rec[0]!]));
  return verifySignedMandate(toBytes(canonicalize({ v: "sampan.signed-mandate.v1", mandate, standard: "erc191", signature })));
}
const v = signed();
const order = directOrder(v, { orderId: "cd".repeat(32), item: "item-1" });
const params = { verified: v, orderText: order, originAsset: BASE_USDC, refundTo: REFUND_EVM, deadlineMs: NOW + HOUR };
const code = (f: () => unknown) => {
  try { f(); } catch (e) { return e instanceof PaymentError ? e.code : `other:${(e as Error).message}`; }
  return "none";
};
function live(req: QuoteRequest, quote: Record<string, unknown> = {}, echo: Record<string, unknown> = {}) {
  return {
    quoteRequest: { ...req, dry: false, ...echo },
    quote: { depositAddress: "0x" + "12".repeat(20), amountIn: "1010000", amountOut: "1000000", minAmountOut: "1000000", deadline: req.deadline, timeEstimate: 35, ...quote },
    signature: "ed25519:test", correlationId: "c-1",
  };
}

describe("M5-1 quote request from the signed mandate only", () => {
  it("exact output of the signed price to the gate, with the short attribution message", () => {
    const r = quoteRequest(params, false);
    expect(r).toMatchObject({ swapType: "EXACT_OUTPUT", amount: "1000000", recipient: "gate.sampan.near", recipientType: "DESTINATION_CHAIN", destinationAsset: `nep141:${USDC_NEAR}`, refundTo: REFUND_EVM, refundType: "ORIGIN_CHAIN", depositType: "ORIGIN_CHAIN" });
    expect(JSON.parse(r.customRecipientMsg)).toEqual({ mandate_hash: v.mandateHash, order });
    expect(Object.keys(r)).not.toContain("appFees");
    expect(Object.keys(r)).not.toContain("referral");
  });
  it("an order that is not the exact price, payee or asset is refused", () => {
    const bad = canonicalize({ v: "sampan.order.v1", order_id: "cd".repeat(32), mandate_hash: v.mandateHash, item: "item-1", amount: "999999", asset: USDC_NEAR, payee: "shop.near" });
    expect(code(() => quoteRequest({ ...params, orderText: bad }, true))).toBe("order");
    expect(code(() => directOrder(signed({ agent: "agent.near" }), { orderId: "cd".repeat(32), item: "item-1" }))).toBe("not_direct");
    expect(code(() => directOrder(v, { orderId: "cd".repeat(32), item: "item-2" }))).toBe("item");
  });
  it("an origin asset that is not offered is refused", () => {
    expect(code(() => quoteRequest({ ...params, originAsset: "nep141:wrap.near" }, true))).toBe("origin_asset");
  });
});

describe("M5-6, M5-7 refund destinations (A1P-06, A1P-08)", () => {
  it("the origin refund address must carry its EIP-55 checksum", () => {
    expect(isChecksummedEvm(REFUND_EVM)).toBe(true);
    expect(code(() => quoteRequest({ ...params, refundTo: REFUND_EVM.toLowerCase() }, true))).toBe("refund_address");
    expect(code(() => quoteRequest({ ...params, refundTo: REFUND_EVM.replace("8b", "8c") }, true))).toBe("refund_address");
  });
  it("an EVM buyer's NEAR refund account is their own 0x account", () => {
    expect(evmRefundAccount(REFUND_EVM)).toBe(REFUND_EVM.toLowerCase());
    expect(code(() => quoteRequest({ ...params, verified: signed({ refund_to: "merchant.near" }) }, true))).toBe("refund_account");
  });
});

describe("M5-8 timing (A1P-07)", () => {
  it("the quote deadline must end 30 minutes before the mandate expires", () => {
    const exp = NOW + 2 * HOUR;
    expect(code(() => quoteRequest({ ...params, deadlineMs: exp - SETTLEMENT_MARGIN_MS }, true))).toBe("none");
    expect(code(() => quoteRequest({ ...params, deadlineMs: exp - SETTLEMENT_MARGIN_MS + 1 }, true))).toBe("timing");
    expect(code(() => quoteRequest({ ...params, deadlineMs: Number.NaN }, true))).toBe("timing");
  });
});

describe("A1P-01 attribution message size", () => {
  it("the largest mandate the formats allow still produces a message within 1Click's limit", () => {
    const long = "x".repeat(64);
    const big = signed({ items: Array.from({ length: 16 }, (_, i) => `${long.slice(0, 62)}${String(i).padStart(2, "0")}`), payee: `${"p".repeat(55)}.near`, gate: `${"g".repeat(55)}.near` });
    const o = directOrder(big, { orderId: "ef".repeat(32), item: big.mandate.items[15]! });
    const msg = attributionMessage(big.mandateHash, o);
    expect(msg.length).toBeLessThanOrEqual(ONECLICK_MSG_LIMIT);
  });
  it("a message for another mandate, or a malformed hash, is refused", () => {
    expect(code(() => attributionMessage("ab".repeat(32), order))).toBe("order");
    expect(code(() => attributionMessage("AB".repeat(32), order))).toBe("mandate_hash");
  });
});

describe("M5-2 live quote echo (quote tampering)", () => {
  const sent = quoteRequest(params, false);
  it("control: an exact echo passes", () => {
    expect(checkLiveQuote(sent, live(sent), v, NOW)).toEqual([]);
  });
  for (const [k, val] of Object.entries({
    swapType: "EXACT_INPUT", slippageTolerance: 5000, originAsset: "nep141:eth.omft.near", depositType: "INTENTS", destinationAsset: "nep141:usdt.tether-token.near",
    amount: "1", refundTo: "0x" + "99".repeat(20), refundType: "INTENTS", recipient: "attacker.near", recipientType: "INTENTS", deadline: new Date(NOW + 5 * HOUR).toISOString(),
    customRecipientMsg: JSON.stringify({ mandate_hash: "ab".repeat(32), order: null }), dry: true,
  })) {
    it(`a changed ${k} stops the checkout`, () => {
      expect(checkLiveQuote(sent, live(sent, {}, { [k]: val }), v, NOW).join()).toMatch(new RegExp(`quoteRequest\\.${k} differs`));
    });
  }
  it("added fees, referral or a virtual recipient stop the checkout", () => {
    for (const k of ["appFees", "referral", "virtualChainRecipient"]) expect(checkLiveQuote(sent, live(sent, {}, { [k]: [{ recipient: "x.near", fee: 100 }] }), v, NOW).join()).toMatch(`quoteRequest.${k} added`);
  });
  it("under- or over-delivery against the signed price stops the checkout", () => {
    expect(checkLiveQuote(sent, live(sent, { amountOut: "999999" }), v, NOW).join()).toMatch(/amountOut/);
    expect(checkLiveQuote(sent, live(sent, { minAmountOut: "990000" }), v, NOW).join()).toMatch(/minAmountOut/);
    expect(checkLiveQuote(sent, live(sent, { amountOut: "1000001" }), v, NOW).join()).toMatch(/amountOut/);
  });
  it("a changed rate above the slippage and fee bound stops the checkout", () => {
    expect(checkLiveQuote(sent, live(sent, { amountIn: "1015000" }), v, NOW)).toEqual([]);
    expect(checkLiveQuote(sent, live(sent, { amountIn: "1015001" }), v, NOW).join()).toMatch(/amountIn/);
    expect(checkLiveQuote(sent, live(sent, { amountIn: "-1" }), v, NOW).join()).toMatch(/amountIn/);
  });
  it("a later deadline, no margin, or a slow route stops the checkout (late delivery)", () => {
    expect(checkLiveQuote(sent, live(sent, { deadline: new Date(NOW + HOUR + 1000).toISOString() }), v, NOW).join()).toMatch(/later than requested/);
    expect(checkLiveQuote(sent, live(sent, { timeEstimate: 3600 }), v, NOW).join()).toMatch(/timeEstimate/);
    expect(checkLiveQuote(sent, live(sent, { timeEstimate: undefined }), v, NOW).join()).toMatch(/timeEstimate/);
  });
  it("a missing or malformed deposit address stops the checkout", () => {
    expect(checkLiveQuote(sent, live(sent, { depositAddress: undefined }), v, NOW).join()).toMatch(/depositAddress/);
    expect(checkLiveQuote(sent, live(sent, { depositAddress: "javascript:alert(1)" }), v, NOW).join()).toMatch(/depositAddress/);
  });
  it("M5-9: a dry request can never be used for a deposit", () => {
    const dry = quoteRequest(params, true);
    expect(dry.dry).toBe(true);
    expect(checkLiveQuote(dry, live(dry, {}, { dry: true }), v, NOW).join()).toMatch(/dry request/);
  });
});

describe("1Click client: errors, timeouts, hosts", () => {
  const sent = quoteRequest(params, true);
  const answer = (status: number, text: string) => async () => ({ ok: status < 400, status, text: async () => text });
  it("only ever calls the 1Click API", async () => {
    const urls: string[] = [];
    await requestQuote(sent, async (u) => { urls.push(u); return { ok: true, status: 200, text: async () => "{}" }; });
    await quoteStatus("0x" + "12".repeat(20), async (u) => { urls.push(u); return { ok: true, status: 200, text: async () => "{}" }; });
    expect(urls.every((u) => u.startsWith(ONECLICK_API + "/"))).toBe(true);
  });
  it("a refusal, garbage, an oversized answer, a network error or a timeout is an error, never a quote", async () => {
    await expect(requestQuote(sent, answer(400, JSON.stringify({ message: "amount too low‮<script>" })))).rejects.toMatchObject({ code: "quote_refused", message: expect.not.stringMatching(/‮/) });
    await expect(requestQuote(sent, answer(200, "<html>"))).rejects.toMatchObject({ code: "response_invalid" });
    await expect(requestQuote(sent, answer(200, " ".repeat(70_000)))).rejects.toMatchObject({ code: "response_too_large" });
    await expect(requestQuote(sent, async () => { throw new Error("offline"); })).rejects.toMatchObject({ code: "network" });
    const hang = (_u: string, init?: { signal?: AbortSignal }) => new Promise<never>((_, rej) => init?.signal?.addEventListener("abort", () => rej(new Error("aborted"))));
    await expect(requestQuote(sent, hang, 20)).rejects.toMatchObject({ code: "network" });
  });
  it("a status request needs a deposit address", async () => {
    await expect(quoteStatus("../../v0/quote", answer(200, "{}"))).rejects.toMatchObject({ code: "deposit_address" });
  });
});

describe("M5 self-review regressions", () => {
  const sent = quoteRequest(params, false);
  it("M5-CR1: a lower-case wallet address is checksummed, never refused", () => {
    expect(toChecksumEvm(REFUND_EVM.toLowerCase())).toBe(REFUND_EVM);
    expect(code(() => quoteRequest({ ...params, refundTo: toChecksumEvm(REFUND_EVM.toLowerCase()) }, true))).toBe("none");
  });
  it("M5-CR3: the deadline is sent in whole seconds and an equal echo in another ISO form passes", () => {
    const r = quoteRequest({ ...params, deadlineMs: NOW + HOUR + 123 }, false);
    expect(r.deadline).toBe(new Date(NOW + HOUR).toISOString());
    expect(checkLiveQuote(r, live(r, {}, { deadline: r.deadline.replace(".000Z", "Z") }), v, NOW)).toEqual([]);
  });
  it("M5-CR6: a quote deadline less than 10 minutes away stops the checkout", () => {
    expect(checkLiveQuote(sent, live(sent, { deadline: new Date(NOW + 5 * 60_000).toISOString() }), v, NOW).join()).toMatch(/less than 10 minutes/);
  });
  it("M5-CR7: a quote asking for less than the price stops the checkout", () => {
    expect(checkLiveQuote(sent, live(sent, { amountIn: "1" }), v, NOW).join()).toMatch(/below the signed price/);
  });
  it("M5-CR8: an oversized streamed answer is cut off while reading", async () => {
    let pulled = 0;
    const body = new ReadableStream<Uint8Array>({ pull(c) { pulled++; c.enqueue(new Uint8Array(16 * 1024)); } });
    await expect(requestQuote(sent, async () => ({ ok: true, status: 200, text: async () => "", body }))).rejects.toMatchObject({ code: "response_too_large" });
    expect(pulled).toBeLessThan(10);
  });
});
