// @sampan/payments (M5): the 1Click side of a direct checkout, as decided after audit A1.
//
// The Sampan relayer registers the buyer's signed mandate on the gate first. The 1Click quote
// then asks for exactly the signed price (EXACT_OUTPUT) delivered to the gate, with a short
// attribution message {"mandate_hash","order"} in customRecipientMsg. Nothing here signs or
// holds a key. Checklist items M5-1 to M5-10 refer to docs/audits/A1-payments.md.
import { canonicalize, parseOrder, toBytes, type VerifiedMandate } from "@sampan/mandate";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex } from "@noble/hashes/utils.js";

export const ONECLICK_API = "https://1click.chaindefuser.com/v0";
/** 1Click refuses a longer customRecipientMsg (observed 6 Nov 2026, A1P-01). */
export const ONECLICK_MSG_LIMIT = 1024;
/** Quote deadline + margin <= mandate expiry (A1P-07). */
export const SETTLEMENT_MARGIN_MS = 30 * 60_000;
export const SLIPPAGE_BPS = 100;
/** At most 0.5% in 1Click fees on top of the slippage. **Assumption**, as in scripts/m1. */
export const FEE_ALLOWANCE_BPS = 50;
export const MAX_RESPONSE_BYTES = 64 * 1024;

/** Origin assets the widget offers. All are USDC with 6 decimals, like USDC on NEAR. */
export const ORIGIN_ASSETS: Record<string, { label: string; chain: "evm" }> = {
  "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near": { label: "USDC on Base", chain: "evm" },
};

export class PaymentError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}
const fail = (code: string, message: string): never => {
  throw new PaymentError(code, message);
};

// ---- addresses --------------------------------------------------------------------------

/** EIP-55: an address must carry its checksum (mixed case), A1P-06. */
export function isChecksummedEvm(address: string): boolean {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) return false;
  const hex = address.slice(2);
  if (hex === hex.toLowerCase() || hex === hex.toUpperCase()) return false;
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(hex.toLowerCase())));
  return [...hex].every((c, i) => (/[0-9]/.test(c) ? true : parseInt(hash[i]!, 16) >= 8 ? c === c.toUpperCase() : c === c.toLowerCase()));
}

/** The EIP-55 form of an address a wallet returned (wallets often return lower case). */
export function toChecksumEvm(address: string): string {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) fail("refund_address", "not an EVM address");
  const hex = address.slice(2).toLowerCase();
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(hex)));
  return "0x" + [...hex].map((c, i) => (parseInt(hash[i]!, 16) >= 8 ? c.toUpperCase() : c)).join("");
}

/** A1P-08: an EVM buyer's refund account on NEAR is their own Ethereum-implicit account
 * (`0x` + the address in lower case), controlled by the same key. **Assumption** (M5 check). */
export function evmRefundAccount(address: string): string {
  if (!isChecksummedEvm(address)) fail("refund_address", "the EVM address must be EIP-55 checksummed");
  return address.toLowerCase();
}

// ---- documents --------------------------------------------------------------------------

/** The unsigned order for a direct checkout: exactly the signed price, once (A1C-04). */
export function directOrder(v: MandateRef, { orderId, item }: { orderId: string; item: string }): string {
  const m = v.mandate;
  if (m.agent !== null) fail("not_direct", "a direct checkout needs a mandate with no agent");
  if (!m.items.includes(item)) fail("item", "the item is not in the signed mandate");
  const text = canonicalize({ v: "sampan.order.v1", order_id: orderId, mandate_hash: v.mandateHash, item, amount: m.max_amount, asset: m.asset, payee: m.payee });
  parseOrder(toBytes(text)); // the shared grammar: throws on a bad order_id or item
  return text;
}

/** The gate's FundingMsg naming a registered mandate, within 1Click's limit (A1P-01). */
export function attributionMessage(mandateHash: string, orderText: string): string {
  if (!/^[0-9a-f]{64}$/.test(mandateHash)) fail("mandate_hash", "the mandate hash must be 64 lower-case hex characters");
  const { order } = parseOrder(toBytes(orderText));
  if (order.mandate_hash !== mandateHash) fail("order", "the order names another mandate");
  const msg = JSON.stringify({ mandate_hash: mandateHash, order: orderText });
  if (msg.length > ONECLICK_MSG_LIMIT) fail("message_too_long", `the payment message is ${msg.length} characters; 1Click allows ${ONECLICK_MSG_LIMIT}`);
  return msg;
}

// ---- quote request (M5-1, M5-8, M5-9) ------------------------------------------------------

/** A mandate and its hash: signed (live) or not yet signed (dry preview, M5-9). */
export type MandateRef = Pick<VerifiedMandate, "mandate" | "mandateHash">;

export interface QuoteParams {
  verified: MandateRef;
  orderText: string;
  originAsset: string;
  /** The buyer's own origin-chain address from the connected wallet (M5-6). */
  refundTo: string;
  /** When 1Click starts refunding if nothing was deposited (ms since epoch). */
  deadlineMs: number;
}

export interface QuoteRequest {
  dry: boolean;
  swapType: "EXACT_OUTPUT";
  slippageTolerance: number;
  originAsset: string;
  depositType: "ORIGIN_CHAIN";
  destinationAsset: string;
  amount: string;
  refundTo: string;
  refundType: "ORIGIN_CHAIN";
  recipient: string;
  recipientType: "DESTINATION_CHAIN";
  deadline: string;
  customRecipientMsg: string;
}

const expiryMs = (v: MandateRef) => Number(BigInt(v.mandate.expiry_ns) / 1_000_000n);

/** Build the quote request from the signed mandate only. `dry` is the only switch between the
 * preview and a live quote with a deposit address (M5-9). */
export function quoteRequest(p: QuoteParams, dry: boolean): QuoteRequest {
  const m = p.verified.mandate;
  const origin = ORIGIN_ASSETS[p.originAsset] ?? fail("origin_asset", "this origin asset is not offered");
  if (origin.chain === "evm" && !isChecksummedEvm(p.refundTo)) fail("refund_address", "the refund address must be the buyer's EIP-55 checksummed address");
  if (!Number.isSafeInteger(p.deadlineMs) || p.deadlineMs + SETTLEMENT_MARGIN_MS > expiryMs(p.verified)) {
    fail("timing", "the quote deadline must end at least 30 minutes before the mandate expires");
  }
  // A1P-08: an EVM buyer's NEAR refunds go to their own Ethereum-implicit account.
  if (m.buyer.startsWith("evm:") && m.refund_to !== m.buyer.slice(4).toLowerCase()) fail("refund_account", "refund_to must be the buyer's own 0x account on NEAR");
  const { order } = parseOrder(toBytes(p.orderText));
  if (order.amount !== m.max_amount || order.payee !== m.payee || order.asset !== m.asset) fail("order", "the order must be the mandate's exact price, payee and asset");
  return {
    dry,
    swapType: "EXACT_OUTPUT",
    slippageTolerance: SLIPPAGE_BPS,
    originAsset: p.originAsset,
    depositType: "ORIGIN_CHAIN",
    destinationAsset: `nep141:${m.asset}`,
    amount: m.max_amount,
    refundTo: p.refundTo,
    refundType: "ORIGIN_CHAIN",
    recipient: m.gate,
    recipientType: "DESTINATION_CHAIN",
    // Whole seconds, so 1Click's echo of the timestamp compares exactly (M5 self-review).
    deadline: new Date(Math.floor(p.deadlineMs / 1000) * 1000).toISOString(),
    customRecipientMsg: attributionMessage(p.verified.mandateHash, p.orderText),
  };
}

// ---- live quote check (M5-2, M5-8) ---------------------------------------------------------

/** Fields 1Click may echo that do not change where or how much money goes. **Assumption**:
 * taken from the public OpenAPI spec; anything else in the echo stops the checkout. */
const BENIGN_ECHO = new Set(["quoteWaitingTimeMs"]);

export interface LiveQuote {
  quoteRequest?: Record<string, unknown>;
  quote?: { depositAddress?: unknown; amountIn?: unknown; amountOut?: unknown; minAmountOut?: unknown; deadline?: unknown; timeEstimate?: unknown };
  signature?: unknown;
  correlationId?: unknown;
}

/** Problems with a live quote; empty means the deposit address may be shown. */
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

/** Shortest time the buyer must have left to pay before 1Click's deadline. */
export const MIN_TIME_TO_PAY_MS = 10 * 60_000;

export function checkLiveQuote(sent: QuoteRequest, live: LiveQuote, v: VerifiedMandate, nowMs = Date.now()): string[] {
  const p: string[] = [];
  const echo = live.quoteRequest ?? {};
  if (sent.dry) p.push("a dry request has no deposit address");
  for (const k of Object.keys(sent) as (keyof QuoteRequest)[]) {
    const a = echo[k];
    const b = sent[k];
    const same =
      k === "refundTo" && typeof a === "string" ? a.toLowerCase() === String(b).toLowerCase()
      : k === "deadline" && typeof a === "string" ? Date.parse(a) === Date.parse(String(b))
      : a === b;
    if (!same) p.push(`quoteRequest.${k} differs`);
  }
  for (const k of Object.keys(echo)) {
    if (!Object.hasOwn(sent, k) && !BENIGN_ECHO.has(k) && echo[k] !== undefined && echo[k] !== null) p.push(`quoteRequest.${k} added`);
  }
  // M5-09: the request itself must be the one quoteRequest() builds for this mandate.
  if (sent.recipient !== v.mandate.gate || sent.amount !== v.mandate.max_amount || sent.destinationAsset !== `nep141:${v.mandate.asset}`) p.push("the request does not match the mandate");
  try {
    if ((JSON.parse(sent.customRecipientMsg) as { mandate_hash?: unknown }).mandate_hash !== v.mandateHash) p.push("the payment message names another mandate");
  } catch {
    p.push("the payment message is not readable");
  }
  const q = live.quote ?? {};
  const price = v.mandate.max_amount;
  if (q.amountOut !== price) p.push("quote.amountOut is not the signed price");
  if (q.minAmountOut !== price) p.push("quote.minAmountOut is not the signed price");
  const amountIn = typeof q.amountIn === "string" && /^[1-9]\d{0,30}$/.test(q.amountIn) ? BigInt(q.amountIn) : null;
  const bound = (BigInt(price) * BigInt(10_000 + SLIPPAGE_BPS + FEE_ALLOWANCE_BPS)) / 10_000n;
  if (amountIn === null || amountIn > bound) p.push("quote.amountIn is above the slippage and fee bound");
  // Same 6-decimal USDC on both sides: exact output cannot cost less than the price.
  if (amountIn !== null && amountIn < BigInt(price)) p.push("quote.amountIn is below the signed price");
  // M5-05: a plain ISO-8601 UTC timestamp only; this text reaches the buyer's screen.
  const deadline = typeof q.deadline === "string" && ISO_UTC.test(q.deadline) ? Date.parse(q.deadline) : NaN;
  if (Number.isNaN(deadline)) p.push("quote.deadline is not a plain UTC timestamp");
  if (!(deadline <= Date.parse(sent.deadline))) p.push("quote.deadline is later than requested");
  if (!(deadline >= nowMs + MIN_TIME_TO_PAY_MS)) p.push("quote.deadline leaves the buyer less than 10 minutes to pay");
  if (!(deadline + SETTLEMENT_MARGIN_MS <= expiryMs(v))) p.push("quote.deadline leaves no settlement margin before the mandate expires");
  const est = typeof q.timeEstimate === "number" ? q.timeEstimate : NaN;
  if (!(est >= 0 && est * 1000 <= SETTLEMENT_MARGIN_MS)) p.push("quote.timeEstimate exceeds the settlement margin");
  const origin = ORIGIN_ASSETS[sent.originAsset];
  if (origin?.chain === "evm" && !(typeof q.depositAddress === "string" && /^0x[0-9a-fA-F]{40}$/.test(q.depositAddress))) p.push("quote.depositAddress is not an EVM address");
  return p;
}

// ---- 1Click client ---------------------------------------------------------------------------

type Fetch = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<{ ok: boolean; status: number; text(): Promise<string>; body?: ReadableStream<Uint8Array> | null }>;

/** Read at most MAX_RESPONSE_BYTES, streaming when the body is a stream (M5 self-review). */
async function readCapped(r: Awaited<ReturnType<Fetch>>): Promise<string> {
  if (!r.body || typeof r.body.getReader !== "function") return r.text();
  const reader = r.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > MAX_RESPONSE_BYTES) {
      await reader.cancel().catch(() => undefined);
      fail("response_too_large", "1Click's answer is too large");
    }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.length;
  }
  return new TextDecoder().decode(all);
}

async function call(fetchImpl: Fetch, path: string, init: { method?: string; body?: string }, timeoutMs: number): Promise<unknown> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetchImpl(`${ONECLICK_API}${path}`, { ...init, headers: { "content-type": "application/json" }, signal: ctrl.signal }).catch(() => fail("network", "1Click did not answer"));
    const text = await readCapped(r);
    if (text.length > MAX_RESPONSE_BYTES) fail("response_too_large", "1Click's answer is too large");
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      fail("response_invalid", "1Click's answer is not JSON");
    }
    if (!r.ok) {
      const msg = typeof (body as { message?: unknown })?.message === "string" ? (body as { message: string }).message : "";
      fail("quote_refused", `1Click refused (${r.status}): ${msg.replace(/[^\x20-\x7e]/g, "").slice(0, 200)}`);
    }
    return body;
  } finally {
    clearTimeout(timer);
  }
}

/** POST /v0/quote. The request must come from quoteRequest(). */
export function requestQuote(req: QuoteRequest, fetchImpl: Fetch, timeoutMs = 15_000): Promise<LiveQuote> {
  return call(fetchImpl, "/quote", { method: "POST", body: JSON.stringify(req) }, timeoutMs) as Promise<LiveQuote>;
}

/** GET /v0/status for a deposit address. */
export async function quoteStatus(depositAddress: string, fetchImpl: Fetch, timeoutMs = 15_000): Promise<unknown> {
  if (!/^[0-9A-Za-z]{20,100}$/.test(depositAddress)) fail("deposit_address", "not a deposit address");
  return call(fetchImpl, `/status?depositAddress=${encodeURIComponent(depositAddress)}`, { method: "GET" }, timeoutMs);
}

// ---- NEAR view calls (the widget confirms with the gate itself, M5-01, M5-07) ---------------

export const NEAR_RPC: Record<"testnet" | "mainnet", string> = {
  testnet: "https://rpc.testnet.near.org",
  mainnet: "https://rpc.mainnet.near.org",
};

async function rpc(network: "testnet" | "mainnet", params: Record<string, unknown>, fetchImpl: Fetch, timeoutMs: number): Promise<{ result?: { result?: number[]; code_hash?: string }; error?: { cause?: { name?: string } } }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetchImpl(NEAR_RPC[network], { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: "sampan", method: "query", params: { finality: "final", ...params } }), signal: ctrl.signal }).catch(() => fail("network", "NEAR did not answer"));
    try {
      return JSON.parse(await readCapped(r));
    } catch (e) {
      if (e instanceof PaymentError) throw e;
      return fail("response_invalid", "NEAR's answer is not JSON");
    }
  } finally {
    clearTimeout(timer);
  }
}

/** true / false when NEAR answers clearly; throws when it cannot tell. */
export async function nearAccountExists(network: "testnet" | "mainnet", account: string, fetchImpl: Fetch, timeoutMs = 10_000): Promise<boolean> {
  const a = await rpc(network, { request_type: "view_account", account_id: account }, fetchImpl, timeoutMs);
  if (a.result && typeof a.result.code_hash === "string") return true;
  if (a.error?.cause?.name === "UNKNOWN_ACCOUNT") return false;
  return fail("network", "NEAR could not say whether the refund account exists");
}

/** The gate's own record of a mandate (final), or null. */
export async function gateMandate(network: "testnet" | "mainnet", gate: string, mandateHash: string, fetchImpl: Fetch, timeoutMs = 10_000): Promise<Record<string, unknown> | null> {
  const args = btoa(JSON.stringify({ mandate_hash: mandateHash }));
  const a = await rpc(network, { request_type: "call_function", account_id: gate, method_name: "get_mandate", args_base64: args }, fetchImpl, timeoutMs);
  if (!a.result || !Array.isArray(a.result.result)) return fail("network", "the gate could not be asked");
  const v = JSON.parse(new TextDecoder().decode(new Uint8Array(a.result.result))) as unknown;
  return v && typeof v === "object" ? (v as Record<string, unknown>) : null;
}

/** M5-01: the gate holds exactly this mandate (payee, budget, refund account). */
export function gateHoldsMandate(record: Record<string, unknown> | null, v: MandateRef): boolean {
  const m = v.mandate;
  return !!record && record.payee === m.payee && record.max_amount === m.max_amount && record.refund_to === m.refund_to && record.expiry_ns === m.expiry_ns && (record.agent ?? null) === m.agent;
}
