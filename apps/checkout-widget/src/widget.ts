// Sampan checkout widget (M5). One script tag, loaded with Subresource Integrity:
//   <div id="sampan-checkout"></div>
//   <script src="sampan-checkout.js" integrity="sha384-…" crossorigin="anonymous"
//     data-network="testnet" data-gate="…" data-asset="…" data-payee="…" data-item="…"
//     data-price="1000000" data-label="…" data-relayer="http://127.0.0.1:8790" data-mode="dry"></script>
//
// Security (docs/SECURITY.md 6 "M5", docs/audits/A1-payments.md M5-1..M5-10):
// - What the buyer sees is rendered from the same mandate object that is signed; after
//   signing, the signed text is verified and must canonicalize to exactly that mandate.
// - The dry path ("data-mode=dry") asks the wallet for its address only. It never signs, never
//   calls the relayer and never shows a deposit address.
// - A deposit address is shown only after checkLiveQuote() passes on the live answer.
// - Text goes into the page with textContent only, inside a shadow root (open: the page could reach it anyway, A1P-09). The widget
//   listens to no postMessage and refuses live payments inside a frame.
// - The merchant page chooses payee, item and price (data attributes). A compromised page
//   can change them; the buyer sees them, the gate account and the mandate hash before
//   signing, and the same hash next to the deposit address (A1P-09, M5-5).
import { canonicalize, hashHex, validateMandate, verifySignedMandate, toBytes, type Mandate } from "@sampan/mandate";
import {
  checkLiveQuote, directOrder, gateHoldsMandate, gateMandate, nearAccountExists, quoteRequest, requestQuote, toChecksumEvm, ORIGIN_ASSETS, SETTLEMENT_MARGIN_MS, PaymentError, type MandateRef,
} from "@sampan/payments";
import { bytesToHex } from "@noble/hashes/utils.js";
import { WIDGET_CSS } from "./style.ts";

type Eth = { request(a: { method: string; params?: unknown[] }): Promise<unknown> };
const ORIGIN_ASSET = Object.keys(ORIGIN_ASSETS)[0]!;
const QUOTE_MS = 60 * 60_000;
const LIFETIME_MS = QUOTE_MS + SETTLEMENT_MARGIN_MS + 30 * 60_000; // 2 hours

function config(el: HTMLScriptElement) {
  const d = el.dataset;
  const need = (k: string) => {
    const v = d[k];
    if (!v) throw new Error(`data-${k} is missing`);
    return v;
  };
  const network = need("network");
  if (network !== "testnet" && network !== "mainnet") throw new Error("data-network must be testnet or mainnet");
  const live = d.mode === "live";
  // M5-02 (accepted, option A): a script on the merchant page can swap the deposit address, so live
  // payments stay on testnet until the checkout runs in an isolated, Sampan-hosted frame.
  if (live && network !== "testnet") throw new Error("live payments on mainnet are not enabled in this widget yet");
  const relayer = d.relayer ?? "";
  // A live checkout must name the Sampan relayer: https, or loopback for local testing.
  if (live && !/^(https:\/\/[a-z0-9.-]+(:\d+)?|http:\/\/(127\.0\.0\.1|localhost)(:\d+)?)$/.test(relayer)) throw new Error("data-relayer must be an https URL");
  return {
    network, gate: need("gate"), asset: need("asset"), payee: need("payee"), item: need("item"), price: need("price"),
    label: d.label ?? need("item"), relayer, live,
  } as const;
}

function randomHex32(): string {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return bytesToHex(b);
}

/** Build and validate the mandate the buyer will see and sign. */
export function buildMandate(c: ReturnType<typeof config>, evmAddress: string, nowMs: number): MandateRef {
  const addr = evmAddress.toLowerCase();
  const mandate: Mandate = {
    v: "sampan.mandate.v1", network: c.network, gate: c.gate, buyer: `evm:${addr}`, agent: null, asset: c.asset,
    max_amount: c.price, payee: c.payee, items: [c.item], expiry_ns: String(BigInt(nowMs + LIFETIME_MS) * 1_000_000n),
    nonce: randomHex32(), refund_to: addr,
  };
  validateMandate(JSON.parse(canonicalize(mandate)));
  return { mandate, mandateHash: hashHex(canonicalize(mandate)) };
}

function ui(root: ShadowRoot) {
  const box = document.createElement("div");
  box.className = "box";
  root.append(box);
  const line = (label: string, value: string, id?: string) => {
    const p = document.createElement("p");
    const b = document.createElement("b");
    b.textContent = label + ": ";
    const s = document.createElement("span");
    s.textContent = value;
    if (id) s.dataset.id = id;
    p.append(b, s);
    box.append(p);
  };
  const say = (text: string, id = "status") => {
    let p = box.querySelector<HTMLElement>(`[data-id="${id}"]`);
    if (!p) {
      p = document.createElement("p");
      p.dataset.id = id;
      box.append(p);
    }
    p.textContent = text;
  };
  const button = (text: string, id: string) => {
    const b = document.createElement("button");
    b.textContent = text;
    b.dataset.id = id;
    box.append(b);
    return b;
  };
  return { box, line, say, button };
}

/** The exact signed amount in USDC (6 decimals), never rounded (M5-04). */
const units = (price: string) => {
  const p = price.padStart(7, "0");
  return `${p.slice(0, -6)}.${p.slice(-6)} USDC`;
};

/** Relayer answers mapped to fixed messages; its own text is never shown (M5-10). */
const RELAYER_REASONS: Record<string, string> = {
  rate_limited: "too many requests; try again later", busy: "the checkout is busy; try again later",
  refund_account_missing: "your NEAR refund account does not exist", unknown_payee: "this shop is not set up", price_too_high: "the price is above the checkout limit",
};
async function register(relayer: string, signedText: string): Promise<{ registered?: boolean; mandate_hash?: string; reason?: string }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 20_000);
  try {
    const r = await fetch(`${relayer}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ signed_mandate: signedText }), signal: ctrl.signal });
    const text = await r.text();
    if (text.length > 4096) return {};
    return JSON.parse(text);
  } catch {
    return {};
  } finally {
    clearTimeout(timer);
  }
}

async function run(script: HTMLScriptElement) {
  const host = document.getElementById("sampan-checkout");
  if (!host) return;
  const root = host.attachShadow({ mode: "open" });
  const style = document.createElement("style");
  style.textContent = WIDGET_CSS;
  root.append(style);
  const u = ui(root);
  let c: ReturnType<typeof config>;
  try {
    c = config(script);
  } catch (e) {
    u.say(`Checkout not available: ${(e as Error).message}`);
    return;
  }
  const framed = window.top !== window.self;
  const eth = (window as unknown as { ethereum?: Eth }).ethereum;
  const start = u.button(c.live ? "Pay with Sampan" : "Preview with Sampan (no payment)", "start");
  start.addEventListener("click", async () => {
    start.disabled = true;
    try {
      if (c.live && framed) throw new PaymentError("framed", "Open this shop in its own tab to pay.");
      if (!eth) throw new PaymentError("wallet", "No EVM wallet found.");
      const accounts = (await eth.request({ method: "eth_requestAccounts" })) as string[];
      const raw = accounts?.[0];
      if (typeof raw !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(raw)) throw new PaymentError("wallet", "The wallet gave no address.");
      // Wallets often return lower case; 1Click's refund address must carry its checksum.
      const account = toChecksumEvm(raw);
      const ref = buildMandate(c, account, Date.now());
      const m = ref.mandate;
      // M5-5: everything that decides where the money goes, before any signature.
      u.line("Item", `${c.label} (${c.item})`, "item");
      u.line("Price", units(m.max_amount), "price");
      u.line("Paid to", m.payee, "payee");
      u.line("Through the gate", `${m.gate} (${m.network})`, "gate");
      u.line("Refund on NEAR to", m.refund_to, "refund_to");
      u.line("Refund on Base to", account, "refund_origin");
      u.line("Offer ends", new Date(Number(BigInt(m.expiry_ns) / 1_000_000n)).toISOString(), "expiry");
      u.line("Mandate", ref.mandateHash, "mandate_hash");
      const order = directOrder(ref, { orderId: randomHex32(), item: c.item });
      const params = { verified: ref, orderText: order, originAsset: ORIGIN_ASSET, refundTo: account, deadlineMs: Date.now() + QUOTE_MS };
      if (!c.live) {
        const preview = await requestQuote(quoteRequest(params, true), fetch.bind(window));
        u.line("You would send about", `${String((preview.quote as { amountInFormatted?: unknown })?.amountInFormatted ?? "?").slice(0, 20)} USDC on Base`, "preview_in");
        u.say("Preview only: nothing was signed and nothing can be paid.");
        return;
      }
      // M5-7 / M5-07: the NEAR refund account must exist before the buyer signs.
      if (!(await nearAccountExists(m.network, m.refund_to, fetch.bind(window)))) {
        throw new PaymentError("refund_account_missing", `Your NEAR refund account ${m.refund_to} does not exist yet. Create it first; nothing was signed.`);
      }
      // Live: the buyer signs exactly the mandate shown above (ERC-191 personal_sign).
      const message = canonicalize(m);
      const sigHex = String(await eth.request({ method: "personal_sign", params: [`0x${bytesToHex(new TextEncoder().encode(message))}`, account] }));
      const signature = sigHex.replace(/^0x/, "").toLowerCase();
      const signedText = canonicalize({ v: "sampan.signed-mandate.v1", mandate: m, standard: "erc191", signature });
      const verified = verifySignedMandate(toBytes(signedText));
      if (verified.mandateHash !== ref.mandateHash || canonicalize(verified.mandate) !== message) throw new PaymentError("signed_differs", "The signed mandate is not the one shown.");
      const regBody = await register(c.relayer, signedText);
      if (regBody.registered !== true || regBody.mandate_hash !== ref.mandateHash) {
        throw new PaymentError("not_registered", `Sampan could not register the mandate (${RELAYER_REASONS[String(regBody.reason)] ?? "refused"}).`);
      }
      // M5-01: the gate itself must hold exactly this mandate before any deposit address is shown.
      if (!gateHoldsMandate(await gateMandate(m.network, m.gate, ref.mandateHash, fetch.bind(window)), ref)) {
        throw new PaymentError("not_registered", "The gate does not hold this mandate. Do not pay.");
      }
      const sent = quoteRequest({ ...params, verified }, false);
      const live = await requestQuote(sent, fetch.bind(window));
      const problems = checkLiveQuote(sent, live, verified);
      if (problems.length) throw new PaymentError("quote_mismatch", `The quote does not match the mandate (${problems[0]}). Do not pay.`);
      const q = live.quote as { depositAddress: string; amountIn: string; deadline: string };
      u.line("Send exactly", `${units(q.amountIn)} on Base`, "amount_in");
      u.line("To deposit address", q.depositAddress, "deposit_address");
      u.line("Before", q.deadline, "deadline");
      u.line("For mandate", verified.mandateHash, "deposit_mandate_hash");
      // M5-3: keep the full quote answer (signature not verified, A1P-09) for disputes.
      const record = document.createElement("a");
      record.textContent = "Save the payment record";
      record.download = `sampan-${verified.mandateHash.slice(0, 12)}.json`;
      record.href = URL.createObjectURL(new Blob([JSON.stringify({ signed_mandate: signedText, order, quote: live, quote_signature_verified: false }, null, 2)], { type: "application/json" }));
      u.box.append(record);
      u.say("Pay from your wallet. The gate pays the shop only this exact order, once.");
    } catch (e) {
      u.say(e instanceof PaymentError ? e.message : "Something went wrong; nothing was paid.");
    }
  });
}

const me = document.currentScript;
if (me instanceof HTMLScriptElement) void run(me);
