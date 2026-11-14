// Checker page. All text goes into the page with textContent; nothing from a receipt or an
// RPC answer is ever parsed as HTML.
import { verifyReceipt, receiptFromFragment, type Result, type Status } from "./verify.ts";
import { ALLOWED_RPC_HOSTS, DEFAULT_RPC } from "./rpc.ts";

const MAX_FILE = 1_000_000;
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

// Inside another page's frame the result could be covered or restyled by that page: refuse
// to check there and offer to open the checker on its own (M6-09).
const framed = (() => { try { return window.top !== window.self; } catch { return true; } })();

const receipt = $<HTMLTextAreaElement>("receipt"), rpc = $<HTMLInputElement>("rpc"), rpc2 = $<HTMLInputElement>("rpc2");
let rpcEdited = false;
rpc.value = DEFAULT_RPC.testnet;
rpc.addEventListener("input", () => { rpcEdited = true; invalidate(); });
rpc2.addEventListener("input", () => invalidate());
$("allowed").textContent = `Allowed RPC hosts: ${ALLOWED_RPC_HOSTS.join(", ")}. This page cannot contact anything else.`;

/** The bytes being checked: exactly what was opened (file or link), or the text box. */
let pendingBytes: Uint8Array | null = null;
/** Each check gets a number; only the latest may paint a verdict (M6-04). */
let runId = 0;

function el(tag: string, text?: string, cls?: string): HTMLElement {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
const LABEL: Record<Status, string> = { pass: "Checked", fail: "Failed", unknown: "Cannot verify" };
const VERDICT = {
  verified: ["pass", "Verified: this payment matches what the buyer approved.", "Every check below passed."],
  invalid: ["fail", "Not valid: this receipt does not match.", "At least one check failed. Do not rely on this receipt."],
  unverifiable: ["unknown", "Cannot verify this receipt right now.", "Some checks could not be completed. This is not a confirmation."],
} as const;

/** Hide any shown verdict: it belonged to what was on screen before (M6-04). */
function invalidate(): void {
  runId++;
  $("result").hidden = true;
}

function render(r: Result, hosts: string[]): void {
  let [cls, title, sub]: readonly string[] = VERDICT[r.overall];
  const verified = r.overall === "verified";
  // A verified refusal is not a payment: say what was verified (M6-CR9).
  if (verified && r.facts?.decision === "refuse") {
    title = "Verified: the gate refused this order, and no money moved.";
    sub = "The refusal is recorded on the NEAR blockchain exactly as this receipt says.";
  }
  // Say whose answers the result rests on (M6-11).
  if (verified) {
    sub += hosts.length > 1
      ? ` The answers came from ${hosts.join(" and ")}, which agree.`
      : ` The answers came from one NEAR RPC, ${hosts[0]}. Add a second RPC run by someone else to cross-check.`;
  }
  const v = $("verdict");
  v.className = `verdict ${cls}`;
  v.replaceChildren(el("span", title), el("small", sub));
  const facts = $("facts");
  facts.replaceChildren();
  if (r.facts) {
    const f = r.facts;
    const paid = f.decision === "release";
    // Only a verified receipt states facts; otherwise they are what the receipt claims (M6-05).
    // Refusals: nobody was paid, so the order's payee and amount are labelled as requested (M6-CR5).
    const rows: [string, string][] = !verified
      ? [
          ["The receipt claims", paid ? "a payment (not confirmed)" : "a refusal (not confirmed)"],
          ["Amount in the receipt", `${f.amount} units`], ["Token in the receipt", f.asset], ["Payee in the receipt", f.payee],
          ["Item", f.item], ["Buyer", f.buyer], ["Network", f.network], ["Gate contract", f.gate], ["Order ID", f.orderId],
        ]
      : [
          ["Decision", paid ? "Paid" : "Refused, no money moved"],
          ...(paid ? [] : [["Why refused", f.refusedBecause.join("; ")] as [string, string]]),
          [paid ? "Amount paid" : "Amount requested", `${f.amount} units`], ["Token", f.asset],
          [paid ? "Paid to" : "Payee in the order", f.payee], ["Item", f.item], ["Buyer", f.buyer], ["Agent", f.agent ?? "none (the buyer paid directly)"],
          ["Network", f.network], ["Gate contract", f.gate], ["Order ID", f.orderId],
        ];
    for (const [k, val] of rows) facts.append(el("dt", k), el("dd", val));
  }
  $("checks").replaceChildren(...r.checks.map((c) => {
    const li = el("li", undefined, c.status);
    li.append(el("span", LABEL[c.status], "state"), el("strong", c.title), el("p", c.detail));
    return li;
  }));
  const note = r.facts?.agentNote ?? null;
  $("note").hidden = note === null;
  $("note-text").textContent = note ?? "";
  $("result").hidden = false;
}

async function run(): Promise<void> {
  const id = ++runId;
  // Check exactly the bytes that were opened; the text box is used only when typed or pasted (M6-14).
  const bytes = pendingBytes ?? new TextEncoder().encode(receipt.value);
  if (!rpcEdited) {
    try { const n = JSON.parse(receipt.value)?.core?.network; if (n === "mainnet" || n === "testnet") rpc.value = DEFAULT_RPC[n]; } catch { /* the checker reports it */ }
  }
  const hosts = [rpc.value, rpc2.value].map((u) => { try { return new URL(u.trim()).hostname; } catch { return ""; } }).filter(Boolean);
  $<HTMLButtonElement>("check").disabled = true;
  let r: Result;
  try {
    r = await verifyReceipt(bytes, {
      rpcUrl: rpc.value.trim(), secondRpcUrl: rpc2.value.trim() || undefined,
      fetchFn: (url, init) => fetch(url, { ...init, credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store" }),
    });
  } catch {
    // Never leave the viewer without a verdict (M6-CR4).
    r = { overall: "unverifiable", facts: null, checks: [{ id: "error", title: "The check could not be completed", status: "unknown", detail: "Something unexpected went wrong. This is not a confirmation; try again or use another RPC." }] };
  } finally {
    if (id === runId) $<HTMLButtonElement>("check").disabled = false;
  }
  if (id === runId) render(r, hosts); // a newer check or an edit has replaced this one
}

if (framed) {
  $("check").setAttribute("disabled", "");
  const main = document.querySelector("main") as HTMLElement;
  main.replaceChildren(el("h1", "Open this checker in its own tab"), el("p", "The receipt checker does not run inside another page, because that page could cover or change the result."));
} else {
  $("check").addEventListener("click", () => { void run(); });
  receipt.addEventListener("input", () => { pendingBytes = null; invalidate(); });
  $<HTMLInputElement>("file").addEventListener("change", (ev) => {
    invalidate();
    const file = (ev.target as HTMLInputElement).files?.[0];
    if (!file) return;
    if (file.size > MAX_FILE) {
      receipt.value = "";
      pendingBytes = null;
      render({ overall: "invalid", facts: null, checks: [{ id: "file", title: "The receipt file is complete and consistent", status: "fail", detail: "The file is larger than 1 MB." }] }, []);
      return;
    }
    const id = runId;
    void file.arrayBuffer().then((buf) => {
      if (id !== runId) return; // another file or an edit came first
      pendingBytes = new Uint8Array(buf);
      receipt.value = new TextDecoder().decode(pendingBytes); // display only
      return run();
    });
  });
  const fromLink = receiptFromFragment(location.hash);
  if (fromLink) { pendingBytes = fromLink; receipt.value = new TextDecoder().decode(fromLink); void run(); }
}
