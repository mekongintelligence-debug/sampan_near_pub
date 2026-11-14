// Receipt packer (M7): builds a receipt envelope from chain data only. Inputs are transaction
// hashes; every part of the envelope is read from final, successful transactions and
// cross-checked against the gate's own receipt event:
// - the decision transaction holds the gate's `receipt` event (core and core hash) and the
//   order (in `purchase` args, or in the funding message of an `ft_transfer_call` to the gate
//   through its token, as an action or as a receipt created by 1Click's contracts);
// - the registration transaction (`register_mandate`) or a funding message holds the signed
//   mandate;
// - the deposit transaction, if given, holds the gate's `funded` event for this mandate.
// Among several candidates the one that hashes to the receipt is used (audit M7-04). The
// result must parse with the checker's own envelope parser.
import { parseOrder, verifySignedMandate, toBytes, type Json } from "@sampan/mandate";
import { parseEnvelope, ENVELOPE_V1, MAX_EVENT_LOG, MAX_NOTE_CHARS, type Envelope } from "./index.ts";

/** Returns an EXPERIMENTAL_tx_status result (with `receipts`), FINAL, or null. */
export type TxFetch = (hash: string, sender: string) => Promise<any | null>;

export class PackError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}
const fail = (code: string, message: string): never => {
  throw new PackError(code, message);
};

const b64json = (s: unknown): any => {
  try {
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(String(s)), (c) => c.charCodeAt(0))));
  } catch {
    return null;
  }
};
const json = (s: unknown): any => {
  try {
    return JSON.parse(String(s));
  } catch {
    return null;
  }
};
/** A status object that is a success; anything else (Failure, "Unknown", "Started") is not (M7-07). */
const succeeded = (status: unknown) => !!status && typeof status === "object" && !("Failure" in (status as object));
const finalOk = (tx: any) => tx?.final_execution_status === "FINAL" && succeeded(tx?.status);

/** Function calls of a transaction and of every receipt it created: [receiver, method, args].
 * A 1Click delivery's `ft_transfer_call` is a receipt created by 1Click's contracts, not an
 * action of the transaction itself (M7-CR1). */
function calls(tx: any): [string, string, any][] {
  const fc = (receiver: string, actions: any[]) =>
    (Array.isArray(actions) ? actions : []).map((a: any) => a?.FunctionCall).filter(Boolean).map((f: any) => [receiver, f.method_name, b64json(f.args)] as [string, string, any]);
  return [
    ...fc(tx?.transaction?.receiver_id, tx?.transaction?.actions),
    ...(Array.isArray(tx?.receipts) ? tx.receipts : []).flatMap((r: any) => fc(r?.receiver_id, r?.receipt?.Action?.actions)),
  ];
}

/** Events the gate emitted in successful receipts of `tx`. */
export function gateEvents(tx: any, gate: string, kind: string): any[] {
  const out: any[] = [];
  for (const r of Array.isArray(tx?.receipts_outcome) ? tx.receipts_outcome : []) {
    const o = r?.outcome;
    if (o?.executor_id !== gate || !succeeded(o?.status)) continue;
    for (const log of Array.isArray(o.logs) ? o.logs : []) {
      if (typeof log !== "string" || !log.startsWith("EVENT_JSON:") || log.length > MAX_EVENT_LOG) continue;
      const ev = json(log.slice(11));
      if (ev?.standard === "sampan" && ev.event === kind && Array.isArray(ev.data)) out.push(...ev.data);
    }
  }
  return out;
}

/** Every order text the decision transaction carries (purchase args, funding messages to the gate). */
function ordersIn(tx: any, token: string | null, gate: string): string[] {
  const out: string[] = [];
  for (const [receiver, method, args] of calls(tx)) {
    if (method === "purchase" && typeof args?.order === "string") out.push(args.order);
    if (method === "ft_transfer_call" && (token === null || receiver === token) && args?.receiver_id === gate) {
      const msg = json(args?.msg);
      if (typeof msg?.order === "string") out.push(msg.order);
    }
  }
  return out;
}

/** Every signed mandate text a registration or funding transaction carries. */
function mandatesIn(tx: any): string[] {
  const out: string[] = [];
  for (const [, method, args] of calls(tx)) {
    if (method === "register_mandate" && typeof args?.signed_mandate === "string") out.push(args.signed_mandate);
    if (method === "ft_transfer_call") {
      const msg = json(args?.msg);
      if (typeof msg?.signed_mandate === "string") out.push(msg.signed_mandate);
    }
  }
  return out;
}

export interface PackInput {
  gate: string;
  /** Settlement token of the gate (from get_config); orders in funding messages must go through it. */
  token: string | null;
  decisionTx: string;
  /** register_mandate, or a funding transaction that carried the signed mandate. */
  mandateTx: string;
  /** A transaction holding the gate's `funded` event for this mandate (checked, M7-01). */
  depositTx?: string | null;
  /** Which decision to pack when the transaction holds several (M7-05). */
  orderId?: string | null;
  note?: string | null;
}

/** Build and cross-check a receipt envelope. */
export async function packReceipt(input: PackInput, fetchTx: TxFetch): Promise<Envelope & { text: string }> {
  const dtx = (await fetchTx(input.decisionTx, input.gate)) ?? fail("no_decision_tx", "the decision transaction was not found");
  if (dtx?.final_execution_status !== "FINAL") fail("not_final", "the decision transaction is not final");
  // M7-02: the transaction read must be the one named.
  if (dtx?.transaction?.hash !== undefined && dtx.transaction.hash !== input.decisionTx) fail("wrong_tx", "the RPC returned another transaction");
  // M7-03: only events executed by the gate, for a core that names this gate.
  const events = gateEvents(dtx, input.gate, "receipt").filter((e) => e?.core?.gate === input.gate);
  // M7-05: several decisions in one transaction are packed one at a time, chosen by order ID.
  const chosen = input.orderId ? events.filter((e) => e?.order_id === input.orderId) : events;
  if (chosen.length === 0) fail("no_receipt_event", `no receipt event from ${input.gate} for this gate${input.orderId ? " and order" : ""}`);
  if (chosen.length > 1) fail("several_decisions", "the transaction holds several decisions; name the order ID");
  const ev = chosen[0];
  // M7-04: the order that hashes to the receipt, wherever it appears.
  let orderText: string | null = null;
  for (const t of ordersIn(dtx, input.token, input.gate)) {
    try {
      if (parseOrder(toBytes(t)).hash === ev.core?.order_hash) {
        orderText = t;
        break;
      }
    } catch {
      /* not an order */
    }
  }
  if (orderText === null) fail(ordersIn(dtx, input.token, input.gate).length ? "order_mismatch" : "no_order", "the decision transaction carries no order matching the receipt");
  const order = parseOrder(toBytes(orderText as string)).order;
  const mtx = (await fetchTx(input.mandateTx, input.gate)) ?? fail("no_mandate_tx", "the mandate transaction was not found");
  if (!finalOk(mtx)) fail("mandate_tx_failed", "the mandate transaction is not final or failed");
  let signedText: string | null = null;
  for (const t of mandatesIn(mtx)) {
    try {
      if (verifySignedMandate(toBytes(t)).mandateHash === ev.core?.mandate_hash) {
        signedText = t;
        break;
      }
    } catch {
      /* not a valid signed mandate */
    }
  }
  if (signedText === null) fail(mandatesIn(mtx).length ? "mandate_mismatch" : "no_mandate", "the mandate transaction carries no signed mandate matching the receipt");
  if (order.mandate_hash !== ev.core?.mandate_hash) fail("mandate_mismatch", "the order names another mandate");
  // M7-01: the deposit transaction must be final, successful and hold this mandate's funding.
  if (input.depositTx) {
    const ftx = (await fetchTx(input.depositTx, input.gate)) ?? fail("no_deposit_tx", "the deposit transaction was not found");
    if (!finalOk(ftx)) fail("deposit_tx_failed", "the deposit transaction is not final or failed");
    if (!gateEvents(ftx, input.gate, "funded").some((f) => f?.mandate_hash === ev.core?.mandate_hash)) fail("deposit_mismatch", "the deposit transaction did not fund this mandate");
  }
  // A release pays out in the decision transaction's receipts: a completed payout for this
  // mandate and order makes the decision transaction also the payout transaction (M7-06).
  const paid = gateEvents(dtx, input.gate, "payout").some((p) => p?.order_id === ev.order_id && p?.mandate_hash === ev.core?.mandate_hash && p?.status === "done");
  if (input.note != null && (typeof input.note !== "string" || [...input.note].length > MAX_NOTE_CHARS)) fail("note", "the note is too long");
  const env = {
    v: ENVELOPE_V1, core: ev.core as Json, core_hash: ev.core_hash, signed_mandate: JSON.parse(signedText as string), order: JSON.parse(orderText as string),
    tx: { deposit: input.depositTx ?? null, decision: input.decisionTx, payout: paid ? input.decisionTx : null },
    untrusted: input.note ? { agent_note: input.note } : null,
  };
  const text = JSON.stringify(env);
  let parsed: Envelope;
  try {
    parsed = parseEnvelope(toBytes(text)); // the checker's own parser (also checks core_hash)
  } catch (e) {
    return fail("envelope_invalid", `the chain data does not form a valid receipt (${(e as Error).message.slice(0, 120)})`);
  }
  return { ...parsed, text };
}
