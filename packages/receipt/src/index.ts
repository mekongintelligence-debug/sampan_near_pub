// Receipt core and envelope (docs/FORMATS.md sections 6-7).
import {
  parseCanonical, canonicalize, hashHex, FormatError, grammar as g, validateOrder,
  verifySignedMandate, toBytes, rejectNumbers, depthOf, MAX_DEPTH, type Json, type Order, type VerifiedMandate,
} from "@sampan/mandate";

export const RECEIPT_V1 = "sampan.receipt.v1";
export const ENVELOPE_V1 = "sampan.receipt-envelope.v1";
export const MAX_RECEIPT_BYTES = 4096;
export const MAX_ENVELOPE_BYTES = 16384;
export const MAX_NOTE_CHARS = 280;
/** Longest gate event log the packer and the checker read. */
export const MAX_EVENT_LOG = 16_384;
export const RULE_IDS = ["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"] as const;

const CORE_KEYS = ["v", "network", "gate", "mandate_hash", "order_hash", "observed", "rules", "decision", "block_height"] as const;
const ENVELOPE_KEYS = ["v", "core", "core_hash", "signed_mandate", "order", "tx", "untrusted"] as const;

export interface ReceiptCore {
  v: typeof RECEIPT_V1;
  network: "testnet" | "mainnet";
  gate: string;
  mandate_hash: string;
  order_hash: string;
  observed: { amount: string; asset: string };
  rules: { id: (typeof RULE_IDS)[number]; pass: boolean }[];
  decision: "release" | "refuse";
  block_height: string;
}

export function validateCore(v: Json | undefined, field = "core"): ReceiptCore {
  const o = g.closedObject(v, field, CORE_KEYS);
  const observed = g.closedObject(o.observed, `${field}.observed`, ["amount", "asset"]);
  if (!Array.isArray(o.rules) || o.rules.length !== RULE_IDS.length) {
    throw new FormatError("schema", `${field}.rules: must list ${RULE_IDS.join(", ")} in order`);
  }
  const rules = o.rules.map((r, i) => {
    const ro = g.closedObject(r, `${field}.rules[${i}]`, ["id", "pass"]);
    if (ro.id !== RULE_IDS[i]) throw new FormatError("schema", `${field}.rules[${i}].id: must be ${RULE_IDS[i]}`);
    if (typeof ro.pass !== "boolean") throw new FormatError("schema", `${field}.rules[${i}].pass: must be true or false`);
    return { id: RULE_IDS[i], pass: ro.pass };
  });
  const decision = g.str(o.decision, `${field}.decision`);
  if (decision !== "release" && decision !== "refuse") throw new FormatError("schema", `${field}.decision: must be release or refuse`);
  const allPass = rules.every((r) => r.pass);
  if ((decision === "release") !== allPass) {
    throw new FormatError("inconsistent", "decision must be release if and only if every rule passes");
  }
  return {
    v: g.literal(o.v, `${field}.v`, RECEIPT_V1),
    network: g.network(o.network, `${field}.network`),
    gate: g.account(o.gate, `${field}.gate`),
    mandate_hash: g.hex32(o.mandate_hash, `${field}.mandate_hash`),
    order_hash: g.hex32(o.order_hash, `${field}.order_hash`),
    observed: { amount: g.amount(observed.amount, `${field}.observed.amount`), asset: g.account(observed.asset, `${field}.observed.asset`) },
    rules,
    decision,
    block_height: g.u64(o.block_height, `${field}.block_height`),
  };
}

/** Parse a canonical receipt core. */
export function parseReceiptCore(bytes: Uint8Array): { core: ReceiptCore; hash: string } {
  const { value, text } = parseCanonical(bytes, MAX_RECEIPT_BYTES);
  return { core: validateCore(value), hash: hashHex(text) };
}

export interface Envelope {
  core: ReceiptCore;
  coreHash: string;
  signed: VerifiedMandate;
  order: Order;
  orderHash: string;
  tx: { deposit: string | null; decision: string; payout: string | null };
  agentNote: string | null; // untrusted: display as plain text only
}

/**
 * Parse a receipt envelope (ordinary JSON, not required to be canonical) and check
 * that its parts agree with each other. Chain checks happen in the checker (M6).
 */
export function parseEnvelope(bytes: Uint8Array): Envelope {
  if (bytes.length > MAX_ENVELOPE_BYTES) throw new FormatError("too_large", `${bytes.length} > ${MAX_ENVELOPE_BYTES} bytes`);
  let text: string;
  try {
    // ignoreBOM: keep a byte order mark so JSON.parse rejects it, as for every other document (M2-07).
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new FormatError("invalid_json", "not valid UTF-8");
  }
  // Same pre-parse limits as every other document (review finding M2-CR3).
  rejectNumbers(text);
  let value: Json;
  try {
    value = JSON.parse(text) as Json;
  } catch {
    throw new FormatError("invalid_json", "not valid JSON");
  }
  if (depthOf(value) > MAX_DEPTH) throw new FormatError("invalid_json", `nesting deeper than ${MAX_DEPTH}`);
  const o = g.closedObject(value, "envelope", ENVELOPE_KEYS);
  g.literal(o.v, "envelope.v", ENVELOPE_V1);
  const core = validateCore(o.core, "envelope.core");
  const coreHash = g.hex32(o.core_hash, "envelope.core_hash");
  if (hashHex(canonicalize(core)) !== coreHash) throw new FormatError("inconsistent", "core_hash does not match core");
  const signed = verifySignedMandate(toBytes(canonicalize(o.signed_mandate)));
  const order = validateOrder(o.order, "envelope.order");
  const orderHash = hashHex(canonicalize(order));
  if (core.mandate_hash !== signed.mandateHash) throw new FormatError("inconsistent", "core.mandate_hash does not match the signed mandate");
  if (core.order_hash !== orderHash) throw new FormatError("inconsistent", "core.order_hash does not match the order");
  if (order.mandate_hash !== signed.mandateHash) throw new FormatError("inconsistent", "order.mandate_hash does not match the signed mandate");
  if (core.network !== signed.mandate.network || core.gate !== signed.mandate.gate) {
    throw new FormatError("inconsistent", "core network or gate does not match the mandate");
  }
  // The order must agree with the signed mandate wherever the result does not depend on
  // gate state (audit M2-03): observed values, asset (R6), payee (R8), item (R9) are pure;
  // the budget part of R7 can only be checked as amount <= max_amount.
  const m = signed.mandate;
  // What the gate observed (M3): it always holds the mandate's asset, and it reserves the
  // order amount, or its whole smaller escrow. So: R6 passed -> observed asset is the
  // order's; R7 passed -> observed amount is the order's; otherwise observed asset is the
  // mandate's and the observed amount is at most the order's (finding M3-X1).
  const pass = Object.fromEntries(core.rules.map((r) => [r.id, r.pass]));
  if (core.observed.asset !== (pass.R6 ? order.asset : m.asset)) {
    throw new FormatError("inconsistent", "observed asset differs from the order or mandate");
  }
  // R7 fails only when the order exceeds the escrow (escrow <= remaining budget always
  // holds), and the gate then observes the whole, strictly smaller escrow (M3-09).
  if (pass.R7 ? core.observed.amount !== order.amount : BigInt(core.observed.amount) >= BigInt(order.amount)) {
    throw new FormatError("inconsistent", "observed amount differs from the order");
  }
  // The gate checks R1 and R2 at funding and R4 and R5 before writing anything, so an
  // anchored core never records them as failed (M3-09).
  for (const id of ["R1", "R2", "R4", "R5"]) {
    if (!pass[id]) throw new FormatError("inconsistent", `${id} cannot fail in an anchored receipt`);
  }
  const pure: Record<string, boolean> = { R6: order.asset === m.asset, R8: order.payee === m.payee, R9: m.items.includes(order.item) };
  for (const r of core.rules) {
    if (r.id in pure && r.pass !== pure[r.id]) throw new FormatError("inconsistent", `${r.id} result contradicts the order and mandate`);
    if (r.id === "R7" && r.pass && BigInt(order.amount) > BigInt(m.max_amount)) throw new FormatError("inconsistent", "R7 passed although the amount exceeds max_amount");
  }
  const tx = g.closedObject(o.tx, "envelope.tx", ["deposit", "decision", "payout"]);
  const optTx = (x: Json | undefined, f: string) => (x === null ? null : g.txHash(x, f));
  let agentNote: string | null = null;
  if (o.untrusted !== null) {
    const u = g.closedObject(o.untrusted, "envelope.untrusted", ["agent_note"]);
    const note = g.str(u.agent_note, "envelope.untrusted.agent_note");
    if ([...note].length > MAX_NOTE_CHARS) throw new FormatError("schema", `envelope.untrusted.agent_note: at most ${MAX_NOTE_CHARS} characters`);
    // No control characters, bidirectional overrides or lone surrogates (M2-08).
    if (!note.isWellFormed() || /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/.test(note)) {
      throw new FormatError("schema", "envelope.untrusted.agent_note: control, bidirectional or invalid characters");
    }
    agentNote = note;
  }
  return {
    core, coreHash, signed, order, orderHash,
    tx: { deposit: optTx(tx.deposit, "envelope.tx.deposit"), decision: g.txHash(tx.decision, "envelope.tx.decision"), payout: optTx(tx.payout, "envelope.tx.payout") },
    agentNote,
  };
}
