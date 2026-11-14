// Mandate, signed mandate and order (docs/FORMATS.md sections 3-5).
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { parseCanonical, canonicalize, toBytes, type Json } from "./canonical.ts";
import { FormatError } from "./errors.ts";
import * as g from "./grammar.ts";
import { verifyNep413, verifyErc191 } from "./signing.ts";

export const MAX_DOC_BYTES = 4096;
export const MAX_ITEMS = 16;

export const MANDATE_V1 = "sampan.mandate.v1";
export const SIGNED_MANDATE_V1 = "sampan.signed-mandate.v1";
export const ORDER_V1 = "sampan.order.v1";

const MANDATE_KEYS = ["v", "network", "gate", "buyer", "agent", "asset", "max_amount", "payee", "items", "expiry_ns", "nonce", "refund_to"] as const;
const SIGNED_KEYS = ["v", "mandate", "standard", "signature"] as const;
const ORDER_KEYS = ["v", "order_id", "mandate_hash", "item", "amount", "asset", "payee"] as const;

export interface Mandate {
  v: typeof MANDATE_V1;
  network: "testnet" | "mainnet";
  gate: string;
  buyer: string;
  agent: string | null;
  asset: string;
  max_amount: string;
  payee: string;
  items: string[];
  expiry_ns: string;
  nonce: string;
  refund_to: string;
}

export interface Order {
  v: typeof ORDER_V1;
  order_id: string;
  mandate_hash: string;
  item: string;
  amount: string;
  asset: string;
  payee: string;
}

export const hashHex = (canonicalText: string) => bytesToHex(sha256(toBytes(canonicalText)));

/** Validate a mandate; returns it with its parsed buyer. */
export function validateMandateWithBuyer(v: Json | undefined, field = "mandate"): { mandate: Mandate; buyer: g.Buyer } {
  const o = g.closedObject(v, field, MANDATE_KEYS);
  const items = o.items;
  if (!Array.isArray(items) || items.length < 1 || items.length > MAX_ITEMS) {
    throw new FormatError("schema", `${field}.items: must hold 1 to ${MAX_ITEMS} item IDs`);
  }
  const ids = items.map((x, i) => g.itemId(x, `${field}.items[${i}]`));
  for (let i = 1; i < ids.length; i++) {
    if (!(ids[i - 1] < ids[i])) throw new FormatError("schema", `${field}.items: must be sorted ascending without duplicates`);
  }
  const buyer = g.buyer(o.buyer, `${field}.buyer`);
  const mandate: Mandate = {
    v: g.literal(o.v, `${field}.v`, MANDATE_V1),
    network: g.network(o.network, `${field}.network`),
    gate: g.account(o.gate, `${field}.gate`),
    buyer: buyer.text,
    agent: o.agent === null ? null : g.account(o.agent, `${field}.agent`),
    asset: g.account(o.asset, `${field}.asset`),
    max_amount: g.amount(o.max_amount, `${field}.max_amount`),
    payee: g.account(o.payee, `${field}.payee`),
    items: ids,
    expiry_ns: g.u64(o.expiry_ns, `${field}.expiry_ns`),
    nonce: g.hex32(o.nonce, `${field}.nonce`),
    refund_to: g.account(o.refund_to, `${field}.refund_to`),
  };
  return { mandate, buyer: buyer.parsed };
}

export function validateMandate(v: Json | undefined, field = "mandate"): Mandate {
  return validateMandateWithBuyer(v, field).mandate;
}

export function validateOrder(v: Json | undefined, field = "order"): Order {
  const o = g.closedObject(v, field, ORDER_KEYS);
  return {
    v: g.literal(o.v, `${field}.v`, ORDER_V1),
    order_id: g.hex32(o.order_id, `${field}.order_id`),
    mandate_hash: g.hex32(o.mandate_hash, `${field}.mandate_hash`),
    item: g.itemId(o.item, `${field}.item`),
    amount: g.amount(o.amount, `${field}.amount`),
    asset: g.account(o.asset, `${field}.asset`),
    payee: g.account(o.payee, `${field}.payee`),
  };
}

/** Parse a canonical mandate document. */
export function parseMandate(bytes: Uint8Array): { mandate: Mandate; hash: string } {
  const { value, text } = parseCanonical(bytes, MAX_DOC_BYTES);
  return { mandate: validateMandate(value), hash: hashHex(text) };
}

/** Parse a canonical order document. */
export function parseOrder(bytes: Uint8Array): { order: Order; hash: string } {
  const { value, text } = parseCanonical(bytes, MAX_DOC_BYTES);
  return { order: validateOrder(value), hash: hashHex(text) };
}

export interface VerifiedMandate {
  mandate: Mandate;
  mandateHash: string;
  standard: "nep413" | "erc191";
}

/** Parse a canonical signed mandate and verify its signature. Throws FormatError. */
export function verifySignedMandate(bytes: Uint8Array): VerifiedMandate {
  const { value } = parseCanonical(bytes, MAX_DOC_BYTES);
  const o = g.closedObject(value, "signed_mandate", SIGNED_KEYS);
  g.literal(o.v, "signed_mandate.v", SIGNED_MANDATE_V1);
  const { mandate, buyer } = validateMandateWithBuyer(o.mandate, "signed_mandate.mandate");
  const standard = g.str(o.standard, "signed_mandate.standard");
  const signature = g.str(o.signature, "signed_mandate.signature");
  const message = canonicalize(mandate);
  if (standard === "nep413") {
    if (buyer.kind !== "near") throw new FormatError("unsupported_standard", "nep413 needs a near:ed25519 buyer");
    verifyNep413(buyer, message, mandate.nonce, mandate.gate, signature);
  } else if (standard === "erc191") {
    if (buyer.kind !== "evm") throw new FormatError("unsupported_standard", "erc191 needs an evm buyer");
    verifyErc191(buyer, message, signature);
  } else {
    throw new FormatError("unsupported_standard", `unknown standard`);
  }
  return { mandate, mandateHash: hashHex(message), standard };
}
