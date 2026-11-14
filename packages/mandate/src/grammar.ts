// Value grammars (docs/FORMATS.md section 2). All values are ASCII strings.
import { base58 } from "@scure/base";
import { FormatError } from "./errors.ts";
import type { Json } from "./canonical.ts";
import { isAcceptablePoint } from "./ed25519-guard.ts";

const ACCOUNT = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;
const DECIMAL_POS = /^[1-9][0-9]*$/;
const HEX32 = /^[0-9a-f]{64}$/;
const ITEM = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const EVM = /^evm:0x[0-9a-f]{40}$/;
const NEAR_ED = /^near:ed25519:([1-9A-HJ-NP-Za-km-z]{32,44})$/;
const B58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

export const U128_MAX = (1n << 128n) - 1n;
export const U64_MAX = (1n << 64n) - 1n;

const fail = (field: string, why: string): never => {
  throw new FormatError("schema", `${field}: ${why}`);
};

export function str(v: Json | undefined, field: string): string {
  if (typeof v !== "string") fail(field, "must be a string");
  return v as string;
}

export function account(v: Json | undefined, field: string): string {
  const s = str(v, field);
  if (s.length < 2 || s.length > 64 || !ACCOUNT.test(s)) fail(field, "not a valid NEAR account ID");
  return s;
}

function decimal(v: Json | undefined, field: string, max: bigint, maxDigits: number): string {
  const s = str(v, field);
  if (s.length > maxDigits || !DECIMAL_POS.test(s)) fail(field, "must be a positive decimal string without leading zeros");
  if (BigInt(s) > max) fail(field, "out of range");
  return s;
}

export const amount = (v: Json | undefined, field: string) => decimal(v, field, U128_MAX, 39);
export const u64 = (v: Json | undefined, field: string) => decimal(v, field, U64_MAX, 20);

export function hex32(v: Json | undefined, field: string): string {
  const s = str(v, field);
  if (!HEX32.test(s)) fail(field, "must be 64 lowercase hex characters");
  return s;
}

export function itemId(v: Json | undefined, field: string): string {
  const s = str(v, field);
  if (!ITEM.test(s)) fail(field, "not a valid item ID");
  return s;
}

export function network(v: Json | undefined, field: string): "testnet" | "mainnet" {
  const s = str(v, field);
  if (s !== "testnet" && s !== "mainnet") fail(field, "must be testnet or mainnet");
  return s as "testnet" | "mainnet";
}

export type Buyer = { kind: "near"; publicKey: Uint8Array } | { kind: "evm"; address: string };

export function buyer(v: Json | undefined, field: string): { text: string; parsed: Buyer } {
  const s = str(v, field);
  if (EVM.test(s)) return { text: s, parsed: { kind: "evm", address: s.slice(4) } };
  const m = NEAR_ED.exec(s);
  if (m) {
    let pk: Uint8Array;
    try {
      pk = base58.decode(m[1]);
    } catch {
      return fail(field, "invalid base58");
    }
    if (pk.length !== 32) fail(field, "ed25519 public key must be 32 bytes");
    if (!isAcceptablePoint(pk)) fail(field, "ed25519 public key is small-order or non-canonical");
    // Reject non-canonical base58 (leading-zero ambiguity): re-encode must match.
    if (base58.encode(pk) !== m[1]) fail(field, "non-canonical base58");
    return { text: s, parsed: { kind: "near", publicKey: pk } };
  }
  return fail(field, "must be near:ed25519:<base58> or evm:0x<40 hex>");
}

export function txHash(v: Json | undefined, field: string): string {
  const s = str(v, field);
  if (!B58.test(s)) fail(field, "not a base58 transaction hash");
  let b: Uint8Array;
  try {
    b = base58.decode(s);
  } catch {
    return fail(field, "invalid base58");
  }
  if (b.length !== 32 || base58.encode(b) !== s) fail(field, "transaction hash must be 32 bytes");
  return s;
}

/** A plain object with exactly the given keys (closed object). */
export function closedObject(v: Json | undefined, field: string, keys: readonly string[]): Record<string, Json> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return fail(field, "must be an object");
  const got = Object.keys(v).sort();
  const want = [...keys].sort();
  if (got.length !== want.length || got.some((k, i) => k !== want[i])) {
    fail(field, `must have exactly the fields ${want.join(", ")}`);
  }
  return v as Record<string, Json>;
}

export function literal<T extends string>(v: Json | undefined, field: string, value: T): T {
  if (v !== value) fail(field, `must be "${value}"`);
  return value;
}
