// Signature payloads and verification for NEP-413 and ERC-191 (docs/FORMATS.md section 4).
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";
import { FormatError } from "./errors.ts";
import { toBytes } from "./canonical.ts";
import type { Buyer } from "./grammar.ts";
import { isAcceptablePoint, isCanonicalScalar } from "./ed25519-guard.ts";

export const NEP413_TAG = 2147484061; // 2^31 + 413

const u32le = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
};
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const borshString = (s: string) => { const b = toBytes(s); return concat(u32le(b.length), b); };

/** sha256 of the borsh-serialised NEP-413 payload, prefixed by the NEP-413 tag. */
export function nep413Hash(message: string, nonceHex: string, recipient: string): Uint8Array {
  const nonce = hexToBytes(nonceHex);
  if (nonce.length !== 32) throw new FormatError("schema", "nonce must be 32 bytes");
  return sha256(concat(u32le(NEP413_TAG), borshString(message), nonce, borshString(recipient), new Uint8Array([0])));
}

/** keccak256("\x19Ethereum Signed Message:\n" + len + message). */
export function erc191Hash(message: string): Uint8Array {
  const m = toBytes(message);
  return keccak_256(concat(toBytes(`\x19Ethereum Signed Message:\n${m.length}`), m));
}

// secp256k1 group order.
const N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const HALF_N = N >> 1n;
const big = (b: Uint8Array) => BigInt("0x" + bytesToHex(b));

function decodeHex(sig: string, bytes: number): Uint8Array {
  if (sig.length !== bytes * 2 || !/^[0-9a-f]+$/.test(sig)) {
    throw new FormatError("bad_signature_encoding", `signature must be ${bytes * 2} lowercase hex characters`);
  }
  return hexToBytes(sig);
}

const ED_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const leToBig = (b: Uint8Array) => { let x = 0n; for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]); return x; };

function ed25519CofactorlessVerify(sig: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    const P = ed25519.Point;
    const A = P.fromBytes(publicKey, false);
    const rBytes = sig.subarray(0, 32);
    const s = leToBig(sig.subarray(32, 64)); // < L, checked by the guard
    const k = leToBig(sha512(new Uint8Array([...rBytes, ...publicKey, ...message]))) % ED_L;
    const rPrime = P.BASE.multiplyUnsafe(s).subtract(A.multiplyUnsafe(k));
    const enc = rPrime.toBytes();
    return enc.length === 32 && enc.every((x, i) => x === rBytes[i]);
  } catch {
    return false;
  }
}

/** Ethereum address (0x + 40 lowercase hex) from a 65-byte uncompressed public key. */
export function evmAddress(uncompressed: Uint8Array): string {
  return "0x" + bytesToHex(keccak_256(uncompressed.subarray(1)).subarray(12));
}

export function verifyNep413(buyer: Extract<Buyer, { kind: "near" }>, message: string, nonceHex: string, recipient: string, sigHex: string): void {
  const sig = decodeHex(sigHex, 64);
  if (!isAcceptablePoint(sig.subarray(0, 32)) || !isCanonicalScalar(sig.subarray(32, 64))) {
    throw new FormatError("bad_signature_encoding", "ed25519 R is small-order or non-canonical, or S >= L");
  }
  const hash = nep413Hash(message, nonceHex, recipient);
  // The exact check NEAR's host function (ed25519-dalek `verify`) performs: recompute
  // R' = [S]B - [k]A with k = SHA-512(R || A || M) mod L and compare its encoding with R
  // byte for byte (cofactorless). noble's own verify is cofactored and accepts signatures
  // with torsion components that NEAR rejects (audit M2-02).
  if (!ed25519CofactorlessVerify(sig, hash, buyer.publicKey)) {
    throw new FormatError("bad_signature", "ed25519 signature does not verify");
  }
}

export function verifyErc191(buyer: Extract<Buyer, { kind: "evm" }>, message: string, sigHex: string): void {
  const sig = decodeHex(sigHex, 65);
  const r = big(sig.subarray(0, 32));
  const s = big(sig.subarray(32, 64));
  let v = sig[64];
  if (v === 27 || v === 28) v -= 27;
  if (v !== 0 && v !== 1) throw new FormatError("bad_signature_encoding", "v must be 0, 1, 27 or 28");
  if (r < 1n || r >= N || s < 1n || s >= N) throw new FormatError("bad_signature_encoding", "r or s out of range");
  if (s > HALF_N) throw new FormatError("high_s", "s must be in the lower half of the curve order");
  const recovered = new Uint8Array(65);
  recovered[0] = v;
  recovered.set(sig.subarray(0, 64), 1);
  let pub: Uint8Array;
  try {
    const compressed = secp256k1.recoverPublicKey(recovered, erc191Hash(message), { prehash: false });
    pub = secp256k1.Point.fromBytes(compressed).toBytes(false);
  } catch {
    throw new FormatError("bad_signature", "public key recovery failed");
  }
  if (evmAddress(pub) !== buyer.address) throw new FormatError("wrong_signer", "recovered address does not match buyer");
}
