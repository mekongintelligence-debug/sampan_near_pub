// Generates the shared test vectors in fixtures/vectors/ (docs/FORMATS.md, M2).
// Run: node scripts/gen-vectors.ts
//
// Rules (CLAUDE.md): existing vector files are NEVER overwritten; new vectors are
// added and recorded in fixtures/vectors/MANIFEST.sha256. Test keys are derived from
// fixed seed phrases at run time; only public keys and signatures are written.
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { SMALL_ORDER } from "../packages/mandate/src/ed25519-guard.ts";
import { base58 } from "@scure/base";
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { canonicalize, nep413Hash, erc191Hash, evmAddress } from "../packages/mandate/src/index.ts";

const ROOT = resolve(import.meta.dirname, "..");
// --check: write nothing; fail if any vector is missing, differs, or is not defined here (M2-04).
const CHECK = process.argv.includes("--check");
const DIR = join(ROOT, "fixtures/vectors");
const MANIFEST = join(DIR, "MANIFEST.sha256");

const seed = (label: string) => sha256(new TextEncoder().encode(`sampan-test-vector-key/${label}`));
const edKey = (label: string) => { const sk = seed(label); return { sk, pk: ed25519.getPublicKey(sk) }; };
const evmKey = (label: string) => { const sk = seed(label); return { sk, address: evmAddress(secp256k1.getPublicKey(sk, false)) }; };

const N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const hex32 = (label: string) => bytesToHex(sha256(new TextEncoder().encode(label)));

const ED = edKey("buyer-ed25519");
const ED_OTHER = edKey("attacker-ed25519");
const EVM = evmKey("buyer-secp256k1");
const EVM_OTHER = evmKey("attacker-secp256k1");

const baseMandate = (over: Record<string, unknown> = {}) => ({
  v: "sampan.mandate.v1",
  network: "testnet",
  gate: "gate.vectors-only.testnet",
  buyer: `near:ed25519:${base58.encode(ED.pk)}`,
  agent: "agent.vectors-only.testnet",
  asset: "token.vectors-only.testnet",
  max_amount: "5000000",
  payee: "merchant.vectors-only.testnet",
  items: ["report-001", "report-002"],
  expiry_ns: "1794873600000000000",
  nonce: hex32("nonce-1"),
  refund_to: "buyer.vectors-only.testnet",
  ...over,
});
const evmMandate = (over: Record<string, unknown> = {}) => baseMandate({ buyer: `evm:${EVM.address}`, nonce: hex32("nonce-evm"), ...over });

const signNep413 = (m: object, key = ED, recipient?: string, nonce?: string) => {
  const mm = m as { gate: string; nonce: string };
  return bytesToHex(ed25519.sign(nep413Hash(canonicalize(m), nonce ?? mm.nonce, recipient ?? mm.gate), key.sk));
};
const signErc191 = (m: object, key = EVM) => {
  const rec = secp256k1.sign(erc191Hash(canonicalize(m)), key.sk, { prehash: false, format: "recovered", lowS: true });
  // noble: [recid, r, s] -> Ethereum: [r, s, v=27+recid]
  return bytesToHex(new Uint8Array([...rec.subarray(1), 27 + rec[0]]));
};
const signed = (m: object, standard: string, signature: string) => ({ v: "sampan.signed-mandate.v1", mandate: m, standard, signature });

type Expect = { ok: true; hash: string } | { ok: false; error: string };
const vectors: { kind: string; name: string; description: string; input: Uint8Array; expect: Expect }[] = [];
const enc = (s: string) => new TextEncoder().encode(s);
const shaHex = (b: Uint8Array) => bytesToHex(sha256(b));
const add = (kind: string, name: string, description: string, input: Uint8Array | string, expect: Expect | string) => {
  const bytes = typeof input === "string" ? enc(input) : input;
  const e: Expect = typeof expect === "string" ? { ok: false, error: expect } : expect;
  vectors.push({ kind, name, description, input: bytes, expect: e });
};
const ok = (text: string): Expect => ({ ok: true, hash: shaHex(enc(text)) });
const C = canonicalize;

// ---- mandate -------------------------------------------------------------------------
const m1 = baseMandate();
add("mandate", "valid-agent", "Valid agent mandate", C(m1), ok(C(m1)));
const m2 = baseMandate({ agent: null, items: ["report-001"], max_amount: "1000000" });
add("mandate", "valid-human", "Valid direct-checkout mandate (agent null)", C(m2), ok(C(m2)));
add("mandate", "whitespace", "Pretty-printed JSON is not canonical", JSON.stringify(m1, null, 1), "not_canonical");
add("mandate", "key-order", "Keys in insertion order, not sorted", JSON.stringify(m1), "not_canonical");
add("mandate", "duplicate-key", "Duplicate payee key (last one would win in many parsers)",
  C(m1).replace('"payee":"merchant.vectors-only.testnet"', '"payee":"evil.testnet","payee":"merchant.vectors-only.testnet"'), "not_canonical");
add("mandate", "escaped-char", "Unicode escape for a plain ASCII letter", C(m1).replace('"report-001"', '"\\u0072eport-001"'), "not_canonical");
add("mandate", "non-ascii-payee", "Non-ASCII lookalike in payee", C(baseMandate({ payee: "merchаnt.testnet" })), "schema");
add("mandate", "number-amount", "Amount as a JSON number", C(m1).replace('"max_amount":"5000000"', '"max_amount":5000000'), "schema");
{ const { refund_to: _r, ...rest } = m1; add("mandate", "missing-field", "refund_to missing", C(rest), "schema"); }
add("mandate", "extra-field", "Unknown extra field", C({ ...m1, memo: "x" }), "schema");
add("mandate", "amount-zero", "Zero amount", C(baseMandate({ max_amount: "0" })), "schema");
add("mandate", "amount-leading-zero", "Leading zero", C(baseMandate({ max_amount: "0100" })), "schema");
const u128max = ((1n << 128n) - 1n).toString();
const m3 = baseMandate({ max_amount: u128max });
add("mandate", "amount-u128-max", "Largest u128", C(m3), ok(C(m3)));
add("mandate", "amount-u128-max-plus-1", "u128 max + 1", C(baseMandate({ max_amount: (1n << 128n).toString() })), "schema");
add("mandate", "amount-decimal-point", "Decimal point", C(baseMandate({ max_amount: "1.5" })), "schema");
add("mandate", "amount-negative", "Negative", C(baseMandate({ max_amount: "-1" })), "schema");
add("mandate", "amount-exponent", "Exponent notation in a string", C(baseMandate({ max_amount: "1e6" })), "schema");
const m4 = baseMandate({ expiry_ns: ((1n << 64n) - 1n).toString() });
add("mandate", "expiry-u64-max", "Largest u64 expiry", C(m4), ok(C(m4)));
add("mandate", "expiry-u64-max-plus-1", "u64 max + 1", C(baseMandate({ expiry_ns: (1n << 64n).toString() })), "schema");
add("mandate", "expiry-seconds-ok-format", "Expiry in seconds is well-formed (unit errors are caught by R3, not the format)",
  C(baseMandate({ expiry_ns: "1794873600" })), ok(C(baseMandate({ expiry_ns: "1794873600" }))));
add("mandate", "items-unsorted", "Items not sorted", C(baseMandate({ items: ["report-002", "report-001"] })), "schema");
add("mandate", "items-duplicate", "Duplicate item", C(baseMandate({ items: ["report-001", "report-001"] })), "schema");
add("mandate", "items-empty", "No items", C(baseMandate({ items: [] })), "schema");
add("mandate", "items-17", "Seventeen items", C(baseMandate({ items: Array.from({ length: 17 }, (_, i) => `item-${String(i).padStart(2, "0")}`) })), "schema");
add("mandate", "oversize", "4097 bytes", C(m1) + " ".repeat(4097 - C(m1).length), "too_large");
add("mandate", "invalid-utf8", "Invalid UTF-8 byte", new Uint8Array([...enc(C(m1).slice(0, 10)), 0xff, ...enc(C(m1).slice(10))]), "invalid_json");
add("mandate", "bom", "UTF-8 byte order mark", new Uint8Array([0xef, 0xbb, 0xbf, ...enc(C(m1))]), "invalid_json");
add("mandate", "account-uppercase", "Uppercase account", C(baseMandate({ payee: "Merchant.testnet" })), "schema");
add("mandate", "account-too-long", "65-character account", C(baseMandate({ payee: "a".repeat(57) + ".testnet" })), "schema");
const m5 = baseMandate({ payee: "a".repeat(64) });
add("mandate", "account-implicit", "64-hex implicit account is valid", C(m5), ok(C(m5)));
add("mandate", "bad-version", "Unknown format version", C(baseMandate({ v: "sampan.mandate.v2" })), "schema");
add("mandate", "nonce-uppercase", "Uppercase hex nonce", C(baseMandate({ nonce: hex32("nonce-1").toUpperCase() })), "schema");
add("mandate", "network-other", "Unknown network", C(baseMandate({ network: "devnet" })), "schema");
add("mandate", "buyer-evm-uppercase", "Checksummed (mixed-case) EVM address", C(baseMandate({ buyer: `evm:0x${EVM.address.slice(2).toUpperCase()}` })), "schema");
add("mandate", "buyer-ed25519-short", "31-byte ed25519 key", C(baseMandate({ buyer: `near:ed25519:${base58.encode(ED.pk.subarray(1))}` })), "schema");

add("mandate", "lone-surrogate", "Escaped lone UTF-16 surrogate", C(m1).replace('"report-001"', '"\\ud800report-001"'), "invalid_json");
add("mandate", "surrogate-pair-escaped", "Escaped valid surrogate pair (emoji)", C(m1).replace('"report-001"', '"\\ud83d\\ude00"'), "not_canonical");
add("mandate", "huge-number", "Number too large for a double", C(m1).replace('"max_amount":"5000000"', '"max_amount":1e400'), "schema");
add("mandate", "negative-zero", "Negative zero", C(m1).replace('"max_amount":"5000000"', '"max_amount":-0'), "schema");
add("mandate", "deep-nesting-40", "Nesting depth 40", "[".repeat(40) + "]".repeat(40), "invalid_json");
add("mandate", "deep-nesting-200", "Nesting depth 200", "[".repeat(200) + "]".repeat(200), "invalid_json");
add("mandate", "slash-escape", "Escaped forward slash", C(m1).replace('"report-001"', '"report\\/001"'), "not_canonical");
add("mandate", "trailing-newline", "Trailing newline", C(m1) + "\n", "not_canonical");
add("mandate", "empty", "Empty input", "", "invalid_json");
add("mandate", "string-with-digits-only", "A digit inside a string is fine (it is the scan, not the value)", C(m2), ok(C(m2)));

// ---- signed mandate ------------------------------------------------------------------
const okSigned = (m: object): Expect => ({ ok: true, hash: shaHex(enc(C(m))) });
add("signed_mandate", "nep413-valid", "Valid NEP-413 signature", C(signed(m1, "nep413", signNep413(m1))), okSigned(m1));
add("signed_mandate", "nep413-valid-human", "Valid NEP-413, direct checkout", C(signed(m2, "nep413", signNep413(m2))), okSigned(m2));
const e1 = evmMandate();
const eSig = signErc191(e1);
add("signed_mandate", "erc191-valid-v27", "Valid ERC-191 signature, v=27/28", C(signed(e1, "erc191", eSig)), okSigned(e1));
const v01 = eSig.slice(0, 128) + (parseInt(eSig.slice(128), 16) - 27).toString(16).padStart(2, "0");
add("signed_mandate", "erc191-valid-v01", "Valid ERC-191 signature with v=0/1", C(signed(e1, "erc191", v01)), okSigned(e1));
const flip = (h: string, i: number) => h.slice(0, i) + ((parseInt(h[i], 16) ^ 1).toString(16)) + h.slice(i + 1);
add("signed_mandate", "nep413-bitflip", "One bit flipped in the signature", C(signed(m1, "nep413", flip(signNep413(m1), 10))), "bad_signature");
add("signed_mandate", "nep413-other-key", "Signed by a different key", C(signed(m1, "nep413", signNep413(m1, ED_OTHER))), "bad_signature");
add("signed_mandate", "nep413-other-gate", "Signed for another recipient (gate)", C(signed(m1, "nep413", signNep413(m1, ED, "other-gate.testnet"))), "bad_signature");
add("signed_mandate", "nep413-other-nonce", "Signed with another NEP-413 nonce", C(signed(m1, "nep413", signNep413(m1, ED, undefined, hex32("other-nonce")))), "bad_signature");
const mMain = baseMandate({ network: "mainnet" });
add("signed_mandate", "nep413-network-swapped", "Testnet signature presented on a mainnet mandate", C(signed(mMain, "nep413", signNep413(m1))), "bad_signature");
const mAmt = baseMandate({ max_amount: "9000000" });
add("signed_mandate", "nep413-amount-raised", "Signature over 5000000 presented with max_amount 9000000", C(signed(mAmt, "nep413", signNep413(m1))), "bad_signature");
add("signed_mandate", "erc191-wrong-signer", "Valid signature by another EVM key", C(signed(e1, "erc191", signErc191(e1, EVM_OTHER))), "wrong_signer");
{
  const s = BigInt("0x" + eSig.slice(64, 128)); const v = parseInt(eSig.slice(128), 16);
  const highS = (N - s).toString(16).padStart(64, "0");
  const flippedV = (v === 27 ? 28 : 27).toString(16).padStart(2, "0");
  add("signed_mandate", "erc191-high-s", "Malleated high-s form of a valid signature", C(signed(e1, "erc191", eSig.slice(0, 64) + highS + flippedV)), "high_s");
  add("signed_mandate", "erc191-v2", "v=2", C(signed(e1, "erc191", eSig.slice(0, 128) + "02")), "bad_signature_encoding");
  add("signed_mandate", "erc191-r-zero", "r = 0", C(signed(e1, "erc191", "0".repeat(64) + eSig.slice(64))), "bad_signature_encoding");
  add("signed_mandate", "erc191-s-n", "s = n", C(signed(e1, "erc191", eSig.slice(0, 64) + N.toString(16) + eSig.slice(128))), "bad_signature_encoding");
}
// ed25519 edge cases where libraries differ (review finding M2-CR1): rejected before verify.
{
  const sig = hexToBytes(signNep413(m1));
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const sLe = sig.subarray(32);
  let sVal = 0n; for (let i = 31; i >= 0; i--) sVal = (sVal << 8n) | BigInt(sLe[i]);
  const sPlusL = sVal + L; const out = new Uint8Array(64); out.set(sig.subarray(0, 32));
  for (let i = 0, x = sPlusL; i < 32; i++, x >>= 8n) out[32 + i] = Number(x & 0xffn);
  add("signed_mandate", "nep413-s-plus-l", "Non-canonical S (S + L), same signature otherwise", C(signed(m1, "nep413", bytesToHex(out))), "bad_signature_encoding");
  const smallR = new Uint8Array(64); smallR[0] = 1; // R = identity point, S = 0
  add("signed_mandate", "nep413-r-small-order", "R is a small-order point", C(signed(m1, "nep413", bytesToHex(smallR))), "bad_signature_encoding");
  const nonCanonR = Uint8Array.from(sig); nonCanonR.set(Uint8Array.from([0xee, ...Array(30).fill(0xff), 0x7f]), 0);
  add("signed_mandate", "nep413-r-non-canonical", "R encodes y >= p", C(signed(m1, "nep413", bytesToHex(nonCanonR))), "bad_signature_encoding");
}
for (const [i, enc] of [...SMALL_ORDER].entries()) {
  add("mandate", `buyer-ed25519-small-order-${i}`, "Buyer key is a small-order point", C(baseMandate({ buyer: `near:ed25519:${base58.encode(hexToBytes(enc))}` })), "schema");
}
add("mandate", "buyer-ed25519-non-canonical", "Buyer key encodes y >= p",
  C(baseMandate({ buyer: `near:ed25519:${base58.encode(Uint8Array.from([0xee, ...Array(30).fill(0xff), 0x7f]))}` })), "schema");

add("signed_mandate", "sig-short", "Signature one byte short", C(signed(m1, "nep413", signNep413(m1).slice(0, 126))), "bad_signature_encoding");
add("signed_mandate", "sig-uppercase", "Uppercase hex signature", C(signed(m1, "nep413", signNep413(m1).toUpperCase())), "bad_signature_encoding");
add("signed_mandate", "unknown-standard", "Unknown signing standard", C(signed(m1, "eip712", signNep413(m1))), "unsupported_standard");
add("signed_mandate", "nep413-evm-buyer", "NEP-413 with an EVM buyer", C(signed(e1, "nep413", signNep413(e1))), "unsupported_standard");
add("signed_mandate", "inner-schema-error", "Signed mandate with an invalid inner field", C(signed(baseMandate({ max_amount: "0" }), "nep413", signNep413(m1))), "schema");

// ---- boundary vectors (mutation testing, M2) -----------------------------------------
add("mandate", "control-char-escaped", "Control character in a string, correctly escaped", C(m1).replace('"report-001"', '"\\u0001"'), "schema");
add("mandate", "space-in-string", "Space inside a string value (not escaped in canonical form)", C(m1).replace('"report-001"', '"report 001"'), "schema");
add("mandate", "deep-objects-40", "Objects nested 40 deep", '{"a":'.repeat(40) + "null" + "}".repeat(40), "invalid_json");
add("mandate", "depth-exactly-32", "Arrays nested exactly 32 deep (allowed depth, then schema)", "[".repeat(32) + "]".repeat(32), "schema");
{ const pre = '{"v":"'; const post = '"}'; add("mandate", "exactly-4096-bytes", "Canonical document of exactly 4096 bytes", pre + "a".repeat(4096 - pre.length - post.length) + post, "schema"); }
const a2 = baseMandate({ payee: "ab" });
add("mandate", "account-two-chars", "Two-character account is valid", C(a2), ok(C(a2)));
add("mandate", "account-one-char", "One-character account", C(baseMandate({ payee: "a" })), "schema");
add("mandate", "account-trailing-dash", "Account ending in a separator", C(baseMandate({ payee: "merchant-" })), "schema");
add("mandate", "account-leading-dash", "Account starting with a separator", C(baseMandate({ payee: "-merchant" })), "schema");
add("mandate", "account-double-separator", "Two separators in a row", C(baseMandate({ payee: "mer--chant" })), "schema");
const it1 = baseMandate({ items: ["a.b_c-d"] });
add("mandate", "item-punctuation", "Item ID with dot, underscore and dash", C(it1), ok(C(it1)));
const it64 = baseMandate({ items: ["a".repeat(64)] });
add("mandate", "item-64-chars", "64-character item ID", C(it64), ok(C(it64)));
add("mandate", "item-65-chars", "65-character item ID", C(baseMandate({ items: ["a".repeat(65)] })), "schema");
add("mandate", "item-uppercase", "Uppercase in item ID", C(baseMandate({ items: ["Report"] })), "schema");
add("mandate", "item-leading-dash", "Item ID starting with a dash", C(baseMandate({ items: ["-report"] })), "schema");
add("mandate", "item-slash", "Slash in item ID", C(baseMandate({ items: ["report/1"] })), "schema");
const i16 = baseMandate({ items: Array.from({ length: 16 }, (_, i) => `item-${String(i).padStart(2, "0")}`) });
add("mandate", "items-16", "Sixteen items (the maximum)", C(i16), ok(C(i16)));
const k32 = baseMandate({ buyer: `near:ed25519:${base58.encode(Uint8Array.from([...Array(31).fill(0), 5]))}` });
add("mandate", "buyer-base58-32-chars", "Buyer key whose base58 form is 32 characters", C(k32), ok(C(k32)));
const k33 = baseMandate({ buyer: `near:ed25519:${base58.encode(Uint8Array.from([...Array(31).fill(0), 100]))}` });
add("mandate", "buyer-base58-33-chars", "Buyer key whose base58 form is 33 characters", C(k33), ok(C(k33)));
add("mandate", "buyer-base58-45-chars", "45-character base58 key", C(baseMandate({ buyer: `near:ed25519:${"2".repeat(45)}` })), "schema");
add("mandate", "buyer-base58-31-chars", "31-character base58 key", C(baseMandate({ buyer: `near:ed25519:${"1".repeat(30)}6` })), "schema");
{
  const sHalf = ((N >> 1n)).toString(16).padStart(64, "0");
  const sig = signErc191(e1);
  add("signed_mandate", "erc191-s-zero", "s = 0", C(signed(e1, "erc191", sig.slice(0, 64) + "0".repeat(64) + sig.slice(128))), "bad_signature_encoding");
  add("signed_mandate", "erc191-r-n", "r = n", C(signed(e1, "erc191", N.toString(16) + sig.slice(64))), "bad_signature_encoding");
  add("signed_mandate", "erc191-s-half-n-plus-1", "s = n/2 + 1 (just above the low-s bound)", C(signed(e1, "erc191", sig.slice(0, 64) + ((N >> 1n) + 1n).toString(16).padStart(64, "0") + sig.slice(128))), "high_s");
  // s = n/2 exactly is allowed by the low-s rule; with an unrelated r it recovers some other key.
  add("signed_mandate", "erc191-s-half-n", "s = n/2 exactly passes the low-s rule (then the signer does not match)", C(signed(e1, "erc191", sig.slice(0, 64) + sHalf + sig.slice(128))), "wrong_signer");
}

// ---- audit M2 additions ------------------------------------------------------------
const fromB64 = (b: string) => new Uint8Array(Buffer.from(b, "base64"));
add("signed_mandate", "audit-m2-01-forged-identity-key", "Forged signature under the identity key with the sign bit set (M2-01)", fromB64("eyJtYW5kYXRlIjp7ImFnZW50IjoiYWdlbnQuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJhc3NldCI6InRva2VuLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYnV5ZXIiOiJuZWFyOmVkMjU1MTk6NHVRZVZqNXRxVmlRaDd5V1dHU3R2a0VHMVptaHg2dWFzSnRXQ0p6aW9oWiIsImV4cGlyeV9ucyI6IjE3OTQ4NzM2MDAwMDAwMDAwMDAiLCJnYXRlIjoiZ2F0ZS5zYW1wYW4tdHJ1c3QtMDEudGVzdG5ldCIsIml0ZW1zIjpbInJlcG9ydC0wMDEiXSwibWF4X2Ftb3VudCI6IjUwMDAwMDAiLCJuZXR3b3JrIjoidGVzdG5ldCIsIm5vbmNlIjoiZDExOTg0NmI0M2M5YmM3YWRmODEyNDNiNWZlNTA5NjdjMGYwZmFkNDU2Y2Y1MDA0YWIxMjBmNmE5ZWMxYWY5ZCIsInBheWVlIjoiYXR0YWNrZXIudGVzdG5ldCIsInJlZnVuZF90byI6ImJ1eWVyLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwidiI6InNhbXBhbi5tYW5kYXRlLnYxIn0sInNpZ25hdHVyZSI6IjU4NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjYwMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwic3RhbmRhcmQiOiJuZXA0MTMiLCJ2Ijoic2FtcGFuLnNpZ25lZC1tYW5kYXRlLnYxIn0="), "schema");
add("mandate", "audit-m2-01-identity-key-sign-bit", "Buyer key 01 00..00 80 (M2-01)", fromB64("eyJhZ2VudCI6ImFnZW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYXNzZXQiOiJ0b2tlbi5zYW1wYW4tdHJ1c3QtMDEudGVzdG5ldCIsImJ1eWVyIjoibmVhcjplZDI1NTE5OjR1UWVWajV0cVZpUWg3eVdXR1N0dmtFRzFabWh4NnVhc0p0V0NKemlvaFoiLCJleHBpcnlfbnMiOiIxNzk0ODczNjAwMDAwMDAwMDAwIiwiZ2F0ZSI6ImdhdGUuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJpdGVtcyI6WyJyZXBvcnQtMDAxIl0sIm1heF9hbW91bnQiOiI1MDAwMDAwIiwibmV0d29yayI6InRlc3RuZXQiLCJub25jZSI6ImQxMTk4NDZiNDNjOWJjN2FkZjgxMjQzYjVmZTUwOTY3YzBmMGZhZDQ1NmNmNTAwNGFiMTIwZjZhOWVjMWFmOWQiLCJwYXllZSI6ImF0dGFja2VyLnRlc3RuZXQiLCJyZWZ1bmRfdG8iOiJidXllci5zYW1wYW4tdHJ1c3QtMDEudGVzdG5ldCIsInYiOiJzYW1wYW4ubWFuZGF0ZS52MSJ9"), "schema");
add("mandate", "audit-m2-01-order-two-key-sign-bit", "Buyer key ec ff..ff ff (M2-01)", fromB64("eyJhZ2VudCI6ImFnZW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYXNzZXQiOiJ0b2tlbi5zYW1wYW4tdHJ1c3QtMDEudGVzdG5ldCIsImJ1eWVyIjoibmVhcjplZDI1NTE5Okd4OWRETnh6cEFMQ293VnVaYjdwQmNlQkxKdWdMQThzUGE2VEpEWHJwZmdpIiwiZXhwaXJ5X25zIjoiMTc5NDg3MzYwMDAwMDAwMDAwMCIsImdhdGUiOiJnYXRlLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiaXRlbXMiOlsicmVwb3J0LTAwMSJdLCJtYXhfYW1vdW50IjoiNTAwMDAwMCIsIm5ldHdvcmsiOiJ0ZXN0bmV0Iiwibm9uY2UiOiJkMTE5ODQ2YjQzYzliYzdhZGY4MTI0M2I1ZmU1MDk2N2MwZjBmYWQ0NTZjZjUwMDRhYjEyMGY2YTllYzFhZjlkIiwicGF5ZWUiOiJtZXJjaGFudC5zYW1wYW4tdHJ1c3QtMDEudGVzdG5ldCIsInJlZnVuZF90byI6ImJ1eWVyLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwidiI6InNhbXBhbi5tYW5kYXRlLnYxIn0="), "schema");
add("signed_mandate", "audit-m2-01-r-identity-sign-bit", "R = 01 00..00 80 (M2-01)", fromB64("eyJtYW5kYXRlIjp7ImFnZW50IjoiYWdlbnQuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJhc3NldCI6InRva2VuLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYnV5ZXIiOiJuZWFyOmVkMjU1MTk6RlZYV2lxamdLTDRhRjI4Y2RIOFZ6Z3RBWGhZeHlGU3J2bmVrRm5qRVNXQ1giLCJleHBpcnlfbnMiOiIxNzk0ODczNjAwMDAwMDAwMDAwIiwiZ2F0ZSI6ImdhdGUuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJpdGVtcyI6WyJyZXBvcnQtMDAxIl0sIm1heF9hbW91bnQiOiI1MDAwMDAwIiwibmV0d29yayI6InRlc3RuZXQiLCJub25jZSI6ImQxMTk4NDZiNDNjOWJjN2FkZjgxMjQzYjVmZTUwOTY3YzBmMGZhZDQ1NmNmNTAwNGFiMTIwZjZhOWVjMWFmOWQiLCJwYXllZSI6Im1lcmNoYW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwicmVmdW5kX3RvIjoiYnV5ZXIuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJ2Ijoic2FtcGFuLm1hbmRhdGUudjEifSwic2lnbmF0dXJlIjoiMDEwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA4MDAxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJzdGFuZGFyZCI6Im5lcDQxMyIsInYiOiJzYW1wYW4uc2lnbmVkLW1hbmRhdGUudjEifQ=="), "bad_signature_encoding");
add("signed_mandate", "audit-m2-02-mixed-order-r", "Mixed-order R: NEAR's cofactorless check rejects (M2-02)", fromB64("eyJtYW5kYXRlIjp7ImFnZW50IjoiYWdlbnQuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJhc3NldCI6InRva2VuLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYnV5ZXIiOiJuZWFyOmVkMjU1MTk6RlZYV2lxamdLTDRhRjI4Y2RIOFZ6Z3RBWGhZeHlGU3J2bmVrRm5qRVNXQ1giLCJleHBpcnlfbnMiOiIxNzk0ODczNjAwMDAwMDAwMDAwIiwiZ2F0ZSI6ImdhdGUuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJpdGVtcyI6WyJyZXBvcnQtMDAxIl0sIm1heF9hbW91bnQiOiI1MDAwMDAwIiwibmV0d29yayI6InRlc3RuZXQiLCJub25jZSI6ImQxMTk4NDZiNDNjOWJjN2FkZjgxMjQzYjVmZTUwOTY3YzBmMGZhZDQ1NmNmNTAwNGFiMTIwZjZhOWVjMWFmOWQiLCJwYXllZSI6Im1lcmNoYW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwicmVmdW5kX3RvIjoiYnV5ZXIuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJ2Ijoic2FtcGFuLm1hbmRhdGUudjEifSwic2lnbmF0dXJlIjoiNzA2M2VhMzNmNGE5OWNmMGE5NGVhOTA1YTAzN2NjMjM2ZjM0OWU3NTFmMTAyOTQzMDZlMGFkMDZlYjFhMWQwYWIwOWQ0ZmE5ZDU3NjM1MGE1ZTE4MzAyODM2ZWU5NTMyZTA5OThjYjZiMWExZmJlMzU5ZmZhOGJiNzAyMTdhMDgiLCJzdGFuZGFyZCI6Im5lcDQxMyIsInYiOiJzYW1wYW4uc2lnbmVkLW1hbmRhdGUudjEifQ=="), "bad_signature");
add("signed_mandate", "audit-m2-02-mixed-order-key", "Mixed-order buyer key: NEAR's cofactorless check rejects (M2-02)", fromB64("eyJtYW5kYXRlIjp7ImFnZW50IjoiYWdlbnQuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJhc3NldCI6InRva2VuLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYnV5ZXIiOiJuZWFyOmVkMjU1MTk6MkU0QTc2NWZ0WnNvTjhHZTlqbVUxenhpeDJRODh0SkNyckNqcjd2NTc4bmYiLCJleHBpcnlfbnMiOiIxNzk0ODczNjAwMDAwMDAwMDAwIiwiZ2F0ZSI6ImdhdGUuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJpdGVtcyI6WyJyZXBvcnQtMDAxIl0sIm1heF9hbW91bnQiOiI1MDAwMDAwIiwibmV0d29yayI6InRlc3RuZXQiLCJub25jZSI6ImM2MzljMmU5ZjQ2NmUwMjA2YWRiYjQ0ZWIxYTgyYTY2Y2M0NDE2NjU2YjRlYjhkYTJkYjhhNjg0OTc0YWRmNmQiLCJwYXllZSI6Im1lcmNoYW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwicmVmdW5kX3RvIjoiYnV5ZXIuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJ2Ijoic2FtcGFuLm1hbmRhdGUudjEifSwic2lnbmF0dXJlIjoiNGRlMzZmZTM0MGZjMjNlNDFlYTlmMTA5NTg5ZDQ2OWJkZmMzYjJjMTc0OTdhMzhjNTIzNjNiODc0MzE3NTA4ZTY4NzY4YTZlMDg3MWIxNzBkMWYzNmRiNjM0NmFmNjVkZWNiZTAyZDFjMTMxNzgyMzVlOTFjYTNlMTExYWM4MDQiLCJzdGFuZGFyZCI6Im5lcDQxMyIsInYiOiJzYW1wYW4uc2lnbmVkLW1hbmRhdGUudjEifQ=="), "bad_signature");
add("mandate", "empty-object", "Empty object", "{}", "schema");
for (const k of Object.keys(m1)) {
  const { [k]: _drop, ...rest } = m1 as Record<string, unknown>;
  add("mandate", `missing-${k.replace(/_/g, "-")}`, `${k} missing`, C(rest), "schema");
}
add("mandate", "nfd-string", "Decomposed (NFD) accent in an account", C(baseMandate({ payee: "cafe\u0301.testnet" })), "schema");
const evmPayee = baseMandate({ payee: `0x${"ab".repeat(20)}` });
add("mandate", "evm-style-account", "0x + 40 hex is a valid NEAR account (Ethereum-style implicit account)", C(evmPayee), ok(C(evmPayee)));
{
  const v0 = { ...m1, v: "sampan.mandate.v0" };
  add("signed_mandate", "nep413-signed-other-version", "Signature made over a v0 mandate, presented as v1", C(signed(m1, "nep413", signNep413(v0))), "bad_signature");
}

// ---- order ---------------------------------------------------------------------------
const mHash = shaHex(enc(C(m1)));
const o1 = { v: "sampan.order.v1", order_id: hex32("order-1"), mandate_hash: mHash, item: "report-001", amount: "2500000", asset: m1.asset, payee: m1.payee };
add("order", "valid", "Valid order", C(o1), ok(C(o1)));
add("order", "extra-field", "Unknown extra field", C({ ...o1, note: "x" }), "schema");
add("order", "bad-mandate-hash", "Mandate hash not 32 bytes", C({ ...o1, mandate_hash: mHash.slice(2) }), "schema");
add("order", "swapped-payee-valid-format", "Swapped payee is well-formed (refused later by R8, not the format)", C({ ...o1, payee: "attacker.testnet" }), ok(C({ ...o1, payee: "attacker.testnet" })));

// ---- receipt core --------------------------------------------------------------------
const rules = (fail: string[] = []) => ["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"].map((id) => ({ id, pass: !fail.includes(id) }));
const core = (over: Record<string, unknown> = {}) => ({
  v: "sampan.receipt.v1", network: "testnet", gate: m1.gate, mandate_hash: mHash, order_hash: shaHex(enc(C(o1))),
  observed: { amount: "2500000", asset: m1.asset }, rules: rules(), decision: "release", block_height: "200000000", ...over,
});
add("receipt_core", "release", "All rules pass, released", C(core()), ok(C(core())));
const refused = core({ rules: rules(["R8", "R9"]), decision: "refuse" });
add("receipt_core", "refuse", "Payee and item rules fail, refused", C(refused), ok(C(refused)));
add("receipt_core", "inconsistent-release", "Release although R8 failed", C(core({ rules: rules(["R8"]) })), "inconsistent");
add("receipt_core", "inconsistent-refuse", "Refuse although all rules pass", C(core({ decision: "refuse" })), "inconsistent");
add("receipt_core", "rules-out-of-order", "Rules not in R1-R9 order", C(core({ rules: [...rules()].reverse() })), "schema");
add("receipt_core", "rules-missing", "R9 missing", C(core({ rules: rules().slice(0, 8) })), "schema");
add("receipt_core", "pass-as-string", "pass written as a string", C(core()).replace('"pass":true', '"pass":"true"'), "schema");

// ---- write (never overwrite) ---------------------------------------------------------
let added = 0;
let drift = 0;
const manifest = existsSync(MANIFEST) ? readFileSync(MANIFEST, "utf8") : "";
for (const v of vectors) {
  const dir = join(DIR, v.kind);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${v.name}.json`);
  const body = JSON.stringify({ name: v.name, kind: v.kind, description: v.description,
    input_b64: Buffer.from(v.input).toString("base64"), expect: v.expect }, null, 2) + "\n";
  if (CHECK) {
    if (!existsSync(file)) { console.error(`MISSING: ${v.kind}/${v.name}.json`); drift++; }
    else if (readFileSync(file, "utf8") !== body) { console.error(`DRIFT: ${v.kind}/${v.name}.json`); drift++; }
    continue;
  }
  if (existsSync(file)) {
    if (readFileSync(file, "utf8") !== body) {
      console.error(`DRIFT: ${v.kind}/${v.name}.json differs from generator output (not overwritten)`);
      drift++;
    }
    continue;
  }
  writeFileSync(file, body);
  const rel = `${v.kind}/${v.name}.json`;
  if (!manifest.includes(` ${rel}\n`)) appendFileSync(MANIFEST, `${shaHex(enc(body))} ${rel}\n`);
  added++;
}
if (CHECK) {
  const defined = new Set(vectors.map((v) => `${v.kind}/${v.name}.json`));
  const listed = readFileSync(MANIFEST, "utf8").trim().split("\n").map((l) => l.split(" ")[1]);
  for (const f of listed) if (!defined.has(f)) { console.error(`EXTRA (not defined by the generator): ${f}`); drift++; }
  if (listed.length !== defined.size) { console.error(`manifest lists ${listed.length}, generator defines ${defined.size}`); drift++; }
}
console.log(`vectors: ${vectors.length} defined, ${added} added${CHECK ? " (check mode)" : ""}`);
// Drift means the implementation no longer reproduces frozen vectors (review finding M2-CR6).
if (drift) { console.error(`${drift} vector(s) drifted; investigate before changing anything`); process.exit(1); }
