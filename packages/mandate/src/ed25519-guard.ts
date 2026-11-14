// Pre-checks that make ed25519 verification identical in TypeScript (noble, strict) and
// NEAR's host function (ed25519-dalek): inputs on which the two libraries are known to
// differ are rejected before verification, in both languages (crates/formats/src/ed25519_guard.rs).

// Encodings of the eight small-order points (the 8-torsion subgroup), plus the two
// encodings of x = 0 points with the sign bit set, which ed25519-dalek (NEAR host)
// decodes as the identity and the order-2 point (audit M2-01).
export const SMALL_ORDER = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0100000000000000000000000000000000000000000000000000000000000080",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
]);

// p = 2^255 - 19 and L = 2^252 + 27742317777372353535851937790883648493, little-endian.
const P_LE = Uint8Array.from([0xed, ...Array(30).fill(0xff), 0x7f]);
const L_LE = Uint8Array.from([0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, ...Array(15).fill(0), 0x10]);

/** Compare two 32-byte little-endian integers. */
function leCmp(a: Uint8Array, b: Uint8Array): number {
  for (let i = 31; i >= 0; i--) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** A point encoding is acceptable if y < p (canonical) and it is not a small-order point. */
export function isAcceptablePoint(enc: Uint8Array): boolean {
  if (enc.length !== 32) return false;
  const y = Uint8Array.from(enc);
  y[31] &= 0x7f;
  if (leCmp(y, P_LE) >= 0) return false;
  return !SMALL_ORDER.has(hex(enc));
}

/** S must be a canonical scalar: S < L. */
export function isCanonicalScalar(s: Uint8Array): boolean {
  return s.length === 32 && leCmp(s, L_LE) < 0;
}
