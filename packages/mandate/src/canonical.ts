// Canonical JSON (RFC 8785, JCS) for the restricted value set our formats use:
// strings, booleans, null, arrays and objects. Numbers are rejected outright.
// Input is accepted only if its raw bytes equal the canonical serialisation.
import { FormatError } from "./errors.ts";

export type Json = string | boolean | null | Json[] | { [key: string]: Json };

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();

function escapeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    // Lone surrogates cannot be represented identically in Rust strings: reject.
    if (c >= 0xd800 && c <= 0xdfff) {
      const hi = c <= 0xdbff;
      const next = s.charCodeAt(i + 1);
      // Rust's JSON parser rejects lone surrogates outright; match it with invalid_json.
      if (!hi || !(next >= 0xdc00 && next <= 0xdfff)) throw new FormatError("invalid_json", "lone surrogate");
      out += s[i] + s[i + 1];
      i++;
      continue;
    }
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += "\\\\";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x0c) out += "\\f";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0d) out += "\\r";
    else if (c === 0x09) out += "\\t";
    else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += s[i];
  }
  return out + '"';
}

/** RFC 8785 serialisation. Keys sorted by UTF-16 code units (JS default sort). */
export function canonicalize(v: unknown): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "string") return escapeString(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v as object).sort();
    return "{" + keys.map((k) => escapeString(k) + ":" + canonicalize((v as Record<string, unknown>)[k])).join(",") + "}";
  }
  // Numbers (and anything else) are not allowed in our formats.
  throw new FormatError("schema", `value of type ${typeof v} not allowed`);
}

export const MAX_DEPTH = 32;

/**
 * Lexical scan before parsing: our formats contain no numbers, so a digit or minus sign
 * outside a string is rejected as "schema" before any JSON parser sees it. This keeps
 * Rust and TypeScript identical on number edge cases (huge, negative zero, exponents).
 */
export function rejectNumbers(text: string): void {
  // One left-to-right pass, identical to crates/formats/src/canonical.rs `prescan`; the first
  // violation wins. Scans the raw text, so a duplicate key cannot hide a value (audit M2-06).
  const hex4 = (at: number) => (/^[0-9a-fA-F]{4}$/.test(text.slice(at, at + 4)) ? parseInt(text.slice(at, at + 4), 16) : -1);
  let inString = false;
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (c === '"') inString = false;
      else if (c === "\\") {
        if (text[i + 1] === "u") {
          const u = hex4(i + 2);
          if (u >= 0xdc00 && u <= 0xdfff) throw new FormatError("invalid_json", "lone low surrogate escape");
          if (u >= 0xd800 && u <= 0xdbff) {
            const lo = text[i + 6] === "\\" && text[i + 7] === "u" ? hex4(i + 8) : -1;
            if (!(lo >= 0xdc00 && lo <= 0xdfff)) throw new FormatError("invalid_json", "lone high surrogate escape");
            i += 6;
          }
          if (u >= 0) i += 4;
        }
        i++;
      }
    } else if (c === '"') inString = true;
    else if (c === "[" || c === "{") {
      depth++;
      if (depth > MAX_DEPTH) throw new FormatError("invalid_json", `nesting deeper than ${MAX_DEPTH}`);
    } else if (c === "]" || c === "}") depth = Math.max(0, depth - 1); // saturating, as in Rust
    else if (c === "-" || (c >= "0" && c <= "9")) throw new FormatError("schema", "numbers are not allowed");
  }
}

export function depthOf(v: unknown): number {
  if (Array.isArray(v)) return 1 + v.reduce((m: number, x) => Math.max(m, depthOf(x)), 0);
  if (v !== null && typeof v === "object") return 1 + Object.values(v).reduce((m: number, x) => Math.max(m, depthOf(x)), 0);
  return 0;
}

export function toBytes(s: string): Uint8Array {
  return encoder.encode(s);
}

/**
 * Parse bytes that must already be canonical. Returns the parsed value and the
 * canonical text (equal to the input).
 */
export function parseCanonical(bytes: Uint8Array, maxBytes: number): { value: Json; text: string } {
  if (!(bytes instanceof Uint8Array)) throw new FormatError("invalid_json", "expected bytes");
  if (bytes.length > maxBytes) throw new FormatError("too_large", `${bytes.length} > ${maxBytes} bytes`);
  let text: string;
  try {
    text = utf8.decode(bytes);
  } catch {
    throw new FormatError("invalid_json", "not valid UTF-8");
  }
  rejectNumbers(text);
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new FormatError("invalid_json", "not valid JSON");
  }
  if (depthOf(value) > MAX_DEPTH) throw new FormatError("invalid_json", `nesting deeper than ${MAX_DEPTH}`);
  const canonical = canonicalize(value);
  if (canonical !== text) throw new FormatError("not_canonical", "bytes differ from canonical form");
  return { value: value as Json, text };
}
