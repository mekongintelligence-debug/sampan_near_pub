// Error codes shared with the Rust implementation (docs/FORMATS.md section 8).
export const ERROR_CODES = [
  "too_large",
  "invalid_json",
  "not_canonical",
  "schema",
  "unsupported_standard",
  "bad_signature_encoding",
  "high_s",
  "bad_signature",
  "wrong_signer",
  "inconsistent",
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export class FormatError extends Error {
  readonly code: ErrorCode;
  constructor(code: ErrorCode, detail: string) {
    super(`${code}: ${detail}`);
    this.code = code;
    this.name = "FormatError";
  }
}
