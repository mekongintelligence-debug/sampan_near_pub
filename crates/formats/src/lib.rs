//! Formats v1 (docs/FORMATS.md): canonical parsing, hashing and signature checks for
//! mandates, orders and receipt cores. Mirrors packages/mandate and packages/receipt;
//! both are held to the shared vectors in fixtures/vectors/.

// Contract-grade code: no panics, no unchecked arithmetic or indexing (docs/SECURITY.md 3.1).
#![cfg_attr(
    not(test),
    forbid(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::disallowed_macros
    )
)]

mod canonical;
mod ed25519_guard;
mod grammar;
mod mandate;
mod receipt;
mod signing;

pub use canonical::{canonicalize, parse_canonical, MAX_DEPTH};
pub use mandate::{
    parse_mandate, parse_order, verify_signed_mandate, Buyer, Mandate, Order, Standard,
    VerifiedMandate, MAX_DOC_BYTES, MAX_ITEMS,
};
pub use receipt::{parse_receipt_core, ReceiptCore, Rule, RULE_IDS};
pub use signing::{erc191_hash, nep413_hash, NEP413_TAG};

/// Error codes shared with the TypeScript implementation (docs/FORMATS.md section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    TooLarge,
    InvalidJson,
    NotCanonical,
    Schema,
    UnsupportedStandard,
    BadSignatureEncoding,
    HighS,
    BadSignature,
    WrongSigner,
    Inconsistent,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::TooLarge => "too_large",
            ErrorCode::InvalidJson => "invalid_json",
            ErrorCode::NotCanonical => "not_canonical",
            ErrorCode::Schema => "schema",
            ErrorCode::UnsupportedStandard => "unsupported_standard",
            ErrorCode::BadSignatureEncoding => "bad_signature_encoding",
            ErrorCode::HighS => "high_s",
            ErrorCode::BadSignature => "bad_signature",
            ErrorCode::WrongSigner => "wrong_signer",
            ErrorCode::Inconsistent => "inconsistent",
        }
    }
}

/// A 32-byte hash as 64 lowercase hex characters.
pub fn hash_hex(bytes: &[u8]) -> String {
    hex_lower(&near_sdk::env::sha256_array(bytes))
}

/// Lowercase hex of any bytes (shared with the gate contract).
pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            if let Some(c) = HEX.get(usize::from(nibble)) {
                out.push(char::from(*c));
            }
        }
    }
    out
}

/// Decodes lowercase hex of exactly `len` bytes.
pub(crate) fn decode_hex_lower(s: &str, len: usize) -> Option<Vec<u8>> {
    if s.len() != len.checked_mul(2)? {
        return None;
    }
    let val = |c: u8| match c {
        b'0'..=b'9' => Some(c.checked_sub(b'0')?),
        b'a'..=b'f' => Some(c.checked_sub(b'a')?.checked_add(10)?),
        _ => None,
    };
    s.as_bytes()
        .chunks(2)
        .map(|pair| match pair {
            [hi, lo] => Some(val(*hi)?.checked_mul(16)?.checked_add(val(*lo)?)?),
            _ => None,
        })
        .collect()
}
