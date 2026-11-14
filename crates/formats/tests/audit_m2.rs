//! Independent audit of M2 (docs/audits/M2.md): exploit tests. Each test asserts the
//! behaviour docs/FORMATS.md requires; a failing test is an open finding. The same input
//! bytes are used in packages/mandate/src/audit-m2.test.ts so the two sides can be compared.
//! Inputs were generated with @noble/curves (no private key of a real party is involved).
// Test-only helper below decodes fixed constants.
#![allow(clippy::unwrap_used)]
use base64::Engine;
use sampan_formats::{
    parse_canonical, parse_mandate, verify_signed_mandate, ErrorCode, MAX_DOC_BYTES,
};

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}
fn sm(s: &str) -> Result<(), ErrorCode> {
    verify_signed_mandate(&b64(s)).map(|_| ())
}

const F1_FORGED: &str = "eyJtYW5kYXRlIjp7ImFnZW50IjoiYWdlbnQuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJhc3NldCI6InRva2VuLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYnV5ZXIiOiJuZWFyOmVkMjU1MTk6NHVRZVZqNXRxVmlRaDd5V1dHU3R2a0VHMVptaHg2dWFzSnRXQ0p6aW9oWiIsImV4cGlyeV9ucyI6IjE3OTQ4NzM2MDAwMDAwMDAwMDAiLCJnYXRlIjoiZ2F0ZS5zYW1wYW4tdHJ1c3QtMDEudGVzdG5ldCIsIml0ZW1zIjpbInJlcG9ydC0wMDEiXSwibWF4X2Ftb3VudCI6IjUwMDAwMDAiLCJuZXR3b3JrIjoidGVzdG5ldCIsIm5vbmNlIjoiZDExOTg0NmI0M2M5YmM3YWRmODEyNDNiNWZlNTA5NjdjMGYwZmFkNDU2Y2Y1MDA0YWIxMjBmNmE5ZWMxYWY5ZCIsInBheWVlIjoiYXR0YWNrZXIudGVzdG5ldCIsInJlZnVuZF90byI6ImJ1eWVyLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwidiI6InNhbXBhbi5tYW5kYXRlLnYxIn0sInNpZ25hdHVyZSI6IjU4NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjYwMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwic3RhbmRhcmQiOiJuZXA0MTMiLCJ2Ijoic2FtcGFuLnNpZ25lZC1tYW5kYXRlLnYxIn0=";
const F1_MANDATE_K0: &str = "eyJhZ2VudCI6ImFnZW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYXNzZXQiOiJ0b2tlbi5zYW1wYW4tdHJ1c3QtMDEudGVzdG5ldCIsImJ1eWVyIjoibmVhcjplZDI1NTE5OjR1UWVWajV0cVZpUWg3eVdXR1N0dmtFRzFabWh4NnVhc0p0V0NKemlvaFoiLCJleHBpcnlfbnMiOiIxNzk0ODczNjAwMDAwMDAwMDAwIiwiZ2F0ZSI6ImdhdGUuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJpdGVtcyI6WyJyZXBvcnQtMDAxIl0sIm1heF9hbW91bnQiOiI1MDAwMDAwIiwibmV0d29yayI6InRlc3RuZXQiLCJub25jZSI6ImQxMTk4NDZiNDNjOWJjN2FkZjgxMjQzYjVmZTUwOTY3YzBmMGZhZDQ1NmNmNTAwNGFiMTIwZjZhOWVjMWFmOWQiLCJwYXllZSI6ImF0dGFja2VyLnRlc3RuZXQiLCJyZWZ1bmRfdG8iOiJidXllci5zYW1wYW4tdHJ1c3QtMDEudGVzdG5ldCIsInYiOiJzYW1wYW4ubWFuZGF0ZS52MSJ9";
const F1_MANDATE_K1: &str = "eyJhZ2VudCI6ImFnZW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYXNzZXQiOiJ0b2tlbi5zYW1wYW4tdHJ1c3QtMDEudGVzdG5ldCIsImJ1eWVyIjoibmVhcjplZDI1NTE5Okd4OWRETnh6cEFMQ293VnVaYjdwQmNlQkxKdWdMQThzUGE2VEpEWHJwZmdpIiwiZXhwaXJ5X25zIjoiMTc5NDg3MzYwMDAwMDAwMDAwMCIsImdhdGUiOiJnYXRlLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiaXRlbXMiOlsicmVwb3J0LTAwMSJdLCJtYXhfYW1vdW50IjoiNTAwMDAwMCIsIm5ldHdvcmsiOiJ0ZXN0bmV0Iiwibm9uY2UiOiJkMTE5ODQ2YjQzYzliYzdhZGY4MTI0M2I1ZmU1MDk2N2MwZjBmYWQ0NTZjZjUwMDRhYjEyMGY2YTllYzFhZjlkIiwicGF5ZWUiOiJtZXJjaGFudC5zYW1wYW4tdHJ1c3QtMDEudGVzdG5ldCIsInJlZnVuZF90byI6ImJ1eWVyLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwidiI6InNhbXBhbi5tYW5kYXRlLnYxIn0=";
const F1_R_NEG_ZERO: &str = "eyJtYW5kYXRlIjp7ImFnZW50IjoiYWdlbnQuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJhc3NldCI6InRva2VuLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYnV5ZXIiOiJuZWFyOmVkMjU1MTk6RlZYV2lxamdLTDRhRjI4Y2RIOFZ6Z3RBWGhZeHlGU3J2bmVrRm5qRVNXQ1giLCJleHBpcnlfbnMiOiIxNzk0ODczNjAwMDAwMDAwMDAwIiwiZ2F0ZSI6ImdhdGUuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJpdGVtcyI6WyJyZXBvcnQtMDAxIl0sIm1heF9hbW91bnQiOiI1MDAwMDAwIiwibmV0d29yayI6InRlc3RuZXQiLCJub25jZSI6ImQxMTk4NDZiNDNjOWJjN2FkZjgxMjQzYjVmZTUwOTY3YzBmMGZhZDQ1NmNmNTAwNGFiMTIwZjZhOWVjMWFmOWQiLCJwYXllZSI6Im1lcmNoYW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwicmVmdW5kX3RvIjoiYnV5ZXIuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJ2Ijoic2FtcGFuLm1hbmRhdGUudjEifSwic2lnbmF0dXJlIjoiMDEwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA4MDAxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJzdGFuZGFyZCI6Im5lcDQxMyIsInYiOiJzYW1wYW4uc2lnbmVkLW1hbmRhdGUudjEifQ==";
const CONTROL_VALID: &str = "eyJtYW5kYXRlIjp7ImFnZW50IjoiYWdlbnQuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJhc3NldCI6InRva2VuLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYnV5ZXIiOiJuZWFyOmVkMjU1MTk6RlZYV2lxamdLTDRhRjI4Y2RIOFZ6Z3RBWGhZeHlGU3J2bmVrRm5qRVNXQ1giLCJleHBpcnlfbnMiOiIxNzk0ODczNjAwMDAwMDAwMDAwIiwiZ2F0ZSI6ImdhdGUuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJpdGVtcyI6WyJyZXBvcnQtMDAxIl0sIm1heF9hbW91bnQiOiI1MDAwMDAwIiwibmV0d29yayI6InRlc3RuZXQiLCJub25jZSI6ImQxMTk4NDZiNDNjOWJjN2FkZjgxMjQzYjVmZTUwOTY3YzBmMGZhZDQ1NmNmNTAwNGFiMTIwZjZhOWVjMWFmOWQiLCJwYXllZSI6Im1lcmNoYW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwicmVmdW5kX3RvIjoiYnV5ZXIuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJ2Ijoic2FtcGFuLm1hbmRhdGUudjEifSwic2lnbmF0dXJlIjoiYjA5NGU4YWZlNzA1YzIwMmVjNzk2NDBkZTRjM2QzNDQ0YmEwYzVlYjJmZGY2NzUxNGNlNTE4OGNmZjI2ZWYxNjBkNzFhNzgwZWM1NjJlNjYwY2MxNTE3NmVkMDFkMTc1YmMzZjQwMDBlZjliNDc2YjI3ZDRjYjAxZDQwZGUwMGIiLCJzdGFuZGFyZCI6Im5lcDQxMyIsInYiOiJzYW1wYW4uc2lnbmVkLW1hbmRhdGUudjEifQ==";
const F2_MIXED_R: &str = "eyJtYW5kYXRlIjp7ImFnZW50IjoiYWdlbnQuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJhc3NldCI6InRva2VuLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYnV5ZXIiOiJuZWFyOmVkMjU1MTk6RlZYV2lxamdLTDRhRjI4Y2RIOFZ6Z3RBWGhZeHlGU3J2bmVrRm5qRVNXQ1giLCJleHBpcnlfbnMiOiIxNzk0ODczNjAwMDAwMDAwMDAwIiwiZ2F0ZSI6ImdhdGUuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJpdGVtcyI6WyJyZXBvcnQtMDAxIl0sIm1heF9hbW91bnQiOiI1MDAwMDAwIiwibmV0d29yayI6InRlc3RuZXQiLCJub25jZSI6ImQxMTk4NDZiNDNjOWJjN2FkZjgxMjQzYjVmZTUwOTY3YzBmMGZhZDQ1NmNmNTAwNGFiMTIwZjZhOWVjMWFmOWQiLCJwYXllZSI6Im1lcmNoYW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwicmVmdW5kX3RvIjoiYnV5ZXIuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJ2Ijoic2FtcGFuLm1hbmRhdGUudjEifSwic2lnbmF0dXJlIjoiNzA2M2VhMzNmNGE5OWNmMGE5NGVhOTA1YTAzN2NjMjM2ZjM0OWU3NTFmMTAyOTQzMDZlMGFkMDZlYjFhMWQwYWIwOWQ0ZmE5ZDU3NjM1MGE1ZTE4MzAyODM2ZWU5NTMyZTA5OThjYjZiMWExZmJlMzU5ZmZhOGJiNzAyMTdhMDgiLCJzdGFuZGFyZCI6Im5lcDQxMyIsInYiOiJzYW1wYW4uc2lnbmVkLW1hbmRhdGUudjEifQ==";
const F2_MIXED_A: &str = "eyJtYW5kYXRlIjp7ImFnZW50IjoiYWdlbnQuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJhc3NldCI6InRva2VuLnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwiYnV5ZXIiOiJuZWFyOmVkMjU1MTk6MkU0QTc2NWZ0WnNvTjhHZTlqbVUxenhpeDJRODh0SkNyckNqcjd2NTc4bmYiLCJleHBpcnlfbnMiOiIxNzk0ODczNjAwMDAwMDAwMDAwIiwiZ2F0ZSI6ImdhdGUuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJpdGVtcyI6WyJyZXBvcnQtMDAxIl0sIm1heF9hbW91bnQiOiI1MDAwMDAwIiwibmV0d29yayI6InRlc3RuZXQiLCJub25jZSI6ImM2MzljMmU5ZjQ2NmUwMjA2YWRiYjQ0ZWIxYTgyYTY2Y2M0NDE2NjU2YjRlYjhkYTJkYjhhNjg0OTc0YWRmNmQiLCJwYXllZSI6Im1lcmNoYW50LnNhbXBhbi10cnVzdC0wMS50ZXN0bmV0IiwicmVmdW5kX3RvIjoiYnV5ZXIuc2FtcGFuLXRydXN0LTAxLnRlc3RuZXQiLCJ2Ijoic2FtcGFuLm1hbmRhdGUudjEifSwic2lnbmF0dXJlIjoiNGRlMzZmZTM0MGZjMjNlNDFlYTlmMTA5NTg5ZDQ2OWJkZmMzYjJjMTc0OTdhMzhjNTIzNjNiODc0MzE3NTA4ZTY4NzY4YTZlMDg3MWIxNzBkMWYzNmRiNjM0NmFmNjVkZWNiZTAyZDFjMTMxNzgyMzVlOTFjYTNlMTExYWM4MDQiLCJzdGFuZGFyZCI6Im5lcDQxMyIsInYiOiJzYW1wYW4uc2lnbmVkLW1hbmRhdGUudjEifQ==";

// Sanity: the harness is not vacuous; an honest NEP-413 signature over the same mandate passes.
#[test]
fn m2_control_honest_signature_verifies() {
    assert_eq!(sm(CONTROL_VALID), Ok(()));
}

// M2-01: buyer key 0x01 00..00 80 is the identity point with the x sign bit set (x = 0, x_0 = 1).
// The guard compares against the canonical small-order encodings only, so it passes. NEAR's
// host (ed25519-dalek `verify`) decodes it as the identity, so R = [s]B verifies for ANY
// message: here R = basepoint, S = 1, and payee = attacker.testnet. FORMATS.md 4 requires a
// small-order buyer key to be a `schema` error.
#[test]
fn m2_01_forged_signature_under_negative_zero_identity_key_is_rejected() {
    assert_eq!(sm(F1_FORGED), Err(ErrorCode::Schema));
}

#[test]
fn m2_01_buyer_key_identity_with_sign_bit_is_schema_error() {
    assert_eq!(
        parse_mandate(&b64(F1_MANDATE_K0)).map(|_| ()),
        Err(ErrorCode::Schema)
    );
}

#[test]
fn m2_01_buyer_key_order_two_point_with_sign_bit_is_schema_error() {
    // 0xec ff..ff ff: y = p - 1, x = 0 with the sign bit set: the order-2 point.
    assert_eq!(
        parse_mandate(&b64(F1_MANDATE_K1)).map(|_| ()),
        Err(ErrorCode::Schema)
    );
}

#[test]
fn m2_01_r_identity_with_sign_bit_is_bad_signature_encoding() {
    // FORMATS.md 4: a small-order R is `bad_signature_encoding`; this encoding gets `bad_signature`.
    assert_eq!(sm(F1_R_NEG_ZERO), Err(ErrorCode::BadSignatureEncoding));
}

// M2-02 (pair with the TypeScript test of the same name): signatures that the TypeScript
// verifier (noble, cofactored equation) accepts and NEAR's host (cofactorless) rejects.
// These assertions pass here; the TypeScript side accepts the same bytes.
#[test]
fn m2_02_mixed_order_r_is_rejected_by_the_host() {
    assert!(
        sm(F2_MIXED_R).is_err(),
        "host must reject an R with a torsion component"
    );
}

#[test]
fn m2_02_mixed_order_buyer_key_signature_is_rejected_by_the_host() {
    assert!(sm(F2_MIXED_A).is_err(), "host rejects; TypeScript accepts");
}

// M2-06 (pair with the TypeScript test): a lone surrogate, or nesting deeper than serde_json's
// recursion limit, inside a value that a later duplicate key overwrites. Rust stops at parse
// (`invalid_json`); TypeScript's JSON.parse keeps only the last value and reports `not_canonical`.
// These assertions pass here.
#[test]
fn m2_06_lone_surrogate_in_overwritten_duplicate_is_invalid_json() {
    let doc = br#"{"a":"\ud800","a":"x"}"#;
    assert_eq!(
        parse_canonical(doc, MAX_DOC_BYTES).err(),
        Some(ErrorCode::InvalidJson)
    );
}

#[test]
fn m2_06_deep_nesting_in_overwritten_duplicate_is_invalid_json() {
    let doc = format!(
        "{{\"a\":{}{},\"a\":null}}",
        "[".repeat(130),
        "]".repeat(130)
    );
    assert_eq!(
        parse_canonical(doc.as_bytes(), MAX_DOC_BYTES).err(),
        Some(ErrorCode::InvalidJson)
    );
}
