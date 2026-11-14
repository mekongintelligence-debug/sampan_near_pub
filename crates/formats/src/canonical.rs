//! Canonical JSON (RFC 8785) for our restricted value set, with the same check order as
//! packages/mandate/src/canonical.ts: size, UTF-8, number scan, parse, depth, canonical.
use crate::ErrorCode;
use serde_json::Value;
use std::cmp::Ordering;

pub const MAX_DEPTH: usize = 32;

fn escape_into(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                out.push_str("\\u00");
                out.push_str(&crate::hex_lower(
                    &[u8::try_from(u32::from(c)).unwrap_or(0)],
                ));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Order keys by UTF-16 code units, as RFC 8785 (and JavaScript's default sort) does.
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn write(out: &mut String, v: &Value) -> Result<(), ErrorCode> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::String(s) => escape_into(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape_into(out, k);
                out.push(':');
                write(out, map.get(*k).ok_or(ErrorCode::Schema)?)?;
            }
            out.push('}');
        }
        // Our formats contain no numbers.
        Value::Number(_) => return Err(ErrorCode::Schema),
    }
    Ok(())
}

/// RFC 8785 serialisation of a value without numbers.
pub fn canonicalize(v: &Value) -> Result<String, ErrorCode> {
    let mut out = String::new();
    write(&mut out, v)?;
    Ok(out)
}

fn hex4(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let s = std::str::from_utf8(bytes.get(at..end)?).ok()?;
    if s.bytes().all(|b| b.is_ascii_hexdigit()) {
        u32::from_str_radix(s, 16).ok()
    } else {
        None
    }
}

/// One left-to-right pass over the raw bytes, identical to `rejectNumbers` in
/// packages/mandate/src/canonical.ts; the first violation wins. Escapes are ASCII and
/// UTF-8 multi-byte sequences never contain ASCII bytes, so a byte scan is exact.
fn prescan(text: &str) -> Result<(), ErrorCode> {
    let b = text.as_bytes();
    let mut i: usize = 0;
    let mut in_string = false;
    let mut depth: usize = 0;
    let next = |i: usize, n: usize| i.checked_add(n).ok_or(ErrorCode::InvalidJson);
    while let Some(&c) = b.get(i) {
        if in_string {
            if c == b'"' {
                in_string = false;
            } else if c == b'\\' {
                if b.get(next(i, 1)?) == Some(&b'u') {
                    let u = hex4(b, next(i, 2)?);
                    match u {
                        Some(0xdc00..=0xdfff) => return Err(ErrorCode::InvalidJson),
                        Some(0xd800..=0xdbff) => {
                            let lo = if b.get(next(i, 6)?) == Some(&b'\\')
                                && b.get(next(i, 7)?) == Some(&b'u')
                            {
                                hex4(b, next(i, 8)?)
                            } else {
                                None
                            };
                            if !matches!(lo, Some(0xdc00..=0xdfff)) {
                                return Err(ErrorCode::InvalidJson);
                            }
                            i = next(i, 6)?;
                        }
                        _ => {}
                    }
                    if u.is_some() {
                        i = next(i, 4)?;
                    }
                }
                i = next(i, 1)?;
            }
        } else if c == b'"' {
            in_string = true;
        } else if c == b'[' || c == b'{' {
            depth = depth.saturating_add(1);
            if depth > MAX_DEPTH {
                return Err(ErrorCode::InvalidJson);
            }
        } else if c == b']' || c == b'}' {
            depth = depth.saturating_sub(1);
        } else if c == b'-' || c.is_ascii_digit() {
            return Err(ErrorCode::Schema);
        }
        i = next(i, 1)?;
    }
    Ok(())
}

fn depth(v: &Value) -> usize {
    match v {
        Value::Array(a) => a.iter().map(depth).max().unwrap_or(0).saturating_add(1),
        Value::Object(m) => m.values().map(depth).max().unwrap_or(0).saturating_add(1),
        _ => 0,
    }
}

/// Parse bytes that must already be in canonical form.
pub fn parse_canonical(bytes: &[u8], max_bytes: usize) -> Result<(Value, String), ErrorCode> {
    if bytes.len() > max_bytes {
        return Err(ErrorCode::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ErrorCode::InvalidJson)?;
    prescan(text)?;
    let value: Value = serde_json::from_str(text).map_err(|_| ErrorCode::InvalidJson)?;
    if depth(&value) > MAX_DEPTH {
        return Err(ErrorCode::InvalidJson);
    }
    let canonical = canonicalize(&value)?;
    if canonical != text {
        return Err(ErrorCode::NotCanonical);
    }
    Ok((value, canonical))
}
