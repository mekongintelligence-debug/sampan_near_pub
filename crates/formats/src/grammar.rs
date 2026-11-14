//! Value grammars (docs/FORMATS.md section 2), identical to packages/mandate/src/grammar.ts.
use crate::ErrorCode;
use serde_json::{Map, Value};

pub(crate) fn str_of(v: Option<&Value>) -> Result<&str, ErrorCode> {
    v.and_then(Value::as_str).ok_or(ErrorCode::Schema)
}

fn is_alnum(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

/// `^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$`, length 2..=64.
pub(crate) fn account(v: Option<&Value>) -> Result<String, ErrorCode> {
    let s = str_of(v)?;
    if s.len() < 2 || s.len() > 64 {
        return Err(ErrorCode::Schema);
    }
    for part in s.split('.') {
        let bytes = part.as_bytes();
        let (first, last) = match (bytes.first(), bytes.last()) {
            (Some(f), Some(l)) => (*f, *l),
            _ => return Err(ErrorCode::Schema),
        };
        if !is_alnum(first) || !is_alnum(last) {
            return Err(ErrorCode::Schema);
        }
        let mut prev_sep = false;
        for &b in bytes {
            let sep = b == b'-' || b == b'_';
            if !(is_alnum(b) || sep) || (sep && prev_sep) {
                return Err(ErrorCode::Schema);
            }
            prev_sep = sep;
        }
    }
    Ok(s.to_string())
}

fn positive_decimal(v: Option<&Value>, max_digits: usize) -> Result<&str, ErrorCode> {
    let s = str_of(v)?;
    let bytes = s.as_bytes();
    match bytes.first() {
        Some(b'1'..=b'9') => {}
        _ => return Err(ErrorCode::Schema),
    }
    if bytes.len() > max_digits || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(ErrorCode::Schema);
    }
    Ok(s)
}

pub(crate) fn amount(v: Option<&Value>) -> Result<(String, u128), ErrorCode> {
    let s = positive_decimal(v, 39)?;
    let n = s.parse::<u128>().map_err(|_| ErrorCode::Schema)?;
    Ok((s.to_string(), n))
}

pub(crate) fn u64_dec(v: Option<&Value>) -> Result<(String, u64), ErrorCode> {
    let s = positive_decimal(v, 20)?;
    let n = s.parse::<u64>().map_err(|_| ErrorCode::Schema)?;
    Ok((s.to_string(), n))
}

pub(crate) fn hex32(v: Option<&Value>) -> Result<String, ErrorCode> {
    let s = str_of(v)?;
    if s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(s.to_string())
    } else {
        Err(ErrorCode::Schema)
    }
}

/// `^[a-z0-9][a-z0-9._-]{0,63}$`
pub(crate) fn item_id(v: Option<&Value>) -> Result<String, ErrorCode> {
    let s = str_of(v)?;
    let bytes = s.as_bytes();
    let ok_first = bytes.first().is_some_and(|b| is_alnum(*b));
    let ok_rest = bytes
        .iter()
        .all(|&b| is_alnum(b) || b == b'.' || b == b'_' || b == b'-');
    if ok_first && ok_rest && bytes.len() <= 64 {
        Ok(s.to_string())
    } else {
        Err(ErrorCode::Schema)
    }
}

pub(crate) fn network(v: Option<&Value>) -> Result<String, ErrorCode> {
    match str_of(v)? {
        s @ ("testnet" | "mainnet") => Ok(s.to_string()),
        _ => Err(ErrorCode::Schema),
    }
}

pub(crate) fn literal(v: Option<&Value>, want: &str) -> Result<(), ErrorCode> {
    if str_of(v)? == want {
        Ok(())
    } else {
        Err(ErrorCode::Schema)
    }
}

/// Decodes canonical base58 of exactly `len` bytes (re-encoding must match).
pub(crate) fn base58_exact(s: &str, len: usize) -> Option<Vec<u8>> {
    if s.len() < 32 || s.len() > 44 {
        return None;
    }
    let bytes = bs58::decode(s).into_vec().ok()?;
    if bytes.len() == len && bs58::encode(&bytes).into_string() == s {
        Some(bytes)
    } else {
        None
    }
}

/// A plain object with exactly the given keys.
pub(crate) fn closed_object<'a>(
    v: Option<&'a Value>,
    keys: &[&str],
) -> Result<&'a Map<String, Value>, ErrorCode> {
    let map = v.and_then(Value::as_object).ok_or(ErrorCode::Schema)?;
    if map.len() != keys.len() || !keys.iter().all(|k| map.contains_key(*k)) {
        return Err(ErrorCode::Schema);
    }
    Ok(map)
}
