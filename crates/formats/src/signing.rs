//! NEP-413 and ERC-191 payloads and verification (docs/FORMATS.md section 4), using
//! NEAR's own host functions so the contract and these tests share one implementation.
use crate::ErrorCode;
use near_sdk::env;

pub const NEP413_TAG: u32 = 2_147_484_061; // 2^31 + 413

// secp256k1 group order n and n/2, big-endian.
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

fn push_borsh_string(out: &mut Vec<u8>, s: &str) -> Result<(), ErrorCode> {
    let len = u32::try_from(s.len()).map_err(|_| ErrorCode::Schema)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

/// sha256 of the borsh-serialised NEP-413 payload, prefixed by the NEP-413 tag.
pub fn nep413_hash(
    message: &str,
    nonce: &[u8; 32],
    recipient: &str,
) -> Result<[u8; 32], ErrorCode> {
    let mut buf = Vec::with_capacity(
        message
            .len()
            .saturating_add(recipient.len())
            .saturating_add(48),
    );
    buf.extend_from_slice(&NEP413_TAG.to_le_bytes());
    push_borsh_string(&mut buf, message)?;
    buf.extend_from_slice(nonce);
    push_borsh_string(&mut buf, recipient)?;
    buf.push(0); // callback_url: None
    Ok(env::sha256_array(&buf))
}

/// keccak256("\x19Ethereum Signed Message:\n" + decimal length + message).
pub fn erc191_hash(message: &str) -> [u8; 32] {
    let mut buf = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    buf.extend_from_slice(message.as_bytes());
    env::keccak256_array(&buf)
}

fn decode_sig(sig_hex: &str, len: usize) -> Result<Vec<u8>, ErrorCode> {
    crate::decode_hex_lower(sig_hex, len).ok_or(ErrorCode::BadSignatureEncoding)
}

pub(crate) fn verify_nep413(
    public_key: &[u8; 32],
    message: &str,
    nonce: &[u8; 32],
    recipient: &str,
    sig_hex: &str,
) -> Result<(), ErrorCode> {
    let sig: [u8; 64] = decode_sig(sig_hex, 64)?
        .try_into()
        .map_err(|_| ErrorCode::BadSignatureEncoding)?;
    let (r, s) = sig
        .split_at_checked(32)
        .ok_or(ErrorCode::BadSignatureEncoding)?;
    let r: &[u8; 32] = r.try_into().map_err(|_| ErrorCode::BadSignatureEncoding)?;
    let s: &[u8; 32] = s.try_into().map_err(|_| ErrorCode::BadSignatureEncoding)?;
    if !crate::ed25519_guard::is_acceptable_point(r)
        || !crate::ed25519_guard::is_canonical_scalar(s)
    {
        return Err(ErrorCode::BadSignatureEncoding);
    }
    let hash = nep413_hash(message, nonce, recipient)?;
    if env::ed25519_verify(&sig, hash, public_key) {
        Ok(())
    } else {
        Err(ErrorCode::BadSignature)
    }
}

/// Ethereum address bytes (20) of a 64-byte uncompressed public key without the 0x04 prefix.
fn evm_address(pub64: &[u8; 64]) -> Vec<u8> {
    env::keccak256_array(pub64)
        .iter()
        .skip(12)
        .copied()
        .collect()
}

pub(crate) fn verify_erc191(address: &[u8], message: &str, sig_hex: &str) -> Result<(), ErrorCode> {
    let sig = decode_sig(sig_hex, 65)?;
    let (rs, v) = match sig.split_at_checked(64) {
        Some((rs, [v])) => (rs, *v),
        _ => return Err(ErrorCode::BadSignatureEncoding),
    };
    let v = match v {
        0 | 1 => v,
        27 | 28 => v.checked_sub(27).ok_or(ErrorCode::BadSignatureEncoding)?,
        _ => return Err(ErrorCode::BadSignatureEncoding),
    };
    let (r, s) = rs
        .split_at_checked(32)
        .ok_or(ErrorCode::BadSignatureEncoding)?;
    let zero = [0u8; 32];
    // Big-endian byte comparison equals numeric comparison for equal-length arrays.
    if r == zero || s == zero || r >= &N[..] || s >= &N[..] {
        return Err(ErrorCode::BadSignatureEncoding);
    }
    if s > &HALF_N[..] {
        return Err(ErrorCode::HighS);
    }
    let hash = erc191_hash(message);
    let pubkey = env::ecrecover(&hash, rs, v, true).ok_or(ErrorCode::BadSignature)?;
    if evm_address(&pubkey) == address {
        Ok(())
    } else {
        Err(ErrorCode::WrongSigner)
    }
}
