//! Mandate, signed mandate and order (docs/FORMATS.md sections 3-5).
use crate::canonical::{canonicalize, parse_canonical};
use crate::grammar as g;
use crate::signing::{verify_erc191, verify_nep413};
use crate::{decode_hex_lower, hash_hex, ErrorCode};
use serde_json::Value;

pub const MAX_DOC_BYTES: usize = 4096;
pub const MAX_ITEMS: usize = 16;
const MANDATE_V1: &str = "sampan.mandate.v1";
const SIGNED_MANDATE_V1: &str = "sampan.signed-mandate.v1";
const ORDER_V1: &str = "sampan.order.v1";
const MANDATE_KEYS: [&str; 12] = [
    "v",
    "network",
    "gate",
    "buyer",
    "agent",
    "asset",
    "max_amount",
    "payee",
    "items",
    "expiry_ns",
    "nonce",
    "refund_to",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Buyer {
    Near { public_key: [u8; 32] },
    Evm { address: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mandate {
    pub network: String,
    pub gate: String,
    pub buyer: Buyer,
    pub agent: Option<String>,
    pub asset: String,
    pub max_amount: u128,
    pub payee: String,
    pub items: Vec<String>,
    pub expiry_ns: u64,
    pub nonce: [u8; 32],
    pub refund_to: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    pub order_id: [u8; 32],
    pub mandate_hash: String,
    pub item: String,
    pub amount: u128,
    pub asset: String,
    pub payee: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standard {
    Nep413,
    Erc191,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMandate {
    pub mandate: Mandate,
    pub mandate_hash: String,
    pub standard: Standard,
}

fn bytes32(hex: &str) -> Result<[u8; 32], ErrorCode> {
    decode_hex_lower(hex, 32)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or(ErrorCode::Schema)
}

fn buyer(v: Option<&Value>) -> Result<Buyer, ErrorCode> {
    let s = g::str_of(v)?;
    if let Some(addr) = s.strip_prefix("evm:0x") {
        let bytes = decode_hex_lower(addr, 20).ok_or(ErrorCode::Schema)?;
        return Ok(Buyer::Evm { address: bytes });
    }
    if let Some(b58) = s.strip_prefix("near:ed25519:") {
        let pk = g::base58_exact(b58, 32)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or(ErrorCode::Schema)?;
        if !crate::ed25519_guard::is_acceptable_point(&pk) {
            return Err(ErrorCode::Schema);
        }
        return Ok(Buyer::Near { public_key: pk });
    }
    Err(ErrorCode::Schema)
}

pub(crate) fn validate_mandate(v: Option<&Value>) -> Result<Mandate, ErrorCode> {
    let o = g::closed_object(v, &MANDATE_KEYS)?;
    let items_v = o
        .get("items")
        .and_then(Value::as_array)
        .ok_or(ErrorCode::Schema)?;
    if items_v.is_empty() || items_v.len() > MAX_ITEMS {
        return Err(ErrorCode::Schema);
    }
    let items = items_v
        .iter()
        .map(|x| g::item_id(Some(x)))
        .collect::<Result<Vec<_>, _>>()?;
    if !items.windows(2).all(|w| matches!(w, [a, b] if a < b)) {
        return Err(ErrorCode::Schema);
    }
    g::literal(o.get("v"), MANDATE_V1)?;
    let agent = match o.get("agent") {
        Some(Value::Null) => None,
        other => Some(g::account(other)?),
    };
    Ok(Mandate {
        network: g::network(o.get("network"))?,
        gate: g::account(o.get("gate"))?,
        buyer: buyer(o.get("buyer"))?,
        agent,
        asset: g::account(o.get("asset"))?,
        max_amount: g::amount(o.get("max_amount"))?.1,
        payee: g::account(o.get("payee"))?,
        items,
        expiry_ns: g::u64_dec(o.get("expiry_ns"))?.1,
        nonce: bytes32(&g::hex32(o.get("nonce"))?)?,
        refund_to: g::account(o.get("refund_to"))?,
    })
}

pub(crate) fn validate_order(v: Option<&Value>) -> Result<Order, ErrorCode> {
    let o = g::closed_object(
        v,
        &[
            "v",
            "order_id",
            "mandate_hash",
            "item",
            "amount",
            "asset",
            "payee",
        ],
    )?;
    g::literal(o.get("v"), ORDER_V1)?;
    Ok(Order {
        order_id: bytes32(&g::hex32(o.get("order_id"))?)?,
        mandate_hash: g::hex32(o.get("mandate_hash"))?,
        item: g::item_id(o.get("item"))?,
        amount: g::amount(o.get("amount"))?.1,
        asset: g::account(o.get("asset"))?,
        payee: g::account(o.get("payee"))?,
    })
}

/// Parse a canonical mandate; returns it with its hash.
pub fn parse_mandate(bytes: &[u8]) -> Result<(Mandate, String), ErrorCode> {
    let (value, text) = parse_canonical(bytes, MAX_DOC_BYTES)?;
    Ok((validate_mandate(Some(&value))?, hash_hex(text.as_bytes())))
}

/// Parse a canonical order; returns it with its hash.
pub fn parse_order(bytes: &[u8]) -> Result<(Order, String), ErrorCode> {
    let (value, text) = parse_canonical(bytes, MAX_DOC_BYTES)?;
    Ok((validate_order(Some(&value))?, hash_hex(text.as_bytes())))
}

/// Parse a canonical signed mandate and verify its signature.
pub fn verify_signed_mandate(bytes: &[u8]) -> Result<VerifiedMandate, ErrorCode> {
    let (value, _) = parse_canonical(bytes, MAX_DOC_BYTES)?;
    let o = g::closed_object(Some(&value), &["v", "mandate", "standard", "signature"])?;
    g::literal(o.get("v"), SIGNED_MANDATE_V1)?;
    let mandate_value = o.get("mandate").ok_or(ErrorCode::Schema)?;
    let mandate = validate_mandate(Some(mandate_value))?;
    let standard = g::str_of(o.get("standard"))?;
    let signature = g::str_of(o.get("signature"))?;
    // The signed message is the canonical mandate; the outer document is canonical,
    // so this equals the mandate's bytes as received.
    let message = canonicalize(mandate_value)?;
    let standard = match (standard, &mandate.buyer) {
        ("nep413", Buyer::Near { public_key }) => {
            verify_nep413(
                public_key,
                &message,
                &mandate.nonce,
                &mandate.gate,
                signature,
            )?;
            Standard::Nep413
        }
        ("erc191", Buyer::Evm { address }) => {
            verify_erc191(address, &message, signature)?;
            Standard::Erc191
        }
        _ => return Err(ErrorCode::UnsupportedStandard),
    };
    Ok(VerifiedMandate {
        mandate,
        mandate_hash: hash_hex(message.as_bytes()),
        standard,
    })
}
