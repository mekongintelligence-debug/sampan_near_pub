//! Receipt core (docs/FORMATS.md section 6). The envelope is parsed only by the
//! checker (TypeScript); the contract produces and anchors the core.
use crate::canonical::parse_canonical;
use crate::grammar as g;
use crate::{hash_hex, ErrorCode};
use serde_json::Value;

pub const RULE_IDS: [&str; 9] = ["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"];
const MAX_RECEIPT_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: &'static str,
    pub pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptCore {
    pub network: String,
    pub gate: String,
    pub mandate_hash: String,
    pub order_hash: String,
    pub observed_amount: u128,
    pub observed_asset: String,
    pub rules: Vec<Rule>,
    pub release: bool,
    pub block_height: u64,
}

/// Parse a canonical receipt core; returns it with its hash.
pub fn parse_receipt_core(bytes: &[u8]) -> Result<(ReceiptCore, String), ErrorCode> {
    let (value, text) = parse_canonical(bytes, MAX_RECEIPT_BYTES)?;
    let o = g::closed_object(
        Some(&value),
        &[
            "v",
            "network",
            "gate",
            "mandate_hash",
            "order_hash",
            "observed",
            "rules",
            "decision",
            "block_height",
        ],
    )?;
    let observed = g::closed_object(o.get("observed"), &["amount", "asset"])?;
    let rules_v = o
        .get("rules")
        .and_then(Value::as_array)
        .ok_or(ErrorCode::Schema)?;
    if rules_v.len() != RULE_IDS.len() {
        return Err(ErrorCode::Schema);
    }
    let mut rules = Vec::with_capacity(RULE_IDS.len());
    for (r, id) in rules_v.iter().zip(RULE_IDS) {
        let ro = g::closed_object(Some(r), &["id", "pass"])?;
        g::literal(ro.get("id"), id)?;
        let pass = ro
            .get("pass")
            .and_then(Value::as_bool)
            .ok_or(ErrorCode::Schema)?;
        rules.push(Rule { id, pass });
    }
    let release = match g::str_of(o.get("decision"))? {
        "release" => true,
        "refuse" => false,
        _ => return Err(ErrorCode::Schema),
    };
    if release != rules.iter().all(|r| r.pass) {
        return Err(ErrorCode::Inconsistent);
    }
    g::literal(o.get("v"), "sampan.receipt.v1")?;
    let core = ReceiptCore {
        network: g::network(o.get("network"))?,
        gate: g::account(o.get("gate"))?,
        mandate_hash: g::hex32(o.get("mandate_hash"))?,
        order_hash: g::hex32(o.get("order_hash"))?,
        observed_amount: g::amount(observed.get("amount"))?.1,
        observed_asset: g::account(observed.get("asset"))?,
        rules,
        release,
        block_height: g::u64_dec(o.get("block_height"))?.1,
    };
    Ok((core, hash_hex(text.as_bytes())))
}
