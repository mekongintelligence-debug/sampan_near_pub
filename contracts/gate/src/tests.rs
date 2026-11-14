//! Unit, abuse-case and property tests for the gate on near-sdk's mocked VM
//! (docs/SECURITY.md section 6, M3). Names match docs/audits/M3-threat-review.md.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use near_sdk::test_utils::{get_created_receipts, get_logs, VMContextBuilder};
use near_sdk::{testing_env, PromiseResult, RuntimeFeesConfig};
use proptest::prelude::*;
use sampan_formats::{nep413_hash, parse_receipt_core};

const GATE: &str = "gate.testnet";
const TOKEN: &str = "usdc.testnet";
const AGENT: &str = "agent.testnet";
const PAYEE: &str = "shop.testnet";
const REFUND: &str = "buyer.testnet";
const STRANGER: &str = "stranger.testnet";
const T0: u64 = 1_000_000_000_000;
const EXPIRY: u64 = 2_000_000_000_000;

fn hex32(b: &[u8; 32]) -> String {
    hex_lower(b)
}

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn config() -> Config {
    Config {
        network: "testnet".into(),
        token: acc(TOKEN),
        min_funding: U128(10),
        max_escrow_per_mandate: U128(1_000_000),
        max_total_escrow: U128(3_000_000),
        max_mandates: 8,
        max_orders_per_mandate: 6,
        registration_deposit: U128(1_250_000_000_000_000_000_000),
        max_lifetime_ns: 86_400_000_000_000,
        guardian: None,
    }
}

fn set_ctx(pred: &str, now: u64, gas_tgas: u64, results: Vec<PromiseResult>) {
    let ctx = VMContextBuilder::new()
        .current_account_id(acc(GATE))
        .predecessor_account_id(acc(pred))
        .signer_account_id(acc(pred))
        .block_timestamp(now)
        .block_height(4242)
        .prepaid_gas(Gas::from_tgas(gas_tgas))
        .account_balance(NearToken::from_near(10))
        .build();
    testing_env!(
        ctx,
        near_sdk::test_vm_config(),
        RuntimeFeesConfig::test(),
        Default::default(),
        results
    );
}

fn ctx(pred: &str, now: u64) {
    set_ctx(pred, now, 300, vec![]);
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn implicit(seed: u8) -> String {
    hex32(&key(seed).verifying_key().to_bytes())
}

#[derive(Clone)]
struct Spec {
    network: String,
    gate: String,
    agent: Option<String>,
    asset: String,
    max_amount: u128,
    payee: String,
    items: Vec<String>,
    expiry: u64,
    nonce: u8,
    refund_to: String,
    key_seed: u8,
}

fn spec() -> Spec {
    Spec {
        network: "testnet".into(),
        gate: GATE.into(),
        agent: Some(AGENT.into()),
        asset: TOKEN.into(),
        max_amount: 100,
        payee: PAYEE.into(),
        items: vec!["report-001".into(), "report-002".into()],
        expiry: EXPIRY,
        nonce: 1,
        refund_to: REFUND.into(),
        key_seed: 9,
    }
}

/// A canonical signed mandate (NEP-413) and its mandate hash.
fn signed(s: &Spec) -> (String, String) {
    let k = key(s.key_seed);
    let buyer = format!(
        "near:ed25519:{}",
        bs58::encode(k.verifying_key().to_bytes()).into_string()
    );
    let nonce = [s.nonce; 32];
    let mandate = json!({
        "v": "sampan.mandate.v1",
        "network": s.network,
        "gate": s.gate,
        "buyer": buyer,
        "agent": s.agent,
        "asset": s.asset,
        "max_amount": s.max_amount.to_string(),
        "payee": s.payee,
        "items": s.items,
        "expiry_ns": s.expiry.to_string(),
        "nonce": hex32(&nonce),
        "refund_to": s.refund_to,
    });
    let message = canonicalize(&mandate).unwrap();
    let digest = nep413_hash(&message, &nonce, &s.gate).unwrap();
    let sig = k.sign(&digest).to_bytes();
    let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
    let doc = json!({ "v": "sampan.signed-mandate.v1", "mandate": mandate, "standard": "nep413", "signature": sig_hex });
    let hash = sampan_formats::hash_hex(message.as_bytes());
    (canonicalize(&doc).unwrap(), hash)
}

fn order_doc(
    mandate_hash: &str,
    id: u8,
    item: &str,
    amount: u128,
    asset: &str,
    payee: &str,
) -> String {
    canonicalize(&json!({
        "v": "sampan.order.v1",
        "order_id": hex32(&[id; 32]),
        "mandate_hash": mandate_hash,
        "item": item,
        "amount": amount.to_string(),
        "asset": asset,
        "payee": payee,
    }))
    .unwrap()
}

fn order(mh: &str, id: u8, amount: u128) -> String {
    order_doc(mh, id, "report-001", amount, TOKEN, PAYEE)
}

fn new_gate() -> Gate {
    // Start from empty storage: collections of a dropped gate flush on drop.
    ctx(GATE, T0);
    drop(near_sdk::mock::with_mocked_blockchain(|b| b.take_storage()));
    Gate::new(config()).unwrap()
}

fn msg(signed: &str, order: Option<&str>) -> String {
    json!({ "signed_mandate": signed, "order": order }).to_string()
}

/// Calls ft_on_transfer as the token; returns the amount handed back.
fn fund_as(g: &mut Gate, pred: &str, signed: &str, amount: u128, order: Option<&str>) -> u128 {
    if pred == TOKEN {
        register_from_msg(g, GATE, &msg(signed, order), T0);
    }
    ctx(pred, T0);
    match g.ft_on_transfer(acc("solver.testnet"), U128(amount), msg(signed, order)) {
        PromiseOrValue::Value(v) => v.0,
        PromiseOrValue::Promise(_) => panic!("ft_on_transfer must return a value"),
    }
}

fn fund(g: &mut Gate, signed: &str, amount: u128) -> u128 {
    fund_as(g, TOKEN, signed, amount, None)
}

fn funded_gate(amount: u128) -> (Gate, String) {
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    assert_eq!(fund(&mut g, &s, amount), 0);
    (g, mh)
}

fn purchase_as(g: &mut Gate, pred: &str, now: u64, order: &str) -> Value {
    ctx(pred, now);
    serde_json::from_str(&g.purchase(order.to_string())).unwrap()
}

fn m(g: &Gate, mh: &str) -> MandateView {
    g.get_mandate(mh.to_string()).unwrap()
}

/// Flush the gate's collections and return a copy of the whole contract storage.
fn storage(g: &mut Gate) -> (std::collections::BTreeMap<Vec<u8>, Vec<u8>>, Vec<u8>) {
    g.mandates.flush();
    g.receipts.flush();
    let s = near_sdk::mock::with_mocked_blockchain(|b| b.take_storage());
    let copy = s.clone().into_iter().collect();
    near_sdk::env::set_blockchain_interface(near_sdk::MockedBlockchain::new(
        VMContextBuilder::new()
            .current_account_id(acc(GATE))
            .build(),
        near_sdk::test_vm_config(),
        RuntimeFeesConfig::test(),
        vec![],
        s,
        Default::default(),
        None,
    ));
    (copy, near_sdk::borsh::to_vec(&*g).unwrap())
}

fn events(name: &str) -> Vec<Value> {
    get_logs()
        .iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .map(|j| serde_json::from_str::<Value>(j).unwrap())
        .filter(|e| e["event"] == name)
        .collect()
}

fn function_calls() -> Vec<(String, String, String, u128)> {
    let mut out = vec![];
    for r in get_created_receipts() {
        for a in r.actions {
            if let near_sdk::mock::MockAction::FunctionCallWeight {
                method_name,
                args,
                attached_deposit,
                ..
            } = a
            {
                out.push((
                    r.receiver_id.to_string(),
                    String::from_utf8(method_name).unwrap(),
                    String::from_utf8(args).unwrap(),
                    attached_deposit.as_yoctonear(),
                ));
            }
        }
    }
    out
}

fn payout_cb(
    g: &mut Gate,
    order_id: u8,
    mh: &str,
    amount: u128,
    account: &str,
    registering: bool,
    ok: bool,
) -> bool {
    let r = if ok {
        PromiseResult::Successful(vec![])
    } else {
        PromiseResult::Failed
    };
    set_ctx(GATE, T0, 300, vec![r]);
    g.on_payout(
        hex32(&[order_id; 32]),
        mh.to_string(),
        U128(amount),
        acc(account),
        registering,
    )
}

// ---- initialisation -------------------------------------------------------------------

#[test]
fn init_rejects_bad_config() {
    ctx(GATE, T0);
    let mut c = config();
    c.network = "localnet".into();
    assert!(Gate::new(c).is_err());
    let mut c = config();
    c.min_funding = U128(0);
    assert!(Gate::new(c).is_err());
    let mut c = config();
    c.max_escrow_per_mandate = U128(1);
    assert!(Gate::new(c).is_err());
    let mut c = config();
    c.max_orders_per_mandate = 0;
    assert!(Gate::new(c).is_err());
}

#[test]
fn reports_version() {
    let g = new_gate();
    assert_eq!(g.version(), VERSION);
    assert_eq!(g.get_config(), config());
}

// ---- funding --------------------------------------------------------------------------

#[test]
fn funding_credits_escrow() {
    let (g, mh) = funded_gate(80);
    let v = m(&g, &mh);
    assert_eq!((v.funded.0, v.escrow.0, v.spent.0), (80, 80, 0));
    assert_eq!(events("funded").len(), 1);
    assert_eq!(g.get_totals()["total_escrow"], "80");
}

#[test]
fn abuse_fake_token_credit() {
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    assert_eq!(fund_as(&mut g, "fake-usdc.testnet", &s, 50, None), 50);
    assert!(g.get_mandate(mh).is_none());
    assert_eq!(
        events("funding_refused")[0]["data"][0]["reason"],
        "wrong_token"
    );
}

/// Register `signed` as the relayer, with the full deposit, at `now`; returns the answer.
fn register_at(g: &mut Gate, signed: &str, now: u64, deposit: u128) -> Value {
    let c = VMContextBuilder::new()
        .current_account_id(acc(GATE))
        .predecessor_account_id(acc("relayer.testnet"))
        .block_timestamp(now)
        .block_height(4242)
        .prepaid_gas(Gas::from_tgas(300))
        .account_balance(NearToken::from_near(10))
        .attached_deposit(NearToken::from_yoctonear(deposit))
        .build();
    testing_env!(c);
    serde_json::from_str(&g.register_mandate(signed.to_string())).unwrap()
}

fn reserve() -> u128 {
    config().reservation_per_mandate()
}

/// R1, R2, asset and expiry are checked at registration (audit A1 redesign); a payment that
/// names an unregistered mandate is then handed back in full.
fn assert_registration_refused(sp: Spec, reason: &str) {
    let mut g = new_gate();
    let (s, mh) = signed(&sp);
    let r = register_at(&mut g, &s, T0, reserve());
    assert_eq!(
        (r["registered"].as_bool(), r["reason"].as_str()),
        (Some(false), Some(reason))
    );
    assert!(
        g.get_mandate(mh.clone()).is_none(),
        "{reason}: nothing stored"
    );
    // The whole deposit goes back to the relayer.
    let back: u128 = near_sdk::test_utils::get_created_receipts()
        .into_iter()
        .flat_map(|r| r.actions)
        .filter_map(|a| match a {
            near_sdk::mock::MockAction::Transfer { deposit, .. } => Some(deposit.as_yoctonear()),
            _ => None,
        })
        .sum();
    assert_eq!(back, reserve(), "{reason}: deposit returned");
    ctx(TOKEN, T0);
    assert!(matches!(
        g.ft_on_transfer(acc(REFUND), U128(50), msg(&s, None)),
        PromiseOrValue::Value(U128(50))
    ));
    assert_eq!(
        events("funding_refused")[0]["data"][0]["reason"],
        "unknown_mandate"
    );
}

#[test]
fn funding_rejects_wrong_network() {
    let mut s = spec();
    s.network = "mainnet".into();
    assert_registration_refused(s, "wrong_network");
}

#[test]
fn funding_rejects_wrong_gate() {
    let mut s = spec();
    s.gate = "other-gate.testnet".into();
    assert_registration_refused(s, "wrong_gate");
}

#[test]
fn funding_rejects_wrong_asset() {
    let mut s = spec();
    s.asset = "fake-usdc.testnet".into();
    assert_registration_refused(s, "wrong_asset");
}

#[test]
fn funding_rejects_expired_and_exact_expiry() {
    let mut s = spec();
    s.expiry = T0;
    assert_registration_refused(s, "expired");
}

#[test]
fn funding_over_budget_keeps_the_excess_for_the_buyer() {
    // A1P-02: never handed back to the sender; the excess is refund due for refund_to.
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    assert_eq!(fund(&mut g, &s, 101), 0);
    let v = m(&g, &mh);
    assert_eq!((v.escrow.0, v.refund_due.0, v.funded.0), (100, 1, 101));
}

#[test]
fn small_payments_are_accepted_because_the_registrant_paid_storage() {
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    assert_eq!(fund(&mut g, &s, 1), 0);
    assert_eq!(m(&g, &mh).escrow.0, 1);
}

#[test]
fn funding_rejects_zero_amount() {
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    assert_eq!(fund(&mut g, &s, 0), 0);
    assert_eq!(
        events("funding_refused")[0]["data"][0]["reason"],
        "zero_amount"
    );
    assert_eq!(m(&g, &mh).funded.0, 0);
}

#[test]
fn funding_above_the_mandate_escrow_cap_is_refund_due() {
    let mut g = new_gate();
    let mut sp = spec();
    sp.max_amount = 2_000_000;
    let (s, mh) = signed(&sp);
    assert_eq!(fund(&mut g, &s, 1_000_001), 0);
    let v = m(&g, &mh);
    assert_eq!((v.escrow.0, v.refund_due.0), (1_000_000, 1));
}

#[test]
fn funding_rejects_tampered_signature() {
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    let tampered = s.replace("\"max_amount\":\"100\"", "\"max_amount\":\"900\"");
    assert_ne!(tampered, s);
    assert_eq!(fund(&mut g, &tampered, 50), 50);
    assert!(g.get_mandate(mh).is_none());
    assert_eq!(
        events("funding_refused")[0]["data"][0]["reason"],
        "mandate_invalid"
    );
}

#[test]
fn funding_rejects_malformed_msg() {
    let mut g = new_gate();
    for bad in [
        "",
        "{",
        "null",
        "{\"signed_mandate\":\"x\",\"order\":null,\"extra\":1}",
        "{\"order\":null}",
    ] {
        ctx(TOKEN, T0);
        let r = g.ft_on_transfer(acc(REFUND), U128(50), bad.to_string());
        assert!(matches!(r, PromiseOrValue::Value(U128(50))), "{bad}");
    }
    ctx(TOKEN, T0);
    let huge = "a".repeat(MAX_MSG_BYTES + 1);
    assert!(matches!(
        g.ft_on_transfer(acc(REFUND), U128(50), huge),
        PromiseOrValue::Value(U128(50))
    ));
    assert_eq!(g.get_totals()["mandates"], 0);
}

#[test]
fn funding_same_mandate_tops_up_only_when_unexpired() {
    let (mut g, mh) = funded_gate(40);
    let (s, _) = signed(&spec());
    assert_eq!(fund(&mut g, &s, 60), 0);
    assert_eq!(m(&g, &mh).escrow.0, 100);
    // Beyond max_amount: kept as refund due, not handed back (A1P-02).
    assert_eq!(fund(&mut g, &s, 1), 0);
    assert_eq!(m(&g, &mh).refund_due.0, 1);
    // After expiry: the whole payment is refund due.
    let (mut g, mh) = funded_gate(40);
    ctx(TOKEN, EXPIRY);
    assert!(matches!(
        g.ft_on_transfer(acc(REFUND), U128(10), msg(&s, None)),
        PromiseOrValue::Value(U128(0))
    ));
    let v = m(&g, &mh);
    assert_eq!((v.escrow.0, v.refund_due.0), (40, 10));
}

#[test]
fn funding_rejects_nonce_reuse_by_other_mandate() {
    let (mut g, _) = funded_gate(40);
    let mut other = spec();
    other.items = vec!["report-009".into()]; // different mandate, same nonce
    let (s2, mh2) = signed(&other);
    assert_eq!(fund(&mut g, &s2, 40), 40);
    assert!(g.get_mandate(mh2).is_none());
}

#[test]
fn registration_cap_and_total_escrow_cap() {
    let mut g = new_gate();
    for n in 0..8u8 {
        let mut sp = spec();
        sp.nonce = 10 + n;
        assert_eq!(
            register_at(&mut g, &signed(&sp).0, T0, reserve())["registered"],
            true
        );
    }
    let mut sp = spec();
    sp.nonce = 99;
    assert_eq!(
        register_at(&mut g, &signed(&sp).0, T0, reserve())["reason"],
        "mandate_cap"
    );

    // The total escrow cap: what does not fit is refund due, never handed back.
    let mut g = new_gate();
    for n in 0..3u8 {
        let mut sp = spec();
        sp.nonce = 30 + n;
        sp.max_amount = 1_000_000;
        assert_eq!(fund(&mut g, &signed(&sp).0, 1_000_000), 0);
    }
    let mut sp = spec();
    sp.nonce = 40;
    let (s, mh) = signed(&sp);
    assert_eq!(fund(&mut g, &s, 10), 0);
    let v = m(&g, &mh);
    assert_eq!((v.escrow.0, v.refund_due.0), (0, 10));
}

// ---- purchase: release ----------------------------------------------------------------

#[test]
fn purchase_releases_and_pays_payee() {
    let (mut g, mh) = funded_gate(100);
    let r = purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 40));
    assert_eq!(r["decision"], "release");
    assert_eq!(r["anchored"], true);
    let v = m(&g, &mh);
    assert_eq!((v.spent.0, v.escrow.0, v.orders), (40, 60, 1));
    let calls = function_calls();
    let transfer = calls.iter().find(|c| c.1 == "ft_transfer").unwrap();
    assert_eq!(transfer.0, TOKEN);
    let args: Value = serde_json::from_str(&transfer.2).unwrap();
    assert_eq!(args["receiver_id"], PAYEE);
    assert_eq!(args["amount"], "40");
    assert_eq!(transfer.3, 1, "1 yocto");
    assert!(calls.iter().any(|c| c.0 == GATE && c.1 == "on_payout"));
    let rec = g.get_receipt(mh.clone(), hex32(&[1; 32])).unwrap();
    assert_eq!(
        (rec.decision.as_str(), rec.payout),
        ("release", Payout::Pending)
    );
}

#[test]
fn every_decision_has_receipt() {
    let (mut g, mh) = funded_gate(100);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 40));
    purchase_as(
        &mut g,
        AGENT,
        T0,
        &order_doc(&mh, 2, "report-999", 1, TOKEN, PAYEE),
    );
    for (id, decision) in [(1u8, "release"), (2, "refuse")] {
        let rec = g.get_receipt(mh.clone(), hex32(&[id; 32])).unwrap();
        assert_eq!(rec.decision, decision);
    }
    // The emitted core parses as sampan.receipt.v1 and hashes to the stored anchor.
    ctx(AGENT, T0);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 3, 10));
    let ev = &events("receipt")[0]["data"][0];
    let core = canonicalize(&ev["core"]).unwrap();
    let (parsed, hash) = parse_receipt_core(core.as_bytes()).unwrap();
    assert_eq!(hash, ev["core_hash"]);
    assert_eq!(
        hash,
        g.get_receipt(mh.clone(), hex32(&[3; 32]))
            .unwrap()
            .core_hash
    );
    assert_eq!(parsed.mandate_hash, mh);
    assert_eq!(parsed.observed_amount, 10);
    assert_eq!(parsed.observed_asset, TOKEN);
    assert_eq!(parsed.block_height, 4242);
    assert!(parsed.release);
}

#[test]
fn event_contains_only_checked_values() {
    let (mut g, mh) = funded_gate(100);
    let logs_fund = get_logs();
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 40));
    let mut all = logs_fund;
    all.extend(get_logs());
    for l in &all {
        let j = l
            .strip_prefix("EVENT_JSON:")
            .expect("every log is a NEP-297 event");
        let e: Value = serde_json::from_str(j).unwrap();
        assert_eq!(e["standard"], "sampan");
        assert_eq!(e["version"], "1.0.0");
        assert!(e["data"].is_array());
        assert!(
            !l.contains("solver.testnet"),
            "the untrusted sender is never logged"
        );
        assert!(l.is_ascii());
    }
}

// ---- purchase: each rule --------------------------------------------------------------

fn assert_anchored_refusal(g: &mut Gate, mh: &str, order_text: &str, failing: usize) {
    let before = m(g, mh);
    let r = purchase_as(g, AGENT, T0, order_text);
    assert_eq!(r["decision"], "refuse");
    assert_eq!(r["anchored"], true);
    let after = m(g, mh);
    assert_eq!(
        (after.spent, after.escrow),
        (before.spent, before.escrow),
        "a refusal moves no funds"
    );
    assert!(function_calls().is_empty(), "no transfer on refusal");
    let ev = &events("receipt")[0]["data"][0];
    let rules = ev["core"]["rules"].as_array().unwrap();
    let failed: Vec<usize> = rules
        .iter()
        .enumerate()
        .filter(|(_, r)| r["pass"] == false)
        .map(|(i, _)| i)
        .collect();
    assert!(
        failed.contains(&failing),
        "rule index {failing} failed: {failed:?}"
    );
    assert_eq!(ev["core"]["decision"], "refuse");
}

#[test]
fn rule_r3_expired_refused_and_anchored() {
    let (mut g, mh) = funded_gate(100);
    let before = m(&g, &mh);
    let r = purchase_as(&mut g, AGENT, EXPIRY, &order(&mh, 1, 10));
    assert_eq!(
        (r["decision"].as_str(), r["anchored"].as_bool()),
        (Some("refuse"), Some(true))
    );
    assert_eq!(m(&g, &mh).escrow, before.escrow);
    assert_eq!(
        events("receipt")[0]["data"][0]["core"]["rules"][2]["pass"],
        false
    );
    // One nanosecond earlier still passes.
    let r = purchase_as(&mut g, AGENT, EXPIRY - 1, &order(&mh, 2, 10));
    assert_eq!(r["decision"], "release");
}

#[test]
fn rule_r4_order_replay_refused_without_state() {
    let (mut g, mh) = funded_gate(100);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 10));
    let before = m(&g, &mh);
    let r = purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 10));
    assert_eq!(
        (r["anchored"].as_bool(), r["reason"].as_str()),
        (Some(false), Some("order_used"))
    );
    assert_eq!(m(&g, &mh), before);
    // Same ID with a different body is also refused, and the first receipt is untouched.
    let core = g
        .get_receipt(mh.clone(), hex32(&[1; 32]))
        .unwrap()
        .core_hash;
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 11));
    assert_eq!(
        g.get_receipt(mh.clone(), hex32(&[1; 32]))
            .unwrap()
            .core_hash,
        core
    );
}

#[test]
fn abuse_order_replay() {
    let (mut g, mh) = funded_gate(100);
    for _ in 0..5 {
        purchase_as(&mut g, AGENT, T0, &order(&mh, 7, 30));
    }
    assert_eq!(m(&g, &mh).spent.0, 30, "only the first one pays");
}

#[test]
fn rule_r5_stranger_refused_without_state() {
    let (mut g, mh) = funded_gate(100);
    let before = m(&g, &mh);
    for who in [STRANGER, PAYEE, REFUND, TOKEN, GATE] {
        let r = purchase_as(&mut g, who, T0, &order(&mh, 1, 10));
        assert_eq!(
            (r["anchored"].as_bool(), r["reason"].as_str()),
            (Some(false), Some("not_authorised")),
            "{who}"
        );
    }
    assert_eq!(m(&g, &mh), before);
    assert!(g.get_receipt(mh.clone(), hex32(&[1; 32])).is_none());
}

#[test]
fn abuse_stranger_spam_no_state() {
    let (mut g, mh) = funded_gate(100);
    let before = storage(&mut g);
    for id in 0..50u8 {
        purchase_as(&mut g, STRANGER, T0, &order(&mh, id, 10));
    }
    purchase_as(&mut g, STRANGER, T0, &order(&"ab".repeat(32), 1, 10));
    purchase_as(&mut g, STRANGER, T0, "not an order");
    refund_as(&mut g, STRANGER, T0, &mh);
    assert_eq!(storage(&mut g), before, "strangers write no state");
}

#[test]
fn rule_r6_wrong_asset() {
    let (mut g, mh) = funded_gate(100);
    assert_anchored_refusal(
        &mut g,
        &mh,
        &order_doc(&mh, 1, "report-001", 10, "fake-usdc.testnet", PAYEE),
        5,
    );
}

#[test]
fn rule_r7_one_above_remaining_budget() {
    let (mut g, mh) = funded_gate(100);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 60));
    assert_anchored_refusal(&mut g, &mh, &order(&mh, 2, 41), 6);
    let r = purchase_as(&mut g, AGENT, T0, &order(&mh, 3, 40));
    assert_eq!(r["decision"], "release", "exactly the remaining budget");
    assert_eq!(m(&g, &mh).escrow.0, 0);
}

#[test]
fn rule_r7_order_above_escrow_observed() {
    let (mut g, mh) = funded_gate(30); // budget 100, only 30 funded
    assert_anchored_refusal(&mut g, &mh, &order(&mh, 1, 31), 6);
    let (mut g2, mh2) = funded_gate(30);
    purchase_as(&mut g2, AGENT, T0, &order(&mh2, 1, 31));
    assert_eq!(
        events("receipt")[0]["data"][0]["core"]["observed"]["amount"],
        "30"
    );
    assert_eq!(
        purchase_as(&mut g, AGENT, T0, &order(&mh, 2, 30))["decision"],
        "release"
    );
}

#[test]
fn rule_r8_wrong_payee() {
    let (mut g, mh) = funded_gate(100);
    assert_anchored_refusal(
        &mut g,
        &mh,
        &order_doc(&mh, 1, "report-001", 10, TOKEN, "attacker.testnet"),
        7,
    );
}

#[test]
fn rule_r9_wrong_item() {
    let (mut g, mh) = funded_gate(100);
    assert_anchored_refusal(
        &mut g,
        &mh,
        &order_doc(&mh, 1, "report-003", 10, TOKEN, PAYEE),
        8,
    );
}

#[test]
fn purchase_unknown_mandate_and_invalid_order() {
    let (mut g, _) = funded_gate(100);
    let r = purchase_as(&mut g, AGENT, T0, &order(&"cd".repeat(32), 1, 10));
    assert_eq!(r["reason"], "unknown_mandate");
    for bad in [
        "",
        "{}",
        "{\"v\":\"sampan.order.v1\"}",
        &"x".repeat(MAX_DOC_BYTES + 1),
    ] {
        assert_eq!(
            purchase_as(&mut g, AGENT, T0, bad)["reason"],
            "order_invalid"
        );
    }
    // Non-canonical (whitespace) order is refused.
    let (_, mh) = signed(&spec());
    let spaced = order(&mh, 1, 10).replacen(',', ", ", 1);
    assert_eq!(
        purchase_as(&mut g, AGENT, T0, &spaced)["reason"],
        "order_invalid"
    );
}

#[test]
fn abuse_budget_split() {
    let (mut g, mh) = funded_gate(100);
    for (id, amount) in [(1u8, 40u128), (2, 40)] {
        assert_eq!(
            purchase_as(&mut g, AGENT, T0, &order(&mh, id, amount))["decision"],
            "release"
        );
    }
    assert_eq!(
        purchase_as(&mut g, AGENT, T0, &order(&mh, 3, 30))["decision"],
        "refuse"
    );
    assert_eq!(
        purchase_as(&mut g, AGENT, T0, &order(&mh, 4, 20))["decision"],
        "release"
    );
    assert_eq!(
        purchase_as(&mut g, AGENT, T0, &order(&mh, 5, 1))["decision"],
        "refuse"
    );
    let v = m(&g, &mh);
    assert_eq!((v.spent.0, v.escrow.0), (100, 0));
}

#[test]
fn abuse_storage_caps() {
    let (mut g, mh) = funded_gate(100);
    for id in 0..6u8 {
        let r = purchase_as(
            &mut g,
            AGENT,
            T0,
            &order_doc(&mh, id, "report-404", 1, TOKEN, PAYEE),
        );
        assert_eq!(r["anchored"], true);
    }
    let before = storage(&mut g);
    let r = purchase_as(&mut g, AGENT, T0, &order(&mh, 50, 1));
    assert_eq!(
        (r["anchored"].as_bool(), r["reason"].as_str()),
        (Some(false), Some("order_cap"))
    );
    assert_eq!(storage(&mut g), before);
}

#[test]
fn purchase_with_too_little_gas_is_refused_without_state() {
    let (mut g, mh) = funded_gate(100);
    let before = m(&g, &mh);
    set_ctx(AGENT, T0, 40, vec![]);
    let r: Value = serde_json::from_str(&g.purchase(order(&mh, 1, 10))).unwrap();
    assert_eq!(r["reason"], "insufficient_gas");
    assert_eq!(m(&g, &mh), before);
    assert!(g.get_receipt(mh.clone(), hex32(&[1; 32])).is_none());
}

#[test]
fn no_escrow_refused_without_state() {
    let (mut g, mh) = funded_gate(100);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 100));
    let r = purchase_as(&mut g, AGENT, T0, &order(&mh, 2, 1));
    assert_eq!(r["reason"], "no_escrow");
}

// ---- payout callback ------------------------------------------------------------------

#[test]
fn payout_success_marks_done() {
    let (mut g, mh) = funded_gate(100);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 40));
    let registering = function_calls().iter().any(|c| c.1 == "storage_deposit");
    assert!(payout_cb(&mut g, 1, &mh, 40, PAYEE, registering, true));
    assert_eq!(
        g.get_receipt(mh.clone(), hex32(&[1; 32])).unwrap().payout,
        Payout::Done
    );
    assert_eq!(m(&g, &mh).spent.0, 40);
}

#[test]
fn payout_failure_restores_state() {
    let (mut g, mh) = funded_gate(100);
    let before = m(&g, &mh);
    let total_before = g.get_totals()["total_escrow"].clone();
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 40));
    assert!(!payout_cb(&mut g, 1, &mh, 40, PAYEE, true, false));
    let after = m(&g, &mh);
    assert_eq!(
        (after.spent, after.escrow, after.funded),
        (before.spent, before.escrow, before.funded)
    );
    assert_eq!(g.get_totals()["total_escrow"], total_before);
    assert_eq!(
        g.get_totals()["registrations"],
        0,
        "registration slot released"
    );
    assert_eq!(
        g.get_receipt(mh.clone(), hex32(&[1; 32])).unwrap().payout,
        Payout::Failed
    );
    // The order ID stays used; the agent retries with a new ID.
    assert_eq!(
        purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 40))["reason"],
        "order_used"
    );
    assert_eq!(
        purchase_as(&mut g, AGENT, T0, &order(&mh, 2, 40))["decision"],
        "release"
    );
}

#[test]
fn abuse_callback_not_private() {
    let (mut g, mh) = funded_gate(100);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 40));
    let before = m(&g, &mh);
    // A forged "failed" callback would hand the 40 back to escrow while the payee is paid.
    for who in [STRANGER, AGENT, TOKEN, PAYEE] {
        set_ctx(who, T0, 300, vec![PromiseResult::Failed]);
        assert!(!g.on_payout(hex32(&[1; 32]), mh.clone(), U128(40), acc(PAYEE), false));
    }
    assert_eq!(m(&g, &mh), before);
    assert_eq!(
        g.get_receipt(mh.clone(), hex32(&[1; 32])).unwrap().payout,
        Payout::Pending
    );
}

#[test]
fn abuse_refund_callback_not_private() {
    let (mut g, mh) = funded_gate(100);
    refund_as(&mut g, STRANGER, EXPIRY, &mh);
    let before = m(&g, &mh);
    set_ctx(STRANGER, EXPIRY, 300, vec![PromiseResult::Failed]);
    assert!(!g.on_refund(mh.clone(), U128(100), acc(REFUND), false));
    assert_eq!(m(&g, &mh), before);
}

#[test]
fn registration_paid_once_then_skipped() {
    let (mut g, mh) = funded_gate(100);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 10));
    let calls = function_calls();
    let reg = calls
        .iter()
        .find(|c| c.1 == "storage_deposit")
        .expect("first payout registers payee");
    let args: Value = serde_json::from_str(&reg.2).unwrap();
    assert_eq!(args["account_id"], PAYEE);
    assert_eq!(reg.3, config().registration_deposit.0);
    payout_cb(&mut g, 1, &mh, 10, PAYEE, true, true);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 2, 10));
    assert!(
        !function_calls().iter().any(|c| c.1 == "storage_deposit"),
        "already registered"
    );
}

#[test]
fn registrations_at_most_two_per_mandate() {
    // A1P-04, A1C-05: payee and refund_to; the deposit covers two.
    let (mut g, mh) = funded_gate(100);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 10));
    assert!(function_calls().iter().any(|c| c.1 == "storage_deposit"));
    purchase_as(&mut g, AGENT, T0, &order(&mh, 2, 10));
    assert!(
        function_calls().iter().any(|c| c.1 == "storage_deposit"),
        "second slot"
    );
    purchase_as(&mut g, AGENT, T0, &order(&mh, 3, 10));
    assert!(
        !function_calls().iter().any(|c| c.1 == "storage_deposit"),
        "no third"
    );
    // A failed registering batch gives its slot back.
    payout_cb(&mut g, 1, &mh, 10, PAYEE, true, false);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 4, 10));
    assert!(function_calls().iter().any(|c| c.1 == "storage_deposit"));
}

// ---- refund ---------------------------------------------------------------------------

fn refund_as(g: &mut Gate, pred: &str, now: u64, mh: &str) -> Value {
    ctx(pred, now);
    serde_json::from_str(&g.refund(mh.to_string())).unwrap()
}

#[test]
fn refund_before_expiry_refused() {
    let (mut g, mh) = funded_gate(100);
    assert_eq!(
        refund_as(&mut g, REFUND, EXPIRY - 1, &mh)["reason"],
        "not_expired"
    );
    assert_eq!(m(&g, &mh).escrow.0, 100);
}

#[test]
fn refund_after_expiry_by_stranger_goes_to_refund_to() {
    let (mut g, mh) = funded_gate(100);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 30));
    let r = refund_as(&mut g, STRANGER, EXPIRY, &mh);
    assert_eq!(r["refund"], "pending");
    assert_eq!(r["amount"], "70");
    let calls = function_calls();
    let t = calls.iter().find(|c| c.1 == "ft_transfer").unwrap();
    let args: Value = serde_json::from_str(&t.2).unwrap();
    assert_eq!(args["receiver_id"], REFUND);
    assert_eq!(args["amount"], "70");
    let v = m(&g, &mh);
    assert_eq!(
        (v.escrow.0, v.refunded.0, v.spent.0, v.funded.0),
        (0, 70, 30, 100)
    );
}

#[test]
fn refund_twice_and_nothing_left() {
    let (mut g, mh) = funded_gate(100);
    refund_as(&mut g, STRANGER, EXPIRY, &mh);
    assert_eq!(
        refund_as(&mut g, STRANGER, EXPIRY, &mh)["reason"],
        "nothing_to_refund"
    );
    assert_eq!(
        refund_as(&mut g, STRANGER, EXPIRY, &"ef".repeat(32))["reason"],
        "unknown_mandate"
    );
    assert_eq!(
        refund_as(&mut g, STRANGER, EXPIRY, "\u{202e}x")["reason"],
        "invalid_mandate_hash"
    );
}

#[test]
fn refund_failure_restores_to_refund_due() {
    let (mut g, mh) = funded_gate(100);
    refund_as(&mut g, STRANGER, EXPIRY, &mh);
    set_ctx(GATE, EXPIRY, 300, vec![PromiseResult::Failed]);
    assert!(!g.on_refund(mh.clone(), U128(100), acc(REFUND), true));
    let v = m(&g, &mh);
    // Still owed only to refund_to, and payable again at once.
    assert_eq!((v.escrow.0, v.refund_due.0, v.refunded.0), (0, 100, 0));
    assert_eq!(g.get_totals()["total_refund_due"], "100");
    assert_eq!(
        refund_as(&mut g, STRANGER, EXPIRY, &mh)["refund"],
        "pending",
        "retry allowed"
    );
}

#[test]
fn purchase_racing_refund() {
    let (mut g, mh) = funded_gate(100);
    // Purchase in flight, then expiry and refund, then the payout fails.
    purchase_as(&mut g, AGENT, EXPIRY - 1, &order(&mh, 1, 40));
    assert_eq!(refund_as(&mut g, STRANGER, EXPIRY, &mh)["amount"], "60");
    payout_cb(&mut g, 1, &mh, 40, PAYEE, true, false);
    let v = m(&g, &mh);
    assert_eq!((v.escrow.0, v.refunded.0, v.spent.0), (40, 60, 0));
    // The restored 40 can be refunded too; a purchase after expiry is refused.
    assert_eq!(
        purchase_as(&mut g, AGENT, EXPIRY, &order(&mh, 2, 40))["decision"],
        "refuse"
    );
    assert_eq!(refund_as(&mut g, STRANGER, EXPIRY, &mh)["amount"], "40");
}

#[test]
fn two_purchases_same_block() {
    let (mut g, mh) = funded_gate(100);
    assert_eq!(
        purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 60))["decision"],
        "release"
    );
    assert_eq!(
        purchase_as(&mut g, AGENT, T0, &order(&mh, 2, 60))["decision"],
        "refuse"
    );
    assert_eq!(m(&g, &mh).spent.0, 60);
}

// ---- direct checkout (agent null) -----------------------------------------------------

fn agentless() -> Spec {
    let mut s = spec();
    s.agent = None;
    s.max_amount = 25;
    s.nonce = 5;
    s
}

#[test]
fn direct_checkout_order_in_funding_message_releases() {
    let mut g = new_gate();
    let (s, mh) = signed(&agentless());
    let o = order(&mh, 1, 25);
    assert_eq!(fund_as(&mut g, TOKEN, &s, 25, Some(&o)), 0);
    let rec = g.get_receipt(mh.clone(), hex32(&[1; 32])).unwrap();
    assert_eq!(rec.decision, "release");
    assert!(function_calls().iter().any(|c| c.1 == "ft_transfer"));
    assert_eq!(m(&g, &mh).escrow.0, 0);
}

#[test]
fn direct_checkout_refused_order_is_refundable_at_once() {
    let mut g = new_gate();
    let (s, mh) = signed(&agentless());
    let o = order_doc(&mh, 1, "report-001", 25, TOKEN, "attacker.testnet");
    assert_eq!(fund_as(&mut g, TOKEN, &s, 25, Some(&o)), 0);
    // Changed for A1R-02 (docs/audits/A1R.md): a refused order inside a payment is no
    // longer anchored, so strangers cannot fill the order cap; the refusal is an event.
    assert!(g.get_receipt(mh.clone(), hex32(&[1; 32])).is_none());
    assert!(near_sdk::test_utils::get_logs()
        .iter()
        .any(|l| l.contains("\"refused\"") && l.contains("order_refused")));
    assert_eq!(m(&g, &mh).orders, 0, "no order slot used");
    let v = m(&g, &mh);
    assert_eq!((v.escrow.0, v.refund_due.0), (0, 25));
    // A1P-07: no need to wait for expiry.
    assert_eq!(refund_as(&mut g, STRANGER, T0, &mh)["amount"], "25");
}

#[test]
fn order_in_message_to_an_agent_mandate_is_ignored_and_the_payment_kept() {
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    let o = order(&mh, 1, 25);
    assert_eq!(fund_as(&mut g, TOKEN, &s, 25, Some(&o)), 0);
    assert_eq!(m(&g, &mh).escrow.0, 25);
    assert!(g.get_receipt(mh, hex32(&[1; 32])).is_none());
}

#[test]
fn order_in_message_must_match_mandate() {
    let mut g = new_gate();
    let (s, mh) = signed(&agentless());
    let o = order(&"12".repeat(32), 1, 25);
    assert_eq!(fund_as(&mut g, TOKEN, &s, 25, Some(&o)), 0);
    assert_eq!(fund_as(&mut g, TOKEN, &s, 25, Some("{")), 0);
    let v = m(&g, &mh);
    assert_eq!(
        (v.escrow.0, v.refund_due.0, v.spent.0),
        (0, 50, 0),
        "both payments owed to the buyer"
    );
}

#[test]
fn agentless_purchase_only_by_buyer_implicit_account() {
    let mut g = new_gate();
    let sp = agentless();
    let (s, mh) = signed(&sp);
    fund(&mut g, &s, 25);
    assert_eq!(
        purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 25))["reason"],
        "not_authorised"
    );
    let buyer = implicit(sp.key_seed);
    assert_eq!(
        purchase_as(&mut g, &buyer, T0, &order(&mh, 1, 25))["decision"],
        "release"
    );
}

// ---- property tests: invariants of docs/SECURITY.md 6.0 -------------------------------

#[derive(Debug, Clone)]
enum Op {
    Fund {
        mandate: usize,
        amount: u128,
    },
    Purchase {
        mandate: usize,
        caller_ok: bool,
        amount: u128,
        item_ok: bool,
        payee_ok: bool,
    },
    Settle {
        ok: bool,
    },
    Refund {
        mandate: usize,
        ok: bool,
    },
    Advance,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0..3usize, 1..120u128).prop_map(|(mandate, amount)| Op::Fund { mandate, amount }),
        (
            0..3usize,
            any::<bool>(),
            1..120u128,
            any::<bool>(),
            any::<bool>()
        )
            .prop_map(
                |(mandate, caller_ok, amount, item_ok, payee_ok)| Op::Purchase {
                    mandate,
                    caller_ok,
                    amount,
                    item_ok,
                    payee_ok
                }
            ),
        any::<bool>().prop_map(|ok| Op::Settle { ok }),
        (0..3usize, any::<bool>()).prop_map(|(mandate, ok)| Op::Refund { mandate, ok }),
        Just(Op::Advance),
    ]
}

proptest! {
    // A1C-10: PROPTEST_CASES sets the depth (make fuzz runs many cases); 64 by default.
    #![proptest_config({
        let cases: u32 = std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(64);
        ProptestConfig { cases, ..ProptestConfig::default() }
    })]

    #[test]
    fn invariants_hold(ops in proptest::collection::vec(op(), 1..40)) {
        let mut g = new_gate();
        let specs: Vec<Spec> = (0..3u8).map(|i| { let mut s = spec(); s.nonce = 60 + i; s }).collect();
        let docs: Vec<(String, String)> = specs.iter().map(signed).collect();
        // Since the A1 redesign mandates are registered before payments; without this the
        // payments would all bounce and the invariants below would hold vacuously.
        for (s, _) in &docs {
            prop_assert_eq!(register_at(&mut g, s, T0, reserve())["registered"].as_bool(), Some(true));
        }
        let mut now = T0;
        let mut next_id = 0u8;
        let mut pending: Vec<(u8, String, u128, bool)> = vec![];
        let mut credited: u128 = 0; // tokens kept by the gate
        let mut sent: u128 = 0;     // tokens leaving the gate (settled)
        let mut in_flight: u128 = 0;
        let mut seen_ids = std::collections::HashSet::new();
        for o in ops {
            match o {
                Op::Fund { mandate, amount } => {
                    let open = g.get_mandate(docs[mandate].1.clone()).is_some();
                    set_ctx(TOKEN, now, 300, vec![]);
                    if let PromiseOrValue::Value(back) = g.ft_on_transfer(acc("solver.testnet"), U128(amount), msg(&docs[mandate].0, None)) {
                        // Never handed back while the mandate exists (A1P-02); after it closed
                        // (expired, empty, settled) nobody knows refund_to any more, so the
                        // payment returns to the sender (residual covered by A1P-07's margin).
                        prop_assert_eq!(back.0, if open { 0 } else { amount }, "a payment to an open mandate is never handed back");
                        credited += amount - back.0;
                    }
                }
                Op::Purchase { mandate, caller_ok, amount, item_ok, payee_ok } => {
                    let mh = &docs[mandate].1;
                    let before = g.get_mandate(mh.clone());
                    next_id = next_id.wrapping_add(1);
                    let o = order_doc(mh, next_id, if item_ok { "report-001" } else { "report-777" }, amount, TOKEN, if payee_ok { PAYEE } else { "attacker.testnet" });
                    set_ctx(if caller_ok { AGENT } else { STRANGER }, now, 300, vec![]);
                    let r: Value = serde_json::from_str(&g.purchase(o)).unwrap();
                    let calls = function_calls();
                    for c in calls.iter().filter(|c| c.1 == "ft_transfer") {
                        let a: Value = serde_json::from_str(&c.2).unwrap();
                        prop_assert_eq!(a["receiver_id"].as_str(), Some(PAYEE), "transfers only to the payee");
                    }
                    if r["decision"] == "release" {
                        prop_assert!(caller_ok && item_ok && payee_ok && now < EXPIRY);
                        prop_assert!(seen_ids.insert(next_id), "an order ID pays once");
                        let reg = calls.iter().any(|c| c.1 == "storage_deposit");
                        pending.push((next_id, mh.clone(), amount, reg));
                        in_flight += amount;
                    } else {
                        prop_assert_eq!(g.get_mandate(mh.clone()).map(|v| (v.spent, v.escrow)), before.map(|v| (v.spent, v.escrow)), "a refusal moves no funds");
                        prop_assert!(calls.is_empty());
                    }
                }
                Op::Settle { ok } => {
                    if let Some((id, mh, amount, reg)) = pending.pop() {
                        payout_cb(&mut g, id, &mh, amount, PAYEE, reg, ok);
                        in_flight -= amount;
                        if ok { sent += amount; }
                    }
                }
                Op::Refund { mandate, ok } => {
                    set_ctx(STRANGER, now, 300, vec![]);
                    let r: Value = serde_json::from_str(&g.refund(docs[mandate].1.clone())).unwrap();
                    if r["refund"] == "pending" {
                        let amount: u128 = r["amount"].as_str().unwrap().parse().unwrap();
                        // Before expiry only refund due may be paid out (A1P-02, A1P-07).
                        prop_assert!(now >= EXPIRY || r["amount"] != "0");
                        let t = function_calls().into_iter().find(|c| c.1 == "ft_transfer").unwrap();
                        let a: Value = serde_json::from_str(&t.2).unwrap();
                        prop_assert_eq!(a["receiver_id"].as_str(), Some(REFUND), "refunds only to refund_to");
                        // Settle refunds at once, failing at random (A1C-10): a failed
                        // refund must be restored as refund due, never lost.
                        let result = if ok { PromiseResult::Successful(vec![]) } else { PromiseResult::Failed };
                        set_ctx(GATE, now, 300, vec![result]);
                        g.on_refund(docs[mandate].1.clone(), U128(amount), acc(REFUND), false);
                        if ok { sent += amount; }
                    }
                }
                Op::Advance => now = EXPIRY,
            }
            // Invariants after every step.
            let (mut sum_escrow, mut sum_due) = (0u128, 0u128);
            for (_, mh) in &docs {
                if let Some(v) = g.get_mandate(mh.clone()) {
                    prop_assert_eq!(v.funded.0, v.spent.0 + v.escrow.0 + v.refunded.0 + v.refund_due.0, "funded = spent + escrow + refunded + refund due");
                    prop_assert!(v.spent.0 <= v.max_amount.0, "never above budget");
                    prop_assert!(v.spent.0 + v.escrow.0 <= v.max_amount.0, "escrow never exceeds the budget left");
                    sum_escrow += v.escrow.0;
                    sum_due += v.refund_due.0;
                }
            }
            let total: u128 = g.get_totals()["total_escrow"].as_str().unwrap().parse().unwrap();
            let total_due: u128 = g.get_totals()["total_refund_due"].as_str().unwrap().parse().unwrap();
            prop_assert_eq!(total, sum_escrow, "total escrow = sum of escrows");
            prop_assert_eq!(total_due, sum_due, "total refund due = sum of refund due");
            prop_assert_eq!(sum_escrow + sum_due + in_flight, credited - sent, "held + in flight = credited - sent");
        }
    }
}

// ---- regression tests: self-review findings (docs/audits/M3.md) -----------------------

#[test]
fn m3_cr1_other_buyer_cannot_squat_a_nonce() {
    let mut g = new_gate();
    // The attacker funds their own mandate (own key) with the victim's nonce first.
    let mut attacker = spec();
    attacker.key_seed = 66;
    attacker.agent = Some("attacker.testnet".into());
    let (sa, _) = signed(&attacker);
    assert_eq!(fund(&mut g, &sa, 10), 0);
    let (sv, mhv) = signed(&spec());
    assert_eq!(
        fund(&mut g, &sv, 50),
        0,
        "the victim's mandate is still accepted"
    );
    assert_eq!(m(&g, &mhv).escrow.0, 50);
    // The same buyer still cannot reuse a nonce for a different mandate.
    let mut again = spec();
    again.items = vec!["report-777".into()];
    assert_eq!(fund(&mut g, &signed(&again).0, 10), 10);
}

#[test]
fn m3_cr2_order_id_cannot_be_claimed_by_another_mandate() {
    let mut g = new_gate();
    let mut attacker = spec();
    attacker.key_seed = 66;
    attacker.nonce = 2;
    attacker.agent = Some("attacker.testnet".into());
    attacker.payee = "attacker.testnet".into();
    let (sa, mha) = signed(&attacker);
    fund(&mut g, &sa, 10);
    let (sv, mh) = signed(&spec());
    fund(&mut g, &sv, 100);
    // The attacker uses the victim's order ID first, on their own mandate.
    let squat = order_doc(&mha, 1, "report-001", 10, TOKEN, "attacker.testnet");
    assert_eq!(
        purchase_as(&mut g, "attacker.testnet", T0, &squat)["decision"],
        "release"
    );
    // The victim's order with that ID is still decided on its own mandate.
    assert_eq!(
        purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 40))["decision"],
        "release"
    );
    assert_eq!(
        g.get_receipt(mh.clone(), hex32(&[1; 32]))
            .unwrap()
            .mandate_hash,
        mh
    );
    assert_eq!(
        g.get_receipt(mha.clone(), hex32(&[1; 32]))
            .unwrap()
            .mandate_hash,
        mha
    );
}

#[test]
fn m3_cr4_init_rejects_registration_deposit_outside_bounds() {
    ctx(GATE, T0);
    for bad in [
        0,
        1_000_000_000_000_000_000_000,
        MAX_REGISTRATION_DEPOSIT + 1,
    ] {
        let mut c = config();
        c.registration_deposit = U128(bad);
        assert!(Gate::new(c).is_err(), "{bad}");
    }
    let mut c = config();
    c.registration_deposit = U128(MIN_REGISTRATION_DEPOSIT);
    assert!(Gate::new(c).is_ok());
}

#[test]
fn m3_cr5_gas_is_checked_after_the_work_and_never_aborts() {
    // Across a range of prepaid gas, a release either happens with its promises or is
    // refused without state; nothing in between.
    for tgas in (40..=130).step_by(2) {
        let (mut g, mh) = funded_gate(100);
        let before = m(&g, &mh);
        set_ctx(AGENT, T0, tgas, vec![]);
        let r: Value = serde_json::from_str(&g.purchase(order(&mh, 1, 10))).unwrap();
        if r["decision"] == "release" {
            assert!(
                function_calls().iter().any(|c| c.1 == "on_payout"),
                "{tgas} Tgas"
            );
            assert!(gas_left() > 0);
        } else {
            assert_eq!(r["reason"], "insufficient_gas", "{tgas} Tgas");
            assert_eq!(m(&g, &mh), before);
        }
    }
}

#[test]
fn m3_cr7_impossible_restore_is_flagged() {
    let (mut g, mh) = funded_gate(100);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 40));
    // A callback claiming more than was spent cannot be restored: flagged, not hidden.
    assert!(!payout_cb(&mut g, 1, &mh, 41, PAYEE, false, false));
    assert_eq!(events("internal")[0]["data"][0]["reason"], "restore_failed");
    assert_eq!(
        g.get_receipt(mh.clone(), hex32(&[1; 32])).unwrap().payout,
        Payout::Pending
    );
    assert_eq!(m(&g, &mh).spent.0, 40, "nothing changed");
}

// ---- mutation-testing survivors (docs/audits/M3-mutants.md) ---------------------------

#[test]
fn mutants_config_caps_may_equal_min_funding() {
    ctx(GATE, T0);
    let mut c = config();
    c.max_escrow_per_mandate = c.min_funding;
    c.max_total_escrow = c.min_funding;
    assert!(Gate::new(c).is_ok(), "caps equal to min_funding are valid");
    let mut c = config();
    c.max_total_escrow = U128(c.min_funding.0 - 1);
    assert!(Gate::new(c).is_err());
}

#[test]
fn mutants_refund_rejects_non_hex32_hashes() {
    let (mut g, _) = funded_gate(100);
    for bad in [
        "ab".repeat(31) + "a",
        "ab".repeat(32) + "a",
        "AB".repeat(32),
        "zz".repeat(32),
    ] {
        assert_eq!(
            refund_as(&mut g, STRANGER, EXPIRY, &bad)["reason"],
            "invalid_mandate_hash",
            "{bad}"
        );
    }
}

#[test]
fn mutants_refund_with_too_little_gas_is_refused_without_state() {
    let (mut g, mh) = funded_gate(100);
    set_ctx(STRANGER, EXPIRY, 40, vec![]);
    let r: Value = serde_json::from_str(&g.refund(mh.clone())).unwrap();
    assert_eq!(r["reason"], "insufficient_gas");
    assert_eq!(m(&g, &mh).escrow.0, 100);
}

#[test]
fn mutants_funding_msg_size_boundary() {
    let (s, mh) = signed(&spec());
    let base = msg(&s, None);
    // Exactly the limit (JSON whitespace padding) is accepted; one byte more is not.
    let mut g = new_gate();
    register_at(&mut g, &s, T0, reserve());
    let exact = format!("{base}{}", " ".repeat(MAX_MSG_BYTES - base.len()));
    ctx(TOKEN, T0);
    assert!(matches!(
        g.ft_on_transfer(acc(REFUND), U128(50), exact),
        PromiseOrValue::Value(U128(0))
    ));
    assert_eq!(m(&g, &mh).escrow.0, 50);
    let mut g = new_gate();
    let over = format!("{base}{}", " ".repeat(MAX_MSG_BYTES + 1 - base.len()));
    ctx(TOKEN, T0);
    assert!(matches!(
        g.ft_on_transfer(acc(REFUND), U128(50), over),
        PromiseOrValue::Value(U128(50))
    ));
    assert_eq!(
        events("funding_refused")[0]["data"][0]["reason"],
        "msg_too_large"
    );
}

#[test]
fn mutants_payout_event_names_its_status() {
    let (mut g, mh) = funded_gate(100);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 10));
    payout_cb(&mut g, 1, &mh, 10, PAYEE, true, true);
    assert_eq!(events("payout")[0]["data"][0]["status"], "done");
    purchase_as(&mut g, AGENT, T0, &order(&mh, 2, 10));
    payout_cb(&mut g, 2, &mh, 10, PAYEE, false, false);
    assert_eq!(events("payout")[0]["data"][0]["status"], "failed");
}

#[test]
fn m3_11_callbacks_complete_within_their_static_gas() {
    // Heaviest paths: a failed payout (restore + receipt update + event) and a refund
    // that closes the mandate, each with exactly GAS_CALLBACK prepaid.
    let (mut g, mh) = funded_gate(100);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 40));
    set_ctx(
        GATE,
        T0,
        GAS_CALLBACK.as_tgas(),
        vec![PromiseResult::Failed],
    );
    assert!(!g.on_payout(hex32(&[1; 32]), mh.clone(), U128(40), acc(PAYEE), true));
    assert_eq!(m(&g, &mh).escrow.0, 100);
    refund_as(&mut g, STRANGER, EXPIRY, &mh);
    set_ctx(
        GATE,
        EXPIRY,
        GAS_CALLBACK.as_tgas(),
        vec![PromiseResult::Successful(vec![])],
    );
    assert!(g.on_refund(mh.clone(), U128(100), acc(REFUND), true));
    assert!(g.get_mandate(mh).is_none(), "closed");
}

#[test]
fn m3_02_closed_mandate_cannot_be_funded_again() {
    let (mut g, mh) = funded_gate(100);
    refund_as(&mut g, STRANGER, EXPIRY, &mh);
    set_ctx(GATE, EXPIRY, 300, vec![PromiseResult::Successful(vec![])]);
    assert!(g.on_refund(mh.clone(), U128(100), acc(REFUND), false));
    assert!(g.get_mandate(mh.clone()).is_none());
    assert_eq!(g.get_totals()["mandates"], 0);
    // Replaying the same signed mandate after it closed is refused (expired).
    let (s, _) = signed(&spec());
    ctx(TOKEN, EXPIRY);
    assert!(matches!(
        g.ft_on_transfer(acc(REFUND), U128(10), msg(&s, None)),
        PromiseOrValue::Value(U128(10))
    ));
    // Receipts of a closed mandate stay readable.
    let (mut g, mh) = funded_gate(100);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 100));
    payout_cb(&mut g, 1, &mh, 100, PAYEE, true, true);
    assert_eq!(refund_as(&mut g, STRANGER, EXPIRY, &mh)["refund"], "closed");
    assert_eq!(
        g.get_receipt(mh, hex32(&[1; 32])).unwrap().payout,
        Payout::Done
    );
}

// ---- mutation-testing survivors after the audit fixes (docs/audits/M3-mutants.md) -----

#[test]
fn mutants_registration_deposit_covers_storage_and_two_registrations() {
    let per = config().reservation_per_mandate();
    assert_eq!(
        per,
        (2_400 + 6 * 450) * 10_000_000_000_000_000_000 + 2 * 1_250_000_000_000_000_000_000
    );
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    assert_eq!(
        register_at(&mut g, &s, T0, per - 1)["reason"],
        "deposit_too_small"
    );
    assert!(g.get_mandate(mh.clone()).is_none());
    // A surplus is returned at once; the mandate keeps exactly the reservation.
    assert_eq!(register_at(&mut g, &s, T0, per + 5)["registered"], true);
    let back: u128 = near_sdk::test_utils::get_created_receipts()
        .into_iter()
        .flat_map(|r| r.actions)
        .filter_map(|a| match a {
            near_sdk::mock::MockAction::Transfer { deposit, .. } => Some(deposit.as_yoctonear()),
            _ => None,
        })
        .sum();
    assert_eq!(back, 5);
    assert_eq!(
        register_at(&mut g, &s, T0, per)["reason"],
        "already_registered"
    );
}

#[test]
fn mutants_refund_registers_refund_to_after_the_payee() {
    // A1C-05: the payee's registration used one slot; the refund may use the second.
    let (mut g, mh) = funded_gate(100);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 40));
    payout_cb(&mut g, 1, &mh, 40, PAYEE, true, true);
    refund_as(&mut g, STRANGER, EXPIRY, &mh);
    let regs: Vec<_> = function_calls()
        .into_iter()
        .filter(|c| c.1 == "storage_deposit")
        .collect();
    assert_eq!(regs.len(), 1);
    assert!(regs[0].2.contains(REFUND));
}

#[test]
fn mutants_registered_refund_to_is_not_registered_again() {
    let (mut g, mh) = funded_gate(100);
    refund_as(&mut g, STRANGER, EXPIRY, &mh);
    assert!(function_calls().iter().any(|c| c.1 == "storage_deposit"));
    set_ctx(GATE, EXPIRY, 300, vec![PromiseResult::Failed]);
    assert!(!g.on_refund(mh.clone(), U128(100), acc(REFUND), false));
    // The refund failed for another reason; refund_to is not registered by the gate yet, so
    // the retry may register it once more, but a registered account never again.
    set_ctx(GATE, EXPIRY, 300, vec![PromiseResult::Successful(vec![])]);
    refund_as(&mut g, STRANGER, EXPIRY, &mh);
    set_ctx(GATE, EXPIRY, 300, vec![PromiseResult::Successful(vec![])]);
    assert!(g.on_refund(mh.clone(), U128(100), acc(REFUND), true));
    // refund_to is now registered with the token by the gate: another mandate refunding to
    // it pays no registration.
    let mut sp = spec();
    sp.nonce = 77;
    let (s2, mh2) = signed(&sp);
    assert_eq!(fund(&mut g, &s2, 10), 0);
    refund_as(&mut g, STRANGER, EXPIRY, &mh2);
    assert!(!function_calls().iter().any(|c| c.1 == "storage_deposit"));
}

/// Audit A1 redesign (6-7 Nov 2026): a mandate is registered, with a deposit that pays its
/// storage, before any payment. This test helper registers the mandate carried in a funding
/// message (as the Sampan relayer would) just before the payment, or just before expiry for
/// late payments. Mechanical adaptation of the funding helpers; assertions are unchanged.
fn register_from_msg(g: &mut Gate, gate: &str, msg: &str, now: u64) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(msg) else {
        return;
    };
    let Some(text) = v["signed_mandate"].as_str() else {
        return;
    };
    let Ok(vm) = sampan_formats::verify_signed_mandate(text.as_bytes()) else {
        return;
    };
    if g.get_mandate(vm.mandate_hash.clone()).is_some() {
        return;
    }
    let at = now.min(vm.mandate.expiry_ns.saturating_sub(1));
    let deposit = g.get_config().reservation_per_mandate();
    let c = near_sdk::test_utils::VMContextBuilder::new()
        .current_account_id(gate.parse().unwrap())
        .predecessor_account_id("relayer.testnet".parse().unwrap())
        .block_timestamp(at)
        .block_height(4242)
        .prepaid_gas(near_sdk::Gas::from_tgas(300))
        .account_balance(near_sdk::NearToken::from_near(10))
        .attached_deposit(near_sdk::NearToken::from_yoctonear(deposit))
        .build();
    near_sdk::testing_env!(c);
    let _ = g.register_mandate(text.to_string());
}

// ---- regression tests: audit A1 (docs/audits/A1-contract.md, A1-payments.md) ----------

fn gate_with_guardian() -> Gate {
    ctx(GATE, T0);
    drop(near_sdk::mock::with_mocked_blockchain(|b| b.take_storage()));
    ctx(GATE, T0);
    let mut c = config();
    c.guardian = Some(acc("guardian.testnet"));
    Gate::new(c).unwrap()
}

#[test]
fn a1c_03_only_the_guardian_can_stop_and_the_stop_is_one_way() {
    let mut g = gate_with_guardian();
    let (s, mh) = signed(&spec());
    assert_eq!(fund(&mut g, &s, 100), 0);
    for who in [STRANGER, AGENT, GATE, PAYEE] {
        ctx(who, T0);
        assert_eq!(
            serde_json::from_str::<Value>(&g.stop()).unwrap()["reason"],
            "not_guardian",
            "{who}"
        );
    }
    assert_eq!(g.get_totals()["stopped"], false);
    ctx("guardian.testnet", T0);
    assert_eq!(
        serde_json::from_str::<Value>(&g.stop()).unwrap()["stopped"],
        true
    );
    assert_eq!(g.get_totals()["stopped"], true);
    // No new mandates, no purchases; payments are kept for the buyer; refunds still work.
    let mut sp = spec();
    sp.nonce = 2;
    assert_eq!(
        register_at(&mut g, &signed(&sp).0, T0, reserve())["reason"],
        "stopped"
    );
    assert_eq!(
        purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 10))["reason"],
        "stopped"
    );
    assert_eq!(fund(&mut g, &s, 5), 0);
    let v = m(&g, &mh);
    assert_eq!((v.escrow.0, v.refund_due.0), (100, 5));
    assert_eq!(
        refund_as(&mut g, STRANGER, T0, &mh)["amount"],
        "5",
        "refund due is paid even while stopped"
    );
    // The stop cannot be undone: there is no method for it, and stopping again changes nothing.
    ctx("guardian.testnet", T0);
    g.stop();
    assert_eq!(g.get_totals()["stopped"], true);
}

#[test]
fn a1c_03_without_a_guardian_nobody_can_stop() {
    let mut g = new_gate();
    ctx("guardian.testnet", T0);
    assert_eq!(
        serde_json::from_str::<Value>(&g.stop()).unwrap()["reason"],
        "not_guardian"
    );
}

#[test]
fn a1c_01_lifetime_is_bounded_at_registration_and_in_the_config() {
    let mut g = new_gate();
    let mut sp = spec();
    sp.expiry = T0 + 86_400_000_000_000 + 1; // one nanosecond over the 24-hour limit
    assert_eq!(
        register_at(&mut g, &signed(&sp).0, T0, reserve())["reason"],
        "lifetime_too_long"
    );
    sp.expiry = T0 + 86_400_000_000_000;
    assert_eq!(
        register_at(&mut g, &signed(&sp).0, T0, reserve())["registered"],
        true
    );
    ctx(GATE, T0);
    for bad in [0, MIN_LIFETIME_NS - 1, MAX_LIFETIME_NS + 1] {
        let mut c = config();
        c.max_lifetime_ns = bad;
        drop(near_sdk::mock::with_mocked_blockchain(|b| b.take_storage()));
        ctx(GATE, T0);
        assert!(Gate::new(c).is_err(), "{bad}");
    }
}

#[test]
fn a1c_02_closing_returns_the_deposit_minus_what_the_mandate_leaves_behind() {
    let (mut g, mh) = funded_gate(100);
    purchase_as(
        &mut g,
        AGENT,
        T0,
        &order_doc(&mh, 1, "report-404", 1, TOKEN, PAYEE),
    ); // refusal: a receipt stays
    refund_as(&mut g, STRANGER, EXPIRY, &mh);
    set_ctx(GATE, EXPIRY, 300, vec![PromiseResult::Successful(vec![])]);
    assert!(g.on_refund(mh.clone(), U128(100), acc(REFUND), true));
    assert!(g.get_mandate(mh).is_none(), "closed");
    let back: u128 = near_sdk::test_utils::get_created_receipts()
        .into_iter()
        .filter(|r| r.receiver_id.as_str() == "relayer.testnet")
        .flat_map(|r| r.actions)
        .filter_map(|a| match a {
            near_sdk::mock::MockAction::Transfer { deposit, .. } => Some(deposit.as_yoctonear()),
            _ => None,
        })
        .sum();
    // One receipt and one registration (refund_to) were charged; the rest came back.
    assert!(back > 0 && back < reserve(), "{back}");
    assert!(
        reserve() - back >= 1_250_000_000_000_000_000_000,
        "the registration paid for this mandate is kept"
    );
}

#[test]
fn a1p_03_payment_order_must_be_the_exact_price_and_buys_once() {
    let mut g = new_gate();
    let (s, mh) = signed(&agentless()); // exact price 25
                                        // A partial unsigned order is not decided; that payment is owed to the buyer.
    assert_eq!(fund_as(&mut g, TOKEN, &s, 10, Some(&order(&mh, 1, 10))), 0);
    assert!(g.get_receipt(mh.clone(), hex32(&[1; 32])).is_none());
    // The exact price is paid once; a second order in a later payment is not.
    assert_eq!(fund_as(&mut g, TOKEN, &s, 25, Some(&order(&mh, 2, 25))), 0);
    assert_eq!(
        g.get_receipt(mh.clone(), hex32(&[2; 32])).unwrap().decision,
        "release"
    );
    assert_eq!(fund_as(&mut g, TOKEN, &s, 25, Some(&order(&mh, 3, 25))), 0);
    assert!(g.get_receipt(mh.clone(), hex32(&[3; 32])).is_none());
    let v = m(&g, &mh);
    assert_eq!(
        (v.spent.0, v.escrow.0, v.refund_due.0),
        (25, 0, 35),
        "everything else is owed to the buyer"
    );
}

#[test]
fn a1p_01_a_payment_may_name_the_mandate_by_hash() {
    let mut g = new_gate();
    let (s, mh) = signed(&agentless());
    assert_eq!(register_at(&mut g, &s, T0, reserve())["registered"], true);
    let o = order(&mh, 1, 25);
    let short = json!({ "mandate_hash": mh, "order": o }).to_string();
    assert!(
        short.len() <= 1024,
        "fits 1Click's customRecipientMsg limit: {}",
        short.len()
    );
    ctx(TOKEN, T0);
    assert!(matches!(
        g.ft_on_transfer(acc("1click.testnet"), U128(25), short),
        PromiseOrValue::Value(U128(0))
    ));
    assert_eq!(
        g.get_receipt(mh.clone(), hex32(&[1; 32])).unwrap().decision,
        "release"
    );
    // Both forms at once, an unknown hash, or a malformed hash are handed back.
    for bad in [
        json!({ "mandate_hash": mh, "signed_mandate": s, "order": null }).to_string(),
        json!({ "mandate_hash": "ab".repeat(32), "order": null }).to_string(),
        json!({ "mandate_hash": "XYZ", "order": null }).to_string(),
    ] {
        ctx(TOKEN, T0);
        assert!(matches!(
            g.ft_on_transfer(acc("1click.testnet"), U128(7), bad),
            PromiseOrValue::Value(U128(7))
        ));
    }
}

#[test]
fn a1r_05_fund_overflow_is_handed_back_without_state() {
    let mut g = new_gate();
    let (s, mh) = signed(&agentless());
    assert_eq!(fund_as(&mut g, TOKEN, &s, 30, None), 0);
    let before = m(&g, &mh);
    // A second payment that would overflow `funded` is refused before any write.
    assert_eq!(fund_as(&mut g, TOKEN, &s, u128::MAX, None), u128::MAX);
    let after = m(&g, &mh);
    assert_eq!(
        (after.funded.0, after.escrow.0, after.refund_due.0),
        (before.funded.0, before.escrow.0, before.refund_due.0)
    );
}

#[test]
fn m7_10_a_testnet_mandate_cannot_be_registered_on_a_mainnet_gate() {
    // The reverse of e2e N3 (cross-network replay): a gate on mainnet refuses a mandate signed
    // for testnet, even when it names this gate's account.
    let mainnet_gate = "gate.near";
    let at = |pred: &str, deposit: u128| {
        let c = VMContextBuilder::new()
            .current_account_id(acc(mainnet_gate))
            .predecessor_account_id(acc(pred))
            .block_timestamp(T0)
            .block_height(4242)
            .prepaid_gas(Gas::from_tgas(300))
            .account_balance(NearToken::from_near(10))
            .attached_deposit(NearToken::from_yoctonear(deposit))
            .build();
        testing_env!(c);
    };
    at(mainnet_gate, 0);
    drop(near_sdk::mock::with_mocked_blockchain(|b| b.take_storage()));
    at(mainnet_gate, 0);
    let mut c = config();
    c.network = "mainnet".into();
    let mut g = Gate::new(c).unwrap();
    let mut sp = spec();
    sp.gate = mainnet_gate.into();
    sp.network = "testnet".into();
    at("relayer.near", reserve());
    let r: Value = serde_json::from_str(&g.register_mandate(signed(&sp).0)).unwrap();
    assert_eq!(r["reason"], "wrong_network");
    assert!(g.get_mandate(signed(&sp).1).is_none());
    // Control: the same mandate signed for mainnet registers.
    sp.network = "mainnet".into();
    at("relayer.near", reserve());
    let r: Value = serde_json::from_str(&g.register_mandate(signed(&sp).0)).unwrap();
    assert_eq!(r["registered"], true);
}

/// A1P-10 (raised again by audit A2): the first mainnet purchase is an EVM buyer's direct
/// checkout. An ERC-191 agentless mandate, signed in TypeScript with a throwaway key
/// (`node scripts/tests/gen-erc191-gate-fixture.mjs` reproduces it), is registered, paid by hash
/// with the exact-price order, released to the payee once, and its overpayment refunded only to
/// the buyer's own Ethereum-style NEAR account.
const ERC191_SIGNED: &str = r#"{"mandate":{"agent":null,"asset":"usdc.testnet","buyer":"evm:0xe5c41f1539c85b54011fd933398abf751917f926","expiry_ns":"2000000000000","gate":"gate.testnet","items":["report-001"],"max_amount":"25","network":"testnet","nonce":"e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1","payee":"shop.testnet","refund_to":"0xe5c41f1539c85b54011fd933398abf751917f926","v":"sampan.mandate.v1"},"signature":"be9c8a6c831975f7cbcb8910a10992fd17df25cd98cadf3e350f669200828bae4e6bc4a7e0105cdfb194007f07aa75390d05852340797506aed72a1a77e87b551c","standard":"erc191","v":"sampan.signed-mandate.v1"}"#;
const ERC191_HASH: &str = "9072a57c0ffce8c410356135abb0827a3f3890528e9dd45d5b6c6d79b8cfa76b";
const ERC191_REFUND: &str = "0xe5c41f1539c85b54011fd933398abf751917f926";

#[test]
fn a1p_10_erc191_direct_checkout_is_registered_paid_and_released() {
    let mut g = new_gate();
    let r = register_at(&mut g, ERC191_SIGNED, T0, reserve());
    assert_eq!(
        (r["registered"].as_bool(), r["mandate_hash"].as_str()),
        (Some(true), Some(ERC191_HASH)),
        "{r}"
    );
    // The 1Click form: the mandate by hash and the exact-price order; 30 delivered for a price of 25.
    let o = order(ERC191_HASH, 1, 25);
    ctx(TOKEN, T0);
    let msg = json!({ "mandate_hash": ERC191_HASH, "order": o }).to_string();
    assert!(matches!(
        g.ft_on_transfer(acc("solver.near"), U128(30), msg),
        PromiseOrValue::Value(U128(0))
    ));
    let rec = g
        .get_receipt(ERC191_HASH.to_string(), hex32(&[1; 32]))
        .unwrap();
    assert_eq!(rec.decision, "release");
    let payout = near_sdk::test_utils::get_created_receipts()
        .into_iter()
        .any(|x| x.receiver_id.as_str() == TOKEN && x.actions.iter().any(|a| matches!(a, near_sdk::mock::MockAction::FunctionCallWeight { method_name, args, .. } if method_name == b"ft_transfer" && String::from_utf8_lossy(args).contains(PAYEE))));
    assert!(payout, "the payee is paid");
    let v = m(&g, ERC191_HASH);
    assert_eq!((v.spent.0, v.escrow.0, v.refund_due.0), (25, 0, 5));
    // Only the buyer's own account can be refunded, and at once (refund due).
    let rf = refund_as(&mut g, STRANGER, T0, ERC191_HASH);
    assert_eq!(rf["amount"], "5", "{rf}");
    let to_buyer = near_sdk::test_utils::get_created_receipts()
        .into_iter()
        .any(|x| x.actions.iter().any(|a| matches!(a, near_sdk::mock::MockAction::FunctionCallWeight { method_name, args, .. } if method_name == b"ft_transfer" && String::from_utf8_lossy(args).contains(ERC191_REFUND))));
    assert!(to_buyer, "the refund goes to the buyer's own 0x account");
    // An EVM buyer has no NEAR key, so nobody can call `purchase` on this mandate as the buyer.
    assert_eq!(
        purchase_as(&mut g, ERC191_REFUND, T0, &order(ERC191_HASH, 2, 25))["reason"],
        "not_authorised"
    );
}
