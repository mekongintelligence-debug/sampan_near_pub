//! Independent audit A1-contract (docs/audits/A1-contract.md): exploit tests and positive
//! controls for the gate contract at commit 51dac1d, on near-sdk's mocked VM.
//!
//! Each `a1c_NN_*` test asserts the REQUIRED behaviour, so it FAILS while finding A1C-NN
//! is open. `pc_a1_*` tests are positive controls and pass today.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};
use near_sdk::json_types::U128;
use near_sdk::test_utils::{get_created_receipts, get_logs, VMContextBuilder};
use near_sdk::{
    env, testing_env, AccountId, Gas, NearToken, PromiseOrValue, PromiseResult, RuntimeFeesConfig,
};
use sampan_formats::{canonicalize, hash_hex, hex_lower, nep413_hash};
use sampan_gate::{Config, Gate, Payout};
use serde_json::{json, Value};

const GATE: &str = "gate.testnet";
const TOKEN: &str = "usdc.testnet";
const AGENT: &str = "agent.testnet";
const PAYEE: &str = "shop.testnet";
const REFUND: &str = "buyer.testnet";
const STRANGER: &str = "stranger.testnet";
const ATTACKER: &str = "attacker.testnet";
const T0: u64 = 1_000_000_000_000;
const EXPIRY: u64 = 2_000_000_000_000;
const DAY: u64 = 86_400_000_000_000;
/// An expiry about 500 years after T0: the grammar allows any u64.
const FAR: u64 = u64::MAX - 1;

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

fn ctx_on(account: &str, pred: &str, now: u64, tgas: u64, results: Vec<PromiseResult>) {
    let c = VMContextBuilder::new()
        .current_account_id(acc(account))
        .predecessor_account_id(acc(pred))
        .signer_account_id(acc(pred))
        .block_timestamp(now)
        .block_height(4242)
        .prepaid_gas(Gas::from_tgas(tgas))
        .account_balance(NearToken::from_near(10))
        .build();
    testing_env!(
        c,
        near_sdk::test_vm_config(),
        RuntimeFeesConfig::test(),
        Default::default(),
        results
    );
}

fn set_ctx(pred: &str, now: u64, tgas: u64, results: Vec<PromiseResult>) {
    ctx_on(GATE, pred, now, tgas, results);
}

fn ctx(pred: &str, now: u64) {
    set_ctx(pred, now, 300, vec![]);
}

fn fresh_storage() {
    ctx(GATE, T0);
    drop(near_sdk::mock::with_mocked_blockchain(|b| b.take_storage()));
}

fn new_gate_with(c: Config) -> Gate {
    fresh_storage();
    Gate::new(c).unwrap()
}

fn new_gate() -> Gate {
    new_gate_with(config())
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn implicit(seed: u8) -> String {
    hex_lower(&key(seed).verifying_key().to_bytes())
}

#[derive(Clone)]
struct Spec {
    agent: Option<String>,
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
        agent: Some(AGENT.into()),
        max_amount: 100,
        payee: PAYEE.into(),
        items: vec!["report-001".into(), "report-002".into()],
        expiry: EXPIRY,
        nonce: 1,
        refund_to: REFUND.into(),
        key_seed: 9,
    }
}

fn agentless() -> Spec {
    Spec {
        agent: None,
        max_amount: 25,
        nonce: 5,
        ..spec()
    }
}

/// An attacker's own mandate: their key, their refund account, their agent account.
fn attacker_spec(nonce: u8) -> Spec {
    Spec {
        agent: Some(ATTACKER.into()),
        key_seed: 77,
        nonce,
        refund_to: ATTACKER.into(),
        ..spec()
    }
}

fn signed(s: &Spec) -> (String, String) {
    let k = key(s.key_seed);
    let buyer = format!(
        "near:ed25519:{}",
        bs58::encode(k.verifying_key().to_bytes()).into_string()
    );
    let nonce = [s.nonce; 32];
    let mandate = json!({
        "v": "sampan.mandate.v1", "network": "testnet", "gate": GATE, "buyer": buyer,
        "agent": s.agent, "asset": TOKEN, "max_amount": s.max_amount.to_string(),
        "payee": s.payee, "items": s.items, "expiry_ns": s.expiry.to_string(),
        "nonce": hex_lower(&nonce), "refund_to": s.refund_to,
    });
    let message = canonicalize(&mandate).unwrap();
    let digest = nep413_hash(&message, &nonce, GATE).unwrap();
    let sig = hex_lower(&k.sign(&digest).to_bytes());
    let doc = json!({ "v": "sampan.signed-mandate.v1", "mandate": mandate, "standard": "nep413", "signature": sig });
    (canonicalize(&doc).unwrap(), hash_hex(message.as_bytes()))
}

fn order_doc(mh: &str, id: u8, item: &str, amount: u128, payee: &str) -> String {
    canonicalize(&json!({
        "v": "sampan.order.v1", "order_id": hex_lower(&[id; 32]), "mandate_hash": mh,
        "item": item, "amount": amount.to_string(), "asset": TOKEN, "payee": payee,
    }))
    .unwrap()
}

fn order(mh: &str, id: u8, amount: u128) -> String {
    order_doc(mh, id, "report-001", amount, PAYEE)
}

fn msg(signed: &str, order: Option<&str>) -> String {
    json!({ "signed_mandate": signed, "order": order }).to_string()
}

/// ft_on_transfer from the token at `now`; returns the amount handed back.
fn fund_at(g: &mut Gate, now: u64, signed: &str, amount: u128, order: Option<&str>) -> u128 {
    register_from_msg(g, GATE, &msg(signed, order), now);
    set_ctx(TOKEN, now, 300, vec![]);
    match g.ft_on_transfer(acc("solver.testnet"), U128(amount), msg(signed, order)) {
        PromiseOrValue::Value(v) => v.0,
        PromiseOrValue::Promise(_) => panic!("ft_on_transfer must return a value"),
    }
}

fn purchase_as(g: &mut Gate, pred: &str, now: u64, order: &str) -> Value {
    ctx(pred, now);
    serde_json::from_str(&g.purchase(order.to_string())).unwrap()
}

fn refund_as(g: &mut Gate, pred: &str, now: u64, mh: &str) -> Value {
    ctx(pred, now);
    serde_json::from_str(&g.refund(mh.to_string())).unwrap()
}

fn events(name: &str) -> Vec<Value> {
    get_logs()
        .iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .map(|j| serde_json::from_str::<Value>(j).unwrap())
        .filter(|e| e["event"] == name)
        .collect()
}

/// (receiver, method, args, attached yocto) of every function call created in this context.
fn calls() -> Vec<(String, String, Value, u128)> {
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
                    serde_json::from_slice(&args).unwrap_or(Value::Null),
                    attached_deposit.as_yoctonear(),
                ));
            }
        }
    }
    out
}

/// Contract storage in bytes as NEAR charges it (key + value + 40 per record), after
/// writing the gate back; the gate is reloaded from storage.
fn flushed_bytes(g: Gate) -> (u64, Gate) {
    env::state_write(&g);
    drop(g);
    let s = near_sdk::mock::with_mocked_blockchain(|b| b.take_storage());
    let bytes = s.iter().map(|(k, v)| (k.len() + v.len() + 40) as u64).sum();
    env::set_blockchain_interface(near_sdk::MockedBlockchain::new(
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
    (bytes, env::state_read().unwrap())
}

// ---- A1C-01: unbounded expiry lets anyone block the gate for good --------------------------

#[test]
fn a1c_01_far_expiry_mandates_cannot_fill_the_open_mandate_cap() {
    let mut g = new_gate();
    // The attacker signs max_mandates (8) mandates with their own key, refund_to theirs,
    // expiring in about 500 years, and funds each with min_funding (10 units). Closing
    // needs expiry, so these slots never free up; the config is fixed and, on mainnet,
    // the account is locked.
    for n in 0..8u8 {
        let (s, _) = signed(&Spec {
            expiry: FAR,
            ..attacker_spec(100 + n)
        });
        fund_at(&mut g, T0, &s, 10, None);
    }
    // A genuine buyer, 30 days later, with an ordinary one-hour mandate.
    let now = T0 + 30 * DAY;
    let (s, mh) = signed(&Spec {
        expiry: now + DAY / 24,
        nonce: 50,
        ..spec()
    });
    let back = fund_at(&mut g, now, &s, 50, None);
    assert_eq!(
        back,
        0,
        "the gate refuses every new mandate for centuries (cost: 8 x min_funding): {:?}",
        events("funding_refused")
    );
    assert!(g.get_mandate(mh).is_some());
}

#[test]
fn a1c_01b_far_expiry_mandates_cannot_fill_the_total_escrow_cap() {
    let mut g = new_gate();
    // Same idea with capital instead of slots: three far-expiry mandates hold the whole
    // max_total_escrow (3 x 1,000,000).
    for n in 0..3u8 {
        let (s, _) = signed(&Spec {
            expiry: FAR,
            max_amount: 1_000_000,
            ..attacker_spec(110 + n)
        });
        fund_at(&mut g, T0, &s, 1_000_000, None);
    }
    let now = T0 + 30 * DAY;
    let (s, mh) = signed(&Spec {
        expiry: now + DAY / 24,
        nonce: 51,
        ..spec()
    });
    let back = fund_at(&mut g, now, &s, 50, None);
    assert_eq!(
        back,
        0,
        "total escrow cap held for centuries: {:?}",
        events("funding_refused")
    );
    assert!(g.get_mandate(mh).is_some());
}

// ---- A1C-02: closed attacker mandates leave gate-paid storage behind forever --------------

#[test]
fn a1c_02_closed_attacker_mandate_costs_the_gate_no_near() {
    let mut c = config();
    c.max_mandates = 2;
    let (u0, mut g) = flushed_bytes(new_gate_with(c));
    // One attacker cycle. The attacker is their own buyer, agent and refund_to, and names
    // a fresh payee they control, so the gate pays its token registration.
    let payee = format!("p{}.testnet", "x".repeat(54)); // a long, fresh account ID
    let sp = Spec {
        payee: payee.clone(),
        ..attacker_spec(120)
    };
    let (s, mh) = signed(&sp);
    assert_eq!(fund_at(&mut g, T0, &s, 10, None), 0);
    // Five anchored refusals (item not in the mandate): each stores a receipt for good.
    for id in 0..5u8 {
        let r = purchase_as(
            &mut g,
            ATTACKER,
            T0,
            &order_doc(&mh, id, "zz-not-listed", 1, &payee),
        );
        assert_eq!(r["anchored"], true);
    }
    // One 1-unit release to the attacker's payee: the gate attaches a registration.
    let r = purchase_as(
        &mut g,
        ATTACKER,
        T0,
        &order_doc(&mh, 9, "report-001", 1, &payee),
    );
    assert_eq!(r["decision"], "release");
    let deposits: u128 = calls()
        .iter()
        .filter(|c| c.1 == "storage_deposit")
        .map(|c| c.3)
        .sum();
    set_ctx(GATE, T0, 300, vec![PromiseResult::Successful(vec![])]);
    assert!(g.on_payout(hex_lower(&[9; 32]), mh.clone(), U128(1), acc(&payee), true));
    // After expiry the attacker takes the other 9 units back and the mandate closes.
    assert_eq!(
        refund_as(&mut g, STRANGER, EXPIRY, &mh)["refund"],
        "pending"
    );
    set_ctx(GATE, EXPIRY, 300, vec![PromiseResult::Successful(vec![])]);
    assert!(g.on_refund(mh.clone(), U128(9), acc(ATTACKER), false));
    // Author adaptation after the A1 redesign (docs/audits/A1-contract.md, author response): the registrant attached a deposit and gets back only what the mandate
    // does not still use; record what came back when the mandate closed.
    let deposit = g.get_config().reservation_per_mandate();
    let returned: u128 = near_sdk::test_utils::get_created_receipts()
        .into_iter()
        .filter(|r| r.receiver_id.as_str() == "relayer.testnet")
        .flat_map(|r| r.actions)
        .filter_map(|a| match a {
            near_sdk::mock::MockAction::Transfer { deposit, .. } => Some(deposit.as_yoctonear()),
            _ => None,
        })
        .sum();
    assert!(g.get_mandate(mh).is_none(), "closed");
    let (u1, _) = flushed_bytes(g);
    let left = u1.saturating_sub(u0);
    let near_cost = u128::from(left) * 10_000_000_000_000_000_000 + deposits;
    println!("A1C-02: one cycle leaves {left} bytes of gate-paid storage and {deposits} yocto of registration: {near_cost} yoctoNEAR the attacker never paid");
    // Q17 (decided 5 Nov): whoever creates gate state pays for its storage. The attacker
    // attached no NEAR at all, so the gate must not be left paying for anything.
    // Author adaptation after the A1 redesign (docs/audits/A1-contract.md, author response): the cost must be covered by the part of the registrant's deposit
    // the gate kept (the registrant, here the attacker's relayer, paid it).
    let kept = deposit - returned;
    println!("A1C-02 after the fix: the registrant attached {deposit}, got back {returned}, the gate kept {kept}");
    assert!(
        near_cost <= kept,
        "the gate pays {} yoctoNEAR per attacker cycle, for good",
        near_cost - kept
    );
}

// ---- A1C-04: a stranger can create an agentless mandate with an order of their choosing ----

#[test]
fn a1c_04_stranger_cannot_create_agentless_mandate_with_a_partial_order() {
    let mut g = new_gate();
    // The buyer signs an exact-price mandate (25) for direct checkout and gives it to the
    // widget / 1Click quote. Before 1Click delivers, a stranger who has seen it funds it
    // first with 10 of their own units and an order for 10.
    let (s, mh) = signed(&agentless());
    let stranger_order = order(&mh, 0xAA, 10);
    fund_at(&mut g, T0, &s, 10, Some(&stranger_order));
    let rec = g.get_receipt(mh.clone(), hex_lower(&[0xAA; 32]));
    // Observation: the buyer's own delivery (25 with the buyer's order) now bounces back to
    // the 1Click sender, not to refund_to.
    let back = fund_at(&mut g, T0, &s, 25, Some(&order(&mh, 0xBB, 25)));
    println!("A1C-04: buyer's delivery handed back to the sender: {back} of 25");
    assert!(
        rec.as_ref().map(|r| r.decision != "release").unwrap_or(true),
        "a stranger's unsigned partial order (10 of an exact price of 25) was released and anchored with R5 passed"
    );
}

// ---- A1C-05: refund to an unregistered refund_to after the payee used the registration ----

#[test]
fn a1c_05_refund_registers_refund_to_when_the_payee_used_the_registration() {
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    assert_eq!(fund_at(&mut g, T0, &s, 100, None), 0);
    // A release to a new payee: the gate pays the payee's registration (the mandate's one).
    assert_eq!(
        purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 40))["decision"],
        "release"
    );
    assert!(calls().iter().any(|c| c.1 == "storage_deposit"));
    set_ctx(GATE, T0, 300, vec![PromiseResult::Successful(vec![])]);
    assert!(g.on_payout(hex_lower(&[1; 32]), mh.clone(), U128(40), acc(PAYEE), true));
    // After expiry: refund_to (for example an EVM buyer's implicit 0x... account) has never
    // been registered with the token by anyone.
    assert_eq!(
        refund_as(&mut g, STRANGER, EXPIRY, &mh)["refund"],
        "pending"
    );
    let registers_refund_to = calls()
        .iter()
        .any(|c| c.1 == "storage_deposit" && c.2["account_id"] == REFUND);
    assert!(
        registers_refund_to,
        "refund to an unregistered refund_to has no registration: ft_transfer fails, the escrow is restored, and every retry fails the same way until someone registers refund_to"
    );
}

// ---- A1C-09: network in the config is not tied to the account the gate runs on ------------

#[test]
fn a1c_09_init_refuses_a_network_that_does_not_match_the_account() {
    fresh_storage();
    let mut c = config();
    c.network = "mainnet".into();
    // gate.testnet initialised as a "mainnet" gate.
    assert!(
        Gate::new(c).is_err(),
        "a .testnet account accepted network = mainnet"
    );
}

// ---- positive controls ------------------------------------------------------------------

#[test]
fn pc_a1_short_expiry_squat_frees_the_slots_after_expiry() {
    let mut g = new_gate();
    let mut hashes = vec![];
    for n in 0..8u8 {
        let (s, mh) = signed(&attacker_spec(130 + n));
        assert_eq!(fund_at(&mut g, T0, &s, 10, None), 0);
        hashes.push(mh);
    }
    for mh in &hashes {
        refund_as(&mut g, STRANGER, EXPIRY, mh);
        set_ctx(GATE, EXPIRY, 300, vec![PromiseResult::Successful(vec![])]);
        assert!(g.on_refund(mh.clone(), U128(10), acc(ATTACKER), true));
    }
    let (s, _) = signed(&Spec {
        expiry: EXPIRY + DAY,
        nonce: 60,
        ..spec()
    });
    assert_eq!(fund_at(&mut g, EXPIRY + 1, &s, 50, None), 0);
}

#[test]
fn pc_a1_payee_or_stranger_cannot_drive_the_callbacks() {
    let (s, mh) = signed(&spec());
    let mut g = new_gate();
    fund_at(&mut g, T0, &s, 100, None);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 40));
    // A malicious payee contract (or anyone) calls the callbacks claiming a failed transfer,
    // trying to get the budget restored after it was paid.
    for who in [PAYEE, STRANGER, TOKEN] {
        set_ctx(who, T0, 300, vec![PromiseResult::Failed]);
        assert!(!g.on_payout(hex_lower(&[1; 32]), mh.clone(), U128(40), acc(PAYEE), true));
        assert!(!g.on_refund(mh.clone(), U128(40), acc(PAYEE), true));
    }
    let v = g.get_mandate(mh.clone()).unwrap();
    assert_eq!((v.spent.0, v.escrow.0), (40, 60));
    assert_eq!(
        g.get_receipt(mh, hex_lower(&[1; 32])).unwrap().payout,
        Payout::Pending
    );
}

#[test]
fn pc_a1_every_transfer_goes_to_the_token_for_payee_or_refund_to_only() {
    let (s, mh) = signed(&spec());
    let mut g = new_gate();
    fund_at(&mut g, T0, &s, 100, None);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 40));
    let mut all = calls();
    set_ctx(GATE, T0, 300, vec![PromiseResult::Failed]);
    assert!(!g.on_payout(hex_lower(&[1; 32]), mh.clone(), U128(40), acc(PAYEE), true));
    refund_as(&mut g, STRANGER, EXPIRY, &mh);
    all.extend(calls());
    for (receiver, method, args, _) in &all {
        if receiver == GATE {
            assert!(method == "on_payout" || method == "on_refund");
            continue;
        }
        assert_eq!(receiver, TOKEN);
        assert!(
            args["account_id"] == PAYEE
                || args["account_id"] == REFUND
                || args["receiver_id"] == PAYEE
                || args["receiver_id"] == REFUND,
            "{method} {args}"
        );
    }
    // The failed payout was restored and the whole escrow went to refund_to.
    assert!(all
        .iter()
        .any(|c| c.1 == "ft_transfer" && c.2["receiver_id"] == REFUND && c.2["amount"] == "100"));
}

#[test]
fn pc_a1_buyer_direct_checkout_at_exact_price_releases() {
    let mut g = new_gate();
    let (s, mh) = signed(&agentless());
    assert_eq!(fund_at(&mut g, T0, &s, 25, Some(&order(&mh, 0xBB, 25))), 0);
    assert_eq!(
        g.get_receipt(mh.clone(), hex_lower(&[0xBB; 32]))
            .unwrap()
            .decision,
        "release"
    );
    // The buyer's NEP-413 implicit account may also buy on an agentless mandate; others not.
    let (s2, mh2) = signed(&Spec {
        nonce: 6,
        ..agentless()
    });
    fund_at(&mut g, T0, &s2, 25, None);
    assert_eq!(
        purchase_as(&mut g, STRANGER, T0, &order(&mh2, 1, 5))["reason"],
        "not_authorised"
    );
    assert_eq!(
        purchase_as(&mut g, &implicit(9), T0, &order(&mh2, 1, 5))["decision"],
        "release"
    );
}

/// The gate's EVM-buyer path (nonce key `evm:`, no buyer account) has no gate test at
/// 51dac1d (lib.rs:282, 684 uncovered). Uses the committed ERC-191 vector as data.
#[test]
fn pc_a1_evm_buyer_mandate_funds_pays_and_refunds() {
    const VG: &str = "gate.vectors-only.testnet";
    const VT: &str = "token.vectors-only.testnet";
    const VA: &str = "agent.vectors-only.testnet";
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/vectors/signed_mandate/erc191-valid-v27.json"
    ))
    .unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    let text = String::from_utf8(
        near_sdk::base64::Engine::decode(
            &near_sdk::base64::engine::general_purpose::STANDARD,
            v["input_b64"].as_str().unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let mh = v["expect"]["hash"].as_str().unwrap().to_string();
    let doc: Value = serde_json::from_str(&text).unwrap();
    let expiry: u64 = doc["mandate"]["expiry_ns"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let now = expiry - DAY;
    ctx_on(VG, VG, now, 300, vec![]);
    drop(near_sdk::mock::with_mocked_blockchain(|b| b.take_storage()));
    let mut c = config();
    c.token = acc(VT);
    c.max_escrow_per_mandate = U128(5_000_000);
    c.max_total_escrow = U128(10_000_000);
    let mut g = Gate::new(c).unwrap();
    register_from_msg(&mut g, VG, &msg(&text, None), now);
    ctx_on(VG, VT, now, 300, vec![]);
    let back = match g.ft_on_transfer(acc("solver.testnet"), U128(5_000_000), msg(&text, None)) {
        PromiseOrValue::Value(b) => b.0,
        PromiseOrValue::Promise(_) => panic!(),
    };
    assert_eq!(back, 0, "{:?}", events("funding_refused"));
    let payee = doc["mandate"]["payee"].as_str().unwrap();
    let o = canonicalize(&json!({
        "v": "sampan.order.v1", "order_id": hex_lower(&[3; 32]), "mandate_hash": mh,
        "item": "report-002", "amount": "2000000", "asset": VT, "payee": payee,
    }))
    .unwrap();
    ctx_on(VG, VA, now, 300, vec![]);
    let r: Value = serde_json::from_str(&g.purchase(o)).unwrap();
    assert_eq!(r["decision"], "release");
    ctx_on(VG, "stranger.testnet", expiry, 300, vec![]);
    let r: Value = serde_json::from_str(&g.refund(mh.clone())).unwrap();
    assert_eq!(r["amount"], "3000000");
    let to: Vec<String> = calls()
        .into_iter()
        .filter(|c| c.1 == "ft_transfer")
        .map(|c| c.2["receiver_id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        to,
        vec![doc["mandate"]["refund_to"].as_str().unwrap().to_string()]
    );
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
