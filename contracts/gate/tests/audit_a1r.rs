//! Independent audit A1R (docs/audits/A1R.md): exploit tests and positive controls for the
//! redesigned gate (register_mandate, refund due, exact-price direct checkout, stop) at
//! commit 84fc11a, on near-sdk's mocked VM.
//!
//! Each `a1r_NN_*` test asserts the REQUIRED behaviour, so it FAILS while finding A1R-NN is
//! open. `pc_a1r_*` tests are positive controls and pass at 84fc11a.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};
use near_sdk::json_types::U128;
use near_sdk::mock::MockAction;
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
const RELAYER: &str = "relayer.testnet";
const STRANGER: &str = "stranger.testnet";
const ATTACKER: &str = "attacker.testnet";
const GUARDIAN: &str = "guardian.testnet";
const ONECLICK: &str = "intents.testnet";
const T0: u64 = 1_000_000_000_000;
const HOUR: u64 = 3_600_000_000_000;
const DAY: u64 = 86_400_000_000_000;
const EXPIRY: u64 = T0 + HOUR;
const BYTE_COST: u128 = 10_000_000_000_000_000_000;
const REG: u128 = 1_250_000_000_000_000_000_000;

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
        registration_deposit: U128(REG),
        max_lifetime_ns: DAY,
        guardian: None,
    }
}

fn ctx_full(pred: &str, now: u64, tgas: u64, deposit: u128, results: Vec<PromiseResult>) {
    let c = VMContextBuilder::new()
        .current_account_id(acc(GATE))
        .predecessor_account_id(acc(pred))
        .signer_account_id(acc(pred))
        .block_timestamp(now)
        .block_height(4242)
        .prepaid_gas(Gas::from_tgas(tgas))
        .account_balance(NearToken::from_near(10))
        .attached_deposit(NearToken::from_yoctonear(deposit))
        .build();
    testing_env!(
        c,
        near_sdk::test_vm_config(),
        RuntimeFeesConfig::test(),
        Default::default(),
        results
    );
}

fn ctx(pred: &str, now: u64) {
    ctx_full(pred, now, 300, 0, vec![]);
}

fn callback_ctx(now: u64, result: PromiseResult) {
    ctx_full(GATE, now, 300, 0, vec![result]);
}

fn new_gate_with(c: Config) -> Gate {
    ctx(GATE, T0);
    drop(near_sdk::mock::with_mocked_blockchain(|b| b.take_storage()));
    Gate::new(c).unwrap()
}

fn new_gate() -> Gate {
    new_gate_with(config())
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
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

/// A direct-checkout mandate: agent null, exact price 25.
fn agentless() -> Spec {
    Spec {
        agent: None,
        max_amount: 25,
        nonce: 5,
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

fn deposit(g: &Gate) -> u128 {
    g.get_config().reservation_per_mandate()
}

fn register_as(g: &mut Gate, who: &str, now: u64, text: &str, dep: u128) -> Value {
    ctx_full(who, now, 300, dep, vec![]);
    serde_json::from_str(&g.register_mandate(text.to_string())).unwrap()
}

/// A 1Click-style payment naming the mandate by hash; returns the amount handed back.
fn pay(g: &mut Gate, now: u64, mh: &str, amount: u128, order: Option<&str>) -> u128 {
    ctx(TOKEN, now);
    let m = json!({ "mandate_hash": mh, "order": order }).to_string();
    match g.ft_on_transfer(acc(ONECLICK), U128(amount), m) {
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

/// (receiver, method, args) of every function call created in this context.
fn calls() -> Vec<(String, String, Value)> {
    let mut out = vec![];
    for r in get_created_receipts() {
        for a in r.actions {
            if let MockAction::FunctionCallWeight {
                method_name, args, ..
            } = a
            {
                out.push((
                    r.receiver_id.to_string(),
                    String::from_utf8(method_name).unwrap(),
                    serde_json::from_slice(&args).unwrap_or(Value::Null),
                ));
            }
        }
    }
    out
}

/// NEAR transferred to `who` by receipts created in this context.
fn near_sent_to(who: &str) -> u128 {
    get_created_receipts()
        .into_iter()
        .filter(|r| r.receiver_id.as_str() == who)
        .flat_map(|r| r.actions)
        .filter_map(|a| match a {
            MockAction::Transfer { deposit, .. } => Some(deposit.as_yoctonear()),
            _ => None,
        })
        .sum()
}

/// Contract storage in bytes as NEAR charges it (key + value + 40 per record).
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

// ---- A1R-01: a mandate whose refund always fails never closes and holds its slot forever ----

#[test]
fn a1r_01_unrefundable_mandates_cannot_hold_the_mandate_cap_for_good() {
    let mut g = new_gate();
    let dep = deposit(&g);
    // The attacker signs max_mandates (8) one-hour mandates with their own key and sets
    // refund_to = the gate itself. NEP-141 refuses a transfer to the sender ("sender and
    // receiver should be different"; the testnet run used the same fact for payee = gate,
    // docs/a1-testnet.md step F), so every refund of these mandates fails. Each costs one
    // deposit and 1 base unit of USDC.
    let mut hashes = vec![];
    for n in 0..8u8 {
        let (s, mh) = signed(&Spec {
            agent: Some(ATTACKER.into()),
            refund_to: GATE.into(),
            key_seed: 77,
            nonce: 100 + n,
            ..spec()
        });
        assert_eq!(
            register_as(&mut g, ATTACKER, T0, &s, dep)["registered"],
            true
        );
        assert_eq!(pay(&mut g, T0, &mh, 1, None), 0);
        hashes.push(mh);
    }
    // After expiry, anyone tries to refund. The transfer to the gate fails and the unit is
    // put back as refund due, so the mandate cannot close. Retrying changes nothing.
    for _ in 0..3 {
        for mh in &hashes {
            let r = refund_as(&mut g, STRANGER, EXPIRY + 1, mh);
            assert_eq!(r["refund"], "pending", "{r}");
            callback_ctx(EXPIRY + 1, PromiseResult::Failed);
            assert!(!g.on_refund(mh.clone(), U128(1), acc(GATE), false));
        }
    }
    // A genuine buyer, a month later. The config is fixed and the mainnet account locked.
    let later = T0 + 30 * DAY;
    let (s, mh) = signed(&Spec {
        expiry: later + HOUR,
        nonce: 50,
        ..spec()
    });
    let r = register_as(&mut g, RELAYER, later, &s, dep);
    assert_eq!(
        r["registered"],
        true,
        "8 mandates with refund_to = the gate hold every slot for good ({r}); open: {}",
        g.get_totals()["mandates"]
    );
    assert!(g.get_mandate(mh).is_some());
}

// ---- A1R-02: strangers fill a direct-checkout mandate's order cap for 1 unit per receipt ----

#[test]
fn a1r_02_strangers_cannot_fill_a_direct_checkout_order_cap_for_pennies() {
    let mut g = new_gate();
    let dep = deposit(&g);
    // The relayer registers the buyer's direct-checkout mandate (exact price 25). The
    // registration call and its "registered" event are public, before the buyer pays.
    let (s, mh) = signed(&agentless());
    assert_eq!(
        register_as(&mut g, RELAYER, T0, &s, dep)["registered"],
        true
    );
    // A stranger sends max_orders_per_mandate (6) payments of 1 base unit, each with an
    // unsigned order at the exact price. 1 unit is in escrow, so the order is decided;
    // R7 fails (escrow 1 < 25) and the refusal is ANCHORED: a receipt and an order slot.
    for id in 0..6u8 {
        assert_eq!(pay(&mut g, T0, &mh, 1, Some(&order(&mh, id, 25))), 0);
    }
    let anchored = (0..6u8)
        .filter(|id| g.get_receipt(mh.clone(), hex_lower(&[*id; 32])).is_some())
        .count();
    println!("A1R-02: {anchored} refusal receipts anchored for 6 base units");
    // The buyer's real 1Click payment arrives: 25 with the buyer's exact-price order.
    assert_eq!(pay(&mut g, T0 + 1, &mh, 25, Some(&order(&mh, 0xBB, 25))), 0);
    let rec = g.get_receipt(mh.clone(), hex_lower(&[0xBB; 32]));
    assert!(
        rec.as_ref().is_some_and(|r| r.decision == "release"),
        "the buyer's checkout was not decided ({:?}); {anchored} stranger receipts at 1 unit each \
         filled the order cap, and the registrant's deposit pays their storage",
        events("refused")
    );
}

// ---- A1R-04: a failed direct-checkout payout locks the payment until expiry ---------------

#[test]
fn a1r_04_failed_direct_checkout_payout_is_payable_to_refund_to_at_once() {
    let mut g = new_gate();
    let dep = deposit(&g);
    let (s, mh) = signed(&agentless());
    assert_eq!(
        register_as(&mut g, RELAYER, T0, &s, dep)["registered"],
        true
    );
    assert_eq!(pay(&mut g, T0, &mh, 25, Some(&order(&mh, 1, 25))), 0);
    assert_eq!(
        g.get_receipt(mh.clone(), hex_lower(&[1; 32]))
            .unwrap()
            .decision,
        "release"
    );
    // The payout fails (for example the payee is frozen by the token issuer).
    callback_ctx(T0 + 1, PromiseResult::Failed);
    assert!(!g.on_payout(hex_lower(&[1; 32]), mh.clone(), U128(25), acc(PAYEE), true));
    assert_eq!(
        g.get_receipt(mh.clone(), hex_lower(&[1; 32]))
            .unwrap()
            .payout,
        Payout::Failed
    );
    // The single purchase is used up (`released` stays true), so no later payment can buy.
    // The buyer's 25 should then be owed to refund_to now, as every other unspent
    // direct-checkout payment is (A1P-02), not held in escrow until expiry.
    let r = refund_as(&mut g, STRANGER, T0 + 2, &mh);
    assert_eq!(
        (r["refund"].as_str(), r["amount"].as_str()),
        (Some("pending"), Some("25")),
        "after a failed direct-checkout payout the buyer's money waits for expiry: {r} {:?}",
        g.get_mandate(mh.clone())
    );
}

// ---- A1R-08: init accepts network "mainnet" on an account that is not a .near account ------

#[test]
fn a1r_08_init_refuses_mainnet_on_an_implicit_account() {
    let implicit = "ab".repeat(32);
    let c = VMContextBuilder::new()
        .current_account_id(acc(&implicit))
        .predecessor_account_id(acc(&implicit))
        .block_timestamp(T0)
        .build();
    testing_env!(c);
    let mut cfg = config();
    cfg.network = "mainnet".into();
    // The author response for A1C-09 says implicit accounts "end in neither suffix and are
    // refused too". Only the .testnet suffix is checked.
    assert!(
        Gate::new(cfg).is_err(),
        "an implicit (64-hex) account was initialised as a mainnet gate"
    );
}

// ---- positive controls ------------------------------------------------------------------

/// Storage that stays after close (receipts and BOTH registered-account entries) is covered
/// by what the gate keeps of the deposit, and the registrant never gets more than it paid.
#[test]
fn pc_a1r_kept_bytes_cover_everything_left_after_close_with_two_registrations() {
    let (u0, mut g) = flushed_bytes(new_gate());
    let dep = deposit(&g);
    let payee = format!("p{}.testnet", "x".repeat(54));
    let refund_to = format!("r{}.testnet", "y".repeat(54));
    let sp = Spec {
        payee: payee.clone(),
        refund_to: refund_to.clone(),
        ..spec()
    };
    let (s, mh) = signed(&sp);
    // Registrant attaches 1 NEAR more than needed; the surplus comes straight back.
    let r = register_as(
        &mut g,
        RELAYER,
        T0,
        &s,
        dep + 1_000_000_000_000_000_000_000_000,
    );
    assert_eq!(r["registered"], true);
    assert_eq!(near_sent_to(RELAYER), 1_000_000_000_000_000_000_000_000);
    assert_eq!(pay(&mut g, T0, &mh, 100, None), 0);
    for id in 0..5u8 {
        let r = purchase_as(&mut g, AGENT, T0, &order_doc(&mh, id, "zz", 1, &payee));
        assert_eq!(r["anchored"], true);
    }
    let r = purchase_as(
        &mut g,
        AGENT,
        T0,
        &order_doc(&mh, 9, "report-001", 40, &payee),
    );
    assert_eq!(r["decision"], "release");
    assert!(calls().iter().any(|c| c.1 == "storage_deposit"));
    callback_ctx(T0, PromiseResult::Successful(vec![]));
    assert!(g.on_payout(hex_lower(&[9; 32]), mh.clone(), U128(40), acc(&payee), true));
    let r = refund_as(&mut g, STRANGER, EXPIRY, &mh);
    assert_eq!(r["amount"], "60");
    assert!(calls()
        .iter()
        .any(|c| c.1 == "storage_deposit" && c.2["account_id"] == refund_to.as_str()));
    callback_ctx(EXPIRY, PromiseResult::Successful(vec![]));
    assert!(g.on_refund(mh.clone(), U128(60), acc(&refund_to), true));
    let returned = near_sent_to(RELAYER);
    assert!(g.get_mandate(mh.clone()).is_none(), "closed");
    let (u1, mut g) = flushed_bytes(g);
    let left = u128::from(u1 - u0);
    let gate_cost = left * BYTE_COST + 2 * REG;
    let kept = dep - returned;
    println!("A1R pc: {left} bytes + 2 registrations left = {gate_cost}; deposit {dep}, returned {returned}, kept {kept}");
    assert!(returned <= dep);
    assert!(gate_cost <= kept, "gate pays {}", gate_cost - kept);
    // Closing cannot pay the deposit twice: the mandate is gone.
    let r = refund_as(&mut g, STRANGER, EXPIRY + 5, &mh);
    assert_eq!(r["reason"], "unknown_mandate");
    assert_eq!(near_sent_to(RELAYER), 0);
}

/// A mandate with a payout (and registration) in flight cannot close; it closes once, in
/// the callback.
#[test]
fn pc_a1r_no_close_while_a_transfer_is_in_flight() {
    let mut g = new_gate();
    let dep = deposit(&g);
    let (s, mh) = signed(&spec());
    register_as(&mut g, RELAYER, T0, &s, dep);
    assert_eq!(pay(&mut g, T0, &mh, 40, None), 0);
    assert_eq!(
        purchase_as(&mut g, AGENT, EXPIRY - 1, &order(&mh, 1, 40))["decision"],
        "release"
    );
    let r = refund_as(&mut g, STRANGER, EXPIRY, &mh);
    assert_eq!(r["reason"], "nothing_to_refund");
    assert!(g.get_mandate(mh.clone()).is_some());
    assert_eq!(near_sent_to(RELAYER), 0);
    callback_ctx(EXPIRY, PromiseResult::Successful(vec![]));
    assert!(g.on_payout(hex_lower(&[1; 32]), mh.clone(), U128(40), acc(PAYEE), true));
    assert!(g.get_mandate(mh).is_none());
    let back = near_sent_to(RELAYER);
    assert!(back > 0 && back < dep);
}

/// A refused registration returns the whole deposit and stores nothing; front-running the
/// relayer's registration only costs the stranger its own (returned) deposit.
#[test]
fn pc_a1r_refused_or_front_run_registration_harms_nobody() {
    let mut g = new_gate();
    let dep = deposit(&g);
    let (s, mh) = signed(&agentless());
    let r = register_as(&mut g, RELAYER, T0, &s, dep - 1);
    assert_eq!(r["reason"], "deposit_too_small");
    assert_eq!(near_sent_to(RELAYER), dep - 1);
    assert!(g.get_mandate(mh.clone()).is_none());
    assert_eq!(
        register_as(&mut g, STRANGER, T0, &s, dep)["registered"],
        true
    );
    let r = register_as(&mut g, RELAYER, T0, &s, dep);
    assert_eq!(r["reason"], "already_registered");
    assert_eq!(near_sent_to(RELAYER), dep);
    // The buyer's payment still buys at the exact price.
    assert_eq!(pay(&mut g, T0, &mh, 25, Some(&order(&mh, 1, 25))), 0);
    assert_eq!(
        g.get_receipt(mh, hex_lower(&[1; 32])).unwrap().decision,
        "release"
    );
}

/// Only the guardian can stop; after the stop payments to existing mandates are kept for
/// refund_to, nothing new is registered or bought, and refunds still work.
#[test]
fn pc_a1r_stop_is_guardian_only_and_keeps_payments_for_refund_to() {
    let mut c = config();
    c.guardian = Some(acc(GUARDIAN));
    let mut g = new_gate_with(c);
    let dep = deposit(&g);
    let (s, mh) = signed(&spec());
    register_as(&mut g, RELAYER, T0, &s, dep);
    assert_eq!(pay(&mut g, T0, &mh, 30, None), 0);
    for who in [STRANGER, AGENT, GATE, TOKEN] {
        ctx(who, T0);
        let r: Value = serde_json::from_str(&g.stop()).unwrap();
        assert_eq!(r["reason"], "not_guardian");
    }
    assert_eq!(g.get_totals()["stopped"], false);
    ctx(GUARDIAN, T0);
    g.stop();
    assert_eq!(g.get_totals()["stopped"], true);
    assert_eq!(
        purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 10))["reason"],
        "stopped"
    );
    let (s2, _) = signed(&Spec { nonce: 2, ..spec() });
    let r = register_as(&mut g, RELAYER, T0, &s2, dep);
    assert_eq!(r["reason"], "stopped");
    assert_eq!(near_sent_to(RELAYER), dep);
    assert_eq!(pay(&mut g, T0, &mh, 20, None), 0);
    let m = g.get_mandate(mh.clone()).unwrap();
    assert_eq!((m.escrow.0, m.refund_due.0), (30, 20));
    let r = refund_as(&mut g, STRANGER, T0 + 1, &mh);
    assert_eq!(r["amount"], "20");
    let to: Vec<Value> = calls()
        .into_iter()
        .filter(|c| c.1 == "ft_transfer")
        .map(|c| c.2["receiver_id"].clone())
        .collect();
    assert_eq!(to, vec![json!(REFUND)]);
}

/// funded = spent + escrow + refunded + refund_due through over-delivery, a refused order,
/// a release, a failed refund and a late payment.
#[test]
fn pc_a1r_accounting_invariant_through_refund_due_paths() {
    let mut g = new_gate();
    let dep = deposit(&g);
    let (s, mh) = signed(&agentless());
    register_as(&mut g, RELAYER, T0, &s, dep);
    let check = |g: &Gate| {
        let m = g.get_mandate(mh.clone()).unwrap();
        assert_eq!(
            m.funded.0,
            m.spent.0 + m.escrow.0 + m.refunded.0 + m.refund_due.0
        );
    };
    pay(&mut g, T0, &mh, 3, Some(&order(&mh, 1, 3)));
    check(&g);
    pay(&mut g, T0, &mh, 30, Some(&order(&mh, 2, 25)));
    check(&g);
    callback_ctx(T0, PromiseResult::Successful(vec![]));
    g.on_payout(hex_lower(&[2; 32]), mh.clone(), U128(25), acc(PAYEE), true);
    check(&g);
    let r = refund_as(&mut g, STRANGER, T0 + 1, &mh);
    assert_eq!(r["amount"], "8");
    callback_ctx(T0 + 1, PromiseResult::Failed);
    g.on_refund(mh.clone(), U128(8), acc(REFUND), true);
    check(&g);
    assert_eq!(pay(&mut g, EXPIRY + 1, &mh, 4, None), 0);
    check(&g);
    let m = g.get_mandate(mh.clone()).unwrap();
    assert_eq!((m.spent.0, m.escrow.0, m.refund_due.0), (25, 0, 12));
    assert_eq!(g.get_totals()["total_refund_due"], "12");
    assert_eq!(g.get_totals()["total_escrow"], "0");
}

// ---- re-verification at 5afc545 ---------------------------------------------------------

/// A1R-01 fix: `live_expiries` never holds more than `max_mandates` entries, expired
/// entries are dropped, and a full cycle of registrations and closes leaves no storage.
/// A mandate that can never close (refund_to = the gate) frees its slot at expiry.
#[test]
fn a1r_11_live_expiries_stay_bounded_and_leave_no_storage() {
    let (u0, mut g) = flushed_bytes(new_gate());
    let dep = deposit(&g);
    let mut now = T0;
    for round in 0..4u8 {
        let mut hashes = vec![];
        for n in 0..8u8 {
            let (s, mh) = signed(&Spec {
                expiry: now + HOUR,
                nonce: round * 16 + n,
                ..spec()
            });
            assert_eq!(
                register_as(&mut g, RELAYER, now, &s, dep)["registered"],
                true
            );
            hashes.push(mh);
        }
        // The ninth live mandate is refused: the cap still holds.
        let (s, _) = signed(&Spec {
            expiry: now + HOUR,
            nonce: round * 16 + 9,
            ..spec()
        });
        assert_eq!(
            register_as(&mut g, RELAYER, now, &s, dep)["reason"],
            "mandate_cap"
        );
        assert_eq!(g.get_totals()["live_mandates"], 8);
        now += HOUR;
        for mh in &hashes {
            assert_eq!(refund_as(&mut g, STRANGER, now, mh)["refund"], "closed");
        }
        assert_eq!(g.get_totals()["live_mandates"], 0);
        now += 1;
    }
    let (u1, mut g) = flushed_bytes(g);
    assert_eq!(u1, u0, "registrations and closes left {} bytes", u1 - u0);
    // A stuck mandate (refund always fails) keeps its record, paid by its own deposit,
    // but not a slot: after its expiry 8 new mandates fit.
    let (s, mh) = signed(&Spec {
        agent: Some(ATTACKER.into()),
        refund_to: GATE.into(),
        key_seed: 77,
        nonce: 200,
        expiry: now + HOUR,
        ..spec()
    });
    register_as(&mut g, ATTACKER, now, &s, dep);
    assert_eq!(pay(&mut g, now, &mh, 1, None), 0);
    now += HOUR;
    refund_as(&mut g, STRANGER, now, &mh);
    callback_ctx(now, PromiseResult::Failed);
    g.on_refund(mh.clone(), U128(1), acc(GATE), false);
    assert!(g.get_mandate(mh).is_some());
    for n in 0..8u8 {
        let (s, _) = signed(&Spec {
            expiry: now + HOUR,
            nonce: 210 + n,
            ..spec()
        });
        assert_eq!(
            register_as(&mut g, RELAYER, now, &s, dep)["registered"],
            true
        );
    }
    assert_eq!(g.get_totals()["live_mandates"], 8);
}
