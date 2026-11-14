//! Independent audit M3 (docs/audits/M3.md): exploit tests and positive controls for the
//! gate contract, written against its public API on near-sdk's mocked VM.
//!
//! Each `m3_NN_*` test asserts the REQUIRED behaviour, so it FAILS while finding M3-NN is
//! open. `pc_*` tests are positive controls and pass today.
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
const T0: u64 = 1_000_000_000_000;
const EXPIRY: u64 = 2_000_000_000_000;
const LATER: u64 = 9_000_000_000_000;

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

fn set_ctx_full(pred: &str, now: u64, tgas: u64, balance: NearToken, results: Vec<PromiseResult>) {
    let ctx = VMContextBuilder::new()
        .current_account_id(acc(GATE))
        .predecessor_account_id(acc(pred))
        .signer_account_id(acc(pred))
        .block_timestamp(now)
        .block_height(4242)
        .prepaid_gas(Gas::from_tgas(tgas))
        .account_balance(balance)
        .build();
    testing_env!(
        ctx,
        near_sdk::test_vm_config(),
        RuntimeFeesConfig::test(),
        Default::default(),
        results
    );
}

fn set_ctx(pred: &str, now: u64, tgas: u64, results: Vec<PromiseResult>) {
    set_ctx_full(pred, now, tgas, NearToken::from_near(10), results);
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

/// Canonical signed mandate (NEP-413), its mandate hash and the mandate object.
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

/// ft_on_transfer as `pred` at `now` with `tgas`; returns the amount handed back.
fn fund_full(
    g: &mut Gate,
    pred: &str,
    now: u64,
    tgas: u64,
    signed: &str,
    amount: u128,
    order: Option<&str>,
) -> u128 {
    if pred == TOKEN {
        register_from_msg(g, GATE, &msg(signed, order), now);
    }
    set_ctx(pred, now, tgas, vec![]);
    match g.ft_on_transfer(acc("solver.testnet"), U128(amount), msg(signed, order)) {
        PromiseOrValue::Value(v) => v.0,
        PromiseOrValue::Promise(_) => panic!("ft_on_transfer must return a value"),
    }
}

fn fund(g: &mut Gate, signed: &str, amount: u128) -> u128 {
    fund_full(g, TOKEN, T0, 300, signed, amount, None)
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

/// (receiver, method, args) of every function call created in the current context.
fn calls() -> Vec<(String, String, Value)> {
    let mut out = vec![];
    for r in get_created_receipts() {
        for a in r.actions {
            if let near_sdk::mock::MockAction::FunctionCallWeight {
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

fn mandate_count(g: &Gate) -> u64 {
    g.get_totals()["mandates"].as_u64().unwrap()
}

// ---- M3-01: any token holder can decide orders on an agentless mandate ----------------

#[test]
fn m3_01_stranger_cannot_spend_agentless_escrow_via_funding_message() {
    let mut g = new_gate();
    let (s, mh) = signed(&agentless()); // max 25, agent null
                                        // The buyer funds part of the budget (no order yet). The signed mandate is now public
                                        // (it is in the funding transaction's arguments).
    assert_eq!(fund(&mut g, &s, 20), 0);
    // A stranger sends 1 token unit with the public signed mandate and an order of their
    // own choosing: amount, item and order ID are not signed by anyone.
    let o = order_doc(&mh, 0xEE, "report-002", 20, PAYEE);
    fund_full(&mut g, TOKEN, T0, 300, &s, 1, Some(&o));
    let pays = calls().iter().any(|c| c.1 == "ft_transfer");
    let rec = g.get_receipt(mh.clone(), hex_lower(&[0xEE; 32]));
    assert!(
        !pays && rec.is_none(),
        "a stranger's unsigned order released the buyer's escrow (receipt shows R5 pass): {:?}",
        rec.map(|r| r.decision)
    );
    assert_eq!(g.get_mandate(mh).unwrap().spent.0, 0);
}

#[test]
fn m3_01b_stranger_cannot_exhaust_order_cap_of_agentless_mandate() {
    let mut g = new_gate();
    let (s, mh) = signed(&agentless());
    assert_eq!(fund(&mut g, &s, 10), 0);
    // Six 1-unit top-ups, each with an order for an item outside the mandate (anchored R9
    // refusals) fill max_orders_per_mandate (6).
    for id in 0..6u8 {
        fund_full(
            &mut g,
            TOKEN,
            T0,
            300,
            &s,
            1,
            Some(&order_doc(&mh, id, "report-404", 1, PAYEE)),
        );
    }
    // The buyer (NEP-413 implicit account) can no longer buy anything.
    let r = purchase_as(&mut g, &implicit(9), T0, &order(&mh, 100, 5));
    assert_eq!(
        r["decision"], "release",
        "buyer locked out by a stranger: {r}"
    );
}

// ---- M3-02: the lifetime mandate cap is consumable by anyone at no net cost -----------

#[test]
fn m3_02_strangers_cannot_permanently_exhaust_max_mandates() {
    let mut g = new_gate();
    // An attacker signs 8 mandates with their own key, funds each with min_funding, and
    // takes every token back after expiry (refund_to is theirs).
    for n in 0..8u8 {
        let sp = Spec {
            key_seed: 77,
            nonce: 100 + n,
            refund_to: "attacker.testnet".into(),
            ..spec()
        };
        let (s, mh) = signed(&sp);
        assert_eq!(fund(&mut g, &s, 10), 0);
        assert_eq!(
            refund_as(&mut g, STRANGER, EXPIRY, &mh)["refund"],
            "pending"
        );
        set_ctx(GATE, EXPIRY, 300, vec![PromiseResult::Successful(vec![])]);
        assert!(g.on_refund(mh, U128(10), acc("attacker.testnet"), false));
    }
    assert_eq!(
        g.get_totals()["total_escrow"],
        "0",
        "the attacker holds nothing in the gate"
    );
    // A genuine buyer's new mandate, later.
    let (s, mh) = signed(&Spec {
        expiry: LATER,
        nonce: 50,
        ..spec()
    });
    let back = fund_full(&mut g, TOKEN, EXPIRY + 1, 300, &s, 50, None);
    assert_eq!(
        back,
        0,
        "gate permanently refuses new mandates: {:?}",
        events("funding_refused")
    );
    assert!(g.get_mandate(mh).is_some());
}

// ---- M3-03: lifetime registration cap consumable by strangers ---------------------------

#[test]
fn m3_03_strangers_cannot_exhaust_registrations_for_legitimate_payees() {
    let mut c = config();
    c.max_mandates = 20;
    let mut g = new_gate_with(c);
    // The attacker's mandates name four fresh refund_to accounts; each refund makes the
    // gate pay (and count) one registration.
    for n in 0..4u8 {
        let who = format!("sink{n}.testnet");
        let sp = Spec {
            key_seed: 77,
            nonce: 100 + n,
            refund_to: who.clone(),
            ..spec()
        };
        let (s, mh) = signed(&sp);
        assert_eq!(fund(&mut g, &s, 10), 0);
        refund_as(&mut g, STRANGER, EXPIRY, &mh);
        let registering = calls().iter().any(|c| c.1 == "storage_deposit");
        set_ctx(GATE, EXPIRY, 300, vec![PromiseResult::Successful(vec![])]);
        g.on_refund(mh, U128(10), acc(&who), registering);
    }
    // A genuine mandate paying a payee that is not yet registered with the token.
    let sp = Spec {
        expiry: LATER,
        nonce: 60,
        payee: "newshop.testnet".into(),
        ..spec()
    };
    let (s, mh) = signed(&sp);
    assert_eq!(fund_full(&mut g, TOKEN, EXPIRY + 1, 300, &s, 50, None), 0);
    let r = purchase_as(
        &mut g,
        AGENT,
        EXPIRY + 1,
        &order_doc(&mh, 1, "report-001", 10, "newshop.testnet"),
    );
    assert_eq!(r["decision"], "release");
    assert!(
        calls().iter().any(|c| c.1 == "storage_deposit"),
        "registration slots used up by a stranger: this payout to an unregistered payee will fail"
    );
}

// ---- M3-04: `new` can be called by anyone (init front-running) --------------------------

#[test]
fn m3_04_init_only_by_the_gate_account() {
    fresh_storage();
    ctx(STRANGER, T0);
    let mut c = config();
    c.token = acc("fake-usdc.testnet");
    assert!(
        Gate::new(c).is_err(),
        "a stranger can initialise the gate with its own token and caps between deploy and init"
    );
}

// ---- M3-05: gate-paid storage is not bounded by the gate's balance ----------------------

/// Contract storage in bytes as NEAR charges it (key + value + 40 per record). Flushes
/// the gate by writing and dropping it, then reloads it from storage.
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

/// Bytes one worst-case mandate (and its nonce) and one anchored receipt add.
fn worst_case_bytes(orders: u8) -> (u64, u64) {
    let long = |p: &str| format!("{p}{}.testnet", "a".repeat(55 - p.len()));
    let items: Vec<String> = (0..16)
        .map(|i| format!("{i:02}{}", "x".repeat(62)))
        .collect();
    let mut c = config();
    c.max_orders_per_mandate = 255;
    // Author adaptation after the M3-05 fix: one open mandate, so the measuring gate's
    // caps fit its balance; the records measured are unchanged.
    c.max_mandates = 1;
    let (u0, mut g) = flushed_bytes(new_gate_with(c));
    let sp = Spec {
        agent: Some(long("g")),
        payee: long("p"),
        refund_to: long("r"),
        items,
        ..spec()
    };
    let (s, mh) = signed(&sp);
    assert_eq!(fund(&mut g, &s, 100), 0);
    let (u1, mut g) = flushed_bytes(g);
    for id in 0..orders {
        let r = purchase_as(
            &mut g,
            &long("g"),
            T0,
            &order_doc(&mh, id, "zz-not-listed", 1, &long("p")),
        );
        assert_eq!(r["anchored"], true);
    }
    let (u2, _) = flushed_bytes(g);
    (u1 - u0, (u2 - u1) / u64::from(orders.max(1)))
}

#[test]
fn m3_05_observation_storage_per_record() {
    let (mandate, receipt) = worst_case_bytes(4);
    // Printed for docs/audits/M3.md (run with --nocapture).
    println!("worst-case mandate record: {mandate} bytes; receipt record: {receipt} bytes");
    assert!(mandate > 1_000 && receipt > 100);
}

#[test]
fn m3_05_init_rejects_caps_the_balance_cannot_cover() {
    // The live testnet config (scripts/m3/testnet-run.mjs, get_config) on a gate with the
    // live free balance (about 0.41 NEAR above its storage; 0.6 NEAR here). Worst case:
    // 50 mandates x (1,759 + 10 x 336) bytes = 2.56 NEAR of storage the gate must pay.
    fresh_storage();
    set_ctx_full(GATE, T0, 300, NearToken::from_millinear(600), vec![]);
    let c = Config {
        network: "testnet".into(),
        token: acc(TOKEN),
        min_funding: U128(100_000),
        max_escrow_per_mandate: U128(20_000_000),
        max_total_escrow: U128(100_000_000),
        max_mandates: 50,
        max_orders_per_mandate: 10,
        registration_deposit: U128(1_250_000_000_000_000_000_000),
        max_lifetime_ns: 86_400_000_000_000,
        guardian: None,
    };
    // Author adaptation after the A1 redesign (A1C-02): mandate storage is no longer paid
    // from the gate's balance but by each registration's deposit, so the same caps are fine
    // at init, and a registration that does not bring its deposit stores nothing.
    let mut g = Gate::new(c).unwrap();
    let (s, mh) = signed(&spec());
    set_ctx_full(
        "relayer.testnet",
        T0,
        300,
        NearToken::from_millinear(600),
        vec![],
    );
    let r: Value = serde_json::from_str(&g.register_mandate(s)).unwrap();
    assert_eq!(
        r["reason"], "deposit_too_small",
        "a registration without its deposit makes the gate pay"
    );
    assert!(g.get_mandate(mh).is_none());
}

// ---- M3-06: a direct-checkout order refused without an anchor keeps the payment ---------

#[test]
fn m3_06_direct_checkout_unanchored_refusal_returns_the_payment() {
    for tgas in (60..=110).step_by(5) {
        let mut g = new_gate();
        let (s, mh) = signed(&agentless()); // exact price 25
        let back = fund_full(&mut g, TOKEN, T0, tgas, &s, 25, Some(&order(&mh, 1, 25)));
        let anchored = g.get_receipt(mh.clone(), hex_lower(&[1; 32])).is_some();
        // Author adaptation after the A1 redesign (docs/audits/A1-contract.md, author response): since A1P-02 an undecided payment is kept for the buyer as refund
        // due (payable to refund_to at once), never handed back to the sender (1Click).
        let due = g.get_mandate(mh.clone()).map_or(0, |m| m.refund_due.0);
        assert!(
            anchored || (back == 0 && due == 25),
            "{tgas} Tgas: payment kept in escrow until expiry with no anchored decision (returned {back})"
        );
    }
}

// ---- M3-07: unanchored refusals of authorised callers are not attributable --------------

#[test]
fn m3_07_unanchored_refusal_event_names_mandate_and_order() {
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    assert_eq!(fund(&mut g, &s, 100), 0);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 100));
    let r = purchase_as(&mut g, AGENT, T0, &order(&mh, 2, 1));
    assert_eq!(r["reason"], "no_escrow");
    let ev = &events("refused")[0]["data"][0];
    assert_eq!(
        ev["mandate_hash"],
        mh.as_str(),
        "refused event cannot be tied to a mandate: {ev}"
    );
}

// ---- M3-08: an oversized success result is treated as a failed transfer -----------------

#[test]
fn m3_08_successful_transfer_with_long_result_is_not_restored() {
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    assert_eq!(fund(&mut g, &s, 100), 0);
    purchase_as(&mut g, AGENT, T0, &order(&mh, 1, 40));
    // The token's ft_transfer succeeded (tokens are with the payee) but returned 65 bytes.
    set_ctx(
        GATE,
        T0,
        300,
        vec![PromiseResult::Successful(vec![b'1'; 65])],
    );
    g.on_payout(hex_lower(&[1; 32]), mh.clone(), U128(40), acc(PAYEE), false);
    let m = g.get_mandate(mh.clone()).unwrap();
    assert_eq!(
        (m.spent.0, m.escrow.0),
        (40, 60),
        "budget restored although the payee was paid (40 could be paid twice)"
    );
    assert_eq!(
        g.get_receipt(mh, hex_lower(&[1; 32])).unwrap().payout,
        Payout::Done
    );
}

// ---- positive controls ------------------------------------------------------------------

#[test]
fn pc_fake_token_credit_refused() {
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    assert_eq!(fund_full(&mut g, STRANGER, T0, 300, &s, 100, None), 100);
    assert!(g.get_mandate(mh).is_none());
    assert_eq!(mandate_count(&g), 0);
}

#[test]
fn pc_agent_mandate_rejects_order_in_message_and_strangers() {
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    assert_eq!(fund(&mut g, &s, 50), 0);
    // Author adaptation after the A1 redesign (docs/audits/A1-contract.md, author response): an order inside a payment to an agent mandate is ignored and the
    // payment stays in escrow for the agent (A1P-02: never handed back); nothing is decided.
    assert_eq!(
        fund_full(&mut g, TOKEN, T0, 300, &s, 1, Some(&order(&mh, 1, 10))),
        0
    );
    assert!(g.get_receipt(mh.clone(), hex_lower(&[1; 32])).is_none());
    for who in [STRANGER, PAYEE, REFUND, TOKEN, GATE] {
        assert_eq!(
            purchase_as(&mut g, who, T0, &order(&mh, 2, 10))["reason"],
            "not_authorised"
        );
    }
    assert_eq!(g.get_mandate(mh).unwrap().spent.0, 0);
}

#[test]
fn pc_refund_by_stranger_pays_only_refund_to() {
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    assert_eq!(fund(&mut g, &s, 70), 0);
    assert_eq!(
        refund_as(&mut g, STRANGER, EXPIRY - 1, &mh)["reason"],
        "not_expired"
    );
    assert_eq!(refund_as(&mut g, STRANGER, EXPIRY, &mh)["amount"], "70");
    let transfers: Vec<_> = calls()
        .into_iter()
        .filter(|c| c.1 == "ft_transfer")
        .collect();
    assert_eq!(transfers.len(), 1);
    assert_eq!(
        (
            transfers[0].0.as_str(),
            transfers[0].2["receiver_id"].as_str()
        ),
        (TOKEN, Some(REFUND))
    );
    assert_eq!(
        refund_as(&mut g, STRANGER, EXPIRY, &mh)["reason"],
        "nothing_to_refund"
    );
}

#[test]
fn pc_payout_failure_after_refund_keeps_totals_consistent() {
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    assert_eq!(fund(&mut g, &s, 100), 0);
    purchase_as(&mut g, AGENT, EXPIRY - 1, &order(&mh, 1, 40));
    // The refund runs before the payout callback (another block).
    assert_eq!(refund_as(&mut g, STRANGER, EXPIRY, &mh)["amount"], "60");
    set_ctx(GATE, EXPIRY, 300, vec![PromiseResult::Failed]);
    assert!(!g.on_payout(hex_lower(&[1; 32]), mh.clone(), U128(40), acc(PAYEE), false));
    let m = g.get_mandate(mh.clone()).unwrap();
    assert_eq!(
        (m.funded.0, m.spent.0, m.escrow.0, m.refunded.0),
        (100, 0, 40, 60)
    );
    assert_eq!(g.get_totals()["total_escrow"], "40");
    assert_eq!(refund_as(&mut g, STRANGER, EXPIRY, &mh)["amount"], "40");
}

#[test]
fn pc_receipt_core_matches_formats_section_6() {
    let mut g = new_gate();
    let (s, mh) = signed(&spec());
    assert_eq!(fund(&mut g, &s, 30), 0);
    // R7 (above escrow) and R9 fail together: observed is the smaller escrow.
    let o = order_doc(&mh, 3, "report-404", 31, PAYEE);
    let r = purchase_as(&mut g, AGENT, T0, &o);
    assert_eq!(r["decision"], "refuse");
    let ev = &events("receipt")[0]["data"][0];
    let core = &ev["core"];
    let text = canonicalize(core).unwrap();
    assert_eq!(hash_hex(text.as_bytes()), ev["core_hash"].as_str().unwrap());
    let (_, h) = sampan_formats::parse_receipt_core(text.as_bytes()).unwrap();
    assert_eq!(
        g.get_receipt(mh.clone(), hex_lower(&[3; 32]))
            .unwrap()
            .core_hash,
        h
    );
    assert_eq!(core["observed"], json!({ "amount": "30", "asset": TOKEN }));
    assert_eq!(core["order_hash"], hash_hex(o.as_bytes()));
    let fails: Vec<_> = core["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["pass"] == false)
        .map(|r| r["id"].clone())
        .collect();
    assert_eq!(fails, vec![json!("R7"), json!("R9")]);
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
