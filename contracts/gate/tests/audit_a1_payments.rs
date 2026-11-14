//! Independent audit A1-payments (docs/audits/A1-payments.md): exploit tests and positive
//! controls for how money reaches and leaves the gate, written against its public API on
//! near-sdk's mocked VM. Audited commit: 51dac1d.
//!
//! Each `a1p_NN_*` test asserts the REQUIRED behaviour, so it FAILS while finding A1P-NN is
//! open. `pc_*` tests are positive controls and pass today.
//!
//! A 1Click delivery reaches the gate as `ft_on_transfer` called by the token, with
//! `sender_id` = the account that withdrew from NEAR Intents (here `intents.near`, an
//! **Assumption**: the real sender is 1Click's withdrawing account). Whatever the gate
//! returns from `ft_on_transfer` goes back to that sender, not to the buyer (M3-CR3).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};
use near_sdk::json_types::U128;
use near_sdk::test_utils::{get_created_receipts, get_logs, VMContextBuilder};
use near_sdk::{
    testing_env, AccountId, Gas, NearToken, PromiseOrValue, PromiseResult, RuntimeFeesConfig,
};
use sampan_formats::{canonicalize, hash_hex, hex_lower, nep413_hash};
use sampan_gate::{Config, Gate, Payout};
use serde_json::{json, Value};

const GATE: &str = "gate.testnet";
const TOKEN: &str = "usdc.testnet";
const PAYEE: &str = "shop.testnet";
const REFUND: &str = "buyer.testnet";
const STRANGER: &str = "stranger.testnet";
/// The account 1Click withdraws from (sender_id of the delivery). **Assumption.**
const ONECLICK: &str = "intents.near";
const T0: u64 = 1_000_000_000_000;
const EXPIRY: u64 = 2_000_000_000_000;
const LATER: u64 = 9_000_000_000_000;
/// USDC on NEAR mainnet: `storage_balance_bounds` = min = max = 0.00125 NEAR (read-only
/// mainnet RPC view, 6 Nov 2026, contract 17208628...a1).
const USDC_MAINNET_STORAGE: u128 = 1_250_000_000_000_000_000_000;

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn config() -> Config {
    Config {
        network: "testnet".into(),
        token: acc(TOKEN),
        min_funding: U128(1),
        max_escrow_per_mandate: U128(1_000_000),
        max_total_escrow: U128(3_000_000),
        max_mandates: 8,
        max_orders_per_mandate: 6,
        registration_deposit: U128(USDC_MAINNET_STORAGE),
        max_lifetime_ns: 86_400_000_000_000,
        guardian: None,
    }
}

fn set_ctx(pred: &str, now: u64, tgas: u64, results: Vec<PromiseResult>) {
    let ctx = VMContextBuilder::new()
        .current_account_id(acc(GATE))
        .predecessor_account_id(acc(pred))
        .signer_account_id(acc(pred))
        .block_timestamp(now)
        .block_height(4242)
        .prepaid_gas(Gas::from_tgas(tgas))
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

fn new_gate() -> Gate {
    set_ctx(GATE, T0, 300, vec![]);
    drop(near_sdk::mock::with_mocked_blockchain(|b| b.take_storage()));
    Gate::new(config()).unwrap()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A direct-checkout (agentless) mandate: exact price `max_amount`, one payee.
fn signed(max_amount: u128, nonce: u8, expiry: u64) -> (String, String) {
    signed_for("testnet", GATE, max_amount, nonce, expiry)
}

fn signed_for(
    network: &str,
    gate: &str,
    max_amount: u128,
    nonce: u8,
    expiry: u64,
) -> (String, String) {
    let k = key(9);
    let buyer = format!(
        "near:ed25519:{}",
        bs58::encode(k.verifying_key().to_bytes()).into_string()
    );
    let n = [nonce; 32];
    let mandate = json!({
        "v": "sampan.mandate.v1", "network": network, "gate": gate, "buyer": buyer,
        "agent": null, "asset": TOKEN, "max_amount": max_amount.to_string(),
        "payee": PAYEE, "items": ["report-001"], "expiry_ns": expiry.to_string(),
        "nonce": hex_lower(&n), "refund_to": REFUND,
    });
    let message = canonicalize(&mandate).unwrap();
    let digest = nep413_hash(&message, &n, gate).unwrap();
    let sig = hex_lower(&k.sign(&digest).to_bytes());
    let doc = json!({ "v": "sampan.signed-mandate.v1", "mandate": mandate, "standard": "nep413", "signature": sig });
    (canonicalize(&doc).unwrap(), hash_hex(message.as_bytes()))
}

fn order(mh: &str, id: u8, amount: u128) -> String {
    canonicalize(&json!({
        "v": "sampan.order.v1", "order_id": hex_lower(&[id; 32]), "mandate_hash": mh,
        "item": "report-001", "amount": amount.to_string(), "asset": TOKEN, "payee": PAYEE,
    }))
    .unwrap()
}

fn msg(signed: &str, order: Option<&str>) -> String {
    json!({ "signed_mandate": signed, "order": order }).to_string()
}

/// `ft_on_transfer` called by `token` for a transfer from `sender`; returns the amount
/// the gate hands back (which the token returns to `sender`).
fn deliver(
    g: &mut Gate,
    token: &str,
    sender: &str,
    now: u64,
    tgas: u64,
    amount: u128,
    m: &str,
) -> u128 {
    if token == TOKEN {
        register_from_msg(g, GATE, m, now);
    }
    set_ctx(token, now, tgas, vec![]);
    match g.ft_on_transfer(acc(sender), U128(amount), m.to_string()) {
        PromiseOrValue::Value(v) => v.0,
        PromiseOrValue::Promise(_) => panic!("ft_on_transfer must return a value"),
    }
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

fn transfers_to(who: &str) -> u128 {
    calls()
        .iter()
        .filter(|c| c.1 == "ft_transfer" && c.2["receiver_id"] == who)
        .map(|c| c.2["amount"].as_str().unwrap().parse::<u128>().unwrap())
        .sum()
}

fn events(name: &str) -> Vec<Value> {
    get_logs()
        .iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .map(|j| serde_json::from_str::<Value>(j).unwrap())
        .filter(|e| e["event"] == name)
        .collect()
}

fn escrow_of(g: &Gate, mh: &str) -> u128 {
    g.get_mandate(mh.to_string()).map_or(0, |m| m.escrow.0)
}

/// The buyer's money from a refused delivery must stay attributable to the buyer: either
/// the gate keeps it in the mandate's escrow (refundable only to `refund_to`), or it pays
/// it to `refund_to` at once. Handing it back to the 1Click sender is the failure.
fn assert_kept_for_buyer(g: &Gate, mh: &str, returned: u128, amount: u128, what: &str) {
    let to_refund_to = transfers_to(REFUND);
    // Author adaptation after the A1 redesign (docs/audits/A1-contract.md, author response): money kept for the buyer now sits in escrow or in "refund due",
    // both payable only to refund_to.
    let held = escrow_of(g, mh) + g.get_mandate(mh.to_string()).map_or(0, |m| m.refund_due.0);
    assert!(
        returned == 0 && (to_refund_to >= amount || held >= amount),
        "{what}: the gate handed {returned} of {amount} back to the 1Click sender ({ONECLICK}), \
         not to refund_to (paid to refund_to now: {to_refund_to}, held in escrow: {held}); \
         events: {:?}",
        events("funding_refused")
    );
}

// ---- A1P-02: refused 1Click deliveries go back to 1Click, not to the buyer (M3-CR3) ----

#[test]
fn a1p_02_late_1click_delivery_is_kept_for_the_buyer() {
    // The buyer paid on Base before the 1Click deadline; 1Click delivers on NEAR after
    // the mandate's expiry (deadline == expiry, as ARCHITECTURE 3.2 allows, or a slow
    // route). The gate refuses `expired` and returns the payment to 1Click's account.
    let mut g = new_gate();
    let (s, mh) = signed(25, 1, EXPIRY);
    let o = order(&mh, 1, 25);
    let back = deliver(&mut g, TOKEN, ONECLICK, EXPIRY, 300, 25, &msg(&s, Some(&o)));
    assert_kept_for_buyer(&g, &mh, back, 25, "late delivery");
}

#[test]
fn a1p_02_over_max_1click_delivery_is_kept_for_the_buyer() {
    // EXACT_INPUT / FLEX_INPUT quotes deliver a variable amount. 26 arrives for an exact
    // price of 25: the gate refuses `over_max_amount` and returns all 26 to 1Click.
    let mut g = new_gate();
    let (s, mh) = signed(25, 2, EXPIRY);
    let o = order(&mh, 1, 25);
    let back = deliver(&mut g, TOKEN, ONECLICK, T0, 300, 26, &msg(&s, Some(&o)));
    assert!(
        back < 26,
        "over-delivery: all 26 went back to the 1Click sender, none of it to refund_to \
         (events: {:?})",
        events("funding_refused")
    );
}

#[test]
fn a1p_02_low_gas_1click_delivery_is_kept_for_the_buyer() {
    // 1Click (via intents.near) chooses the gas forwarded to ft_on_transfer. With 50 Tgas
    // the direct-checkout decision cannot be anchored, so the gate undoes the mandate and
    // returns the payment to the sender (M3-06 fix), i.e. to 1Click.
    let mut g = new_gate();
    let (s, mh) = signed(25, 3, EXPIRY);
    let o = order(&mh, 1, 25);
    let back = deliver(&mut g, TOKEN, ONECLICK, T0, 50, 25, &msg(&s, Some(&o)));
    assert_kept_for_buyer(&g, &mh, back, 25, "low-gas delivery");
}

// ---- A1P-03: a stranger front-runs the delivery and bounces the buyer's payment -------

#[test]
fn a1p_03_front_run_funding_does_not_bounce_the_buyers_1click_delivery() {
    // The signed mandate and order travel in customRecipientMsg. Anyone who sees them
    // before 1Click delivers (the public /v0/status endpoint returns the quote request
    // for a deposit address visible on the origin chain; the merchant page; 1Click) can
    // create the mandate first with `min_funding` and no order.
    let mut g = new_gate();
    let (s, mh) = signed(25, 4, EXPIRY);
    assert_eq!(
        deliver(&mut g, TOKEN, STRANGER, T0, 300, 1, &msg(&s, None)),
        0
    );
    // The buyer's real delivery now hits `order_on_existing_mandate` and bounces.
    let o = order(&mh, 1, 25);
    let back = deliver(&mut g, TOKEN, ONECLICK, T0 + 1, 300, 25, &msg(&s, Some(&o)));
    let receipt = g.get_receipt(mh.clone(), hex_lower(&[1; 32]));
    assert!(
        back == 0 && receipt.is_some(),
        "a 1-unit front-run made the gate hand the buyer's 25 back to the 1Click sender \
         ({back} returned, order decided: {}); events: {:?}",
        receipt.is_some(),
        events("funding_refused")
    );
}

// ---- A1P-04: remainder after a direct-checkout release cannot reach refund_to ---------

#[test]
fn a1p_04_refund_after_direct_release_registers_refund_to() {
    // Delivery 25 for an order of 20 (EXACT_INPUT surplus, or a buyer-chosen lower
    // order): 20 is released and the gate pays the payee's USDC registration, which uses
    // the mandate's single registration. After expiry the refund of 5 is sent to an
    // unregistered refund_to without `storage_deposit`; USDC's ft_transfer then fails,
    // the escrow is restored, and every later refund fails the same way.
    let mut g = new_gate();
    let (s, mh) = signed(25, 5, EXPIRY);
    // Author adaptation after the A1 redesign (docs/audits/A1-contract.md, author response): an unsigned order inside a payment must ask for exactly the signed
    // price (A1C-04), so the surplus now comes from over-delivery: 30 for an order of 25.
    let o = order(&mh, 1, 25);
    assert_eq!(
        deliver(&mut g, TOKEN, ONECLICK, T0, 300, 30, &msg(&s, Some(&o))),
        0
    );
    assert!(calls()
        .iter()
        .any(|c| c.1 == "storage_deposit" && c.2["account_id"] == PAYEE));
    set_ctx(GATE, T0 + 1, 300, vec![PromiseResult::Successful(vec![])]);
    assert!(g.on_payout(hex_lower(&[1; 32]), mh.clone(), U128(25), acc(PAYEE), true));
    assert_eq!(
        escrow_of(&g, &mh) + g.get_mandate(mh.clone()).unwrap().refund_due.0,
        5
    );
    set_ctx(STRANGER, LATER, 300, vec![]);
    let r: Value = serde_json::from_str(&g.refund(mh.clone())).unwrap();
    assert_eq!(r["refund"], "pending");
    let registers_refund_to = calls()
        .iter()
        .any(|c| c.1 == "storage_deposit" && c.2["account_id"] == REFUND);
    assert!(
        registers_refund_to,
        "the refund of 5 to an unregistered refund_to carries no storage_deposit, so a real \
         NEP-141 (USDC) refuses it and the remainder is stuck until someone registers \
         refund_to by hand; calls: {:?}",
        calls()
    );
}

// ---- positive controls -------------------------------------------------------------

#[test]
fn pc_fake_token_delivery_is_returned_in_full_and_stores_nothing() {
    let mut g = new_gate();
    let (s, mh) = signed(25, 10, EXPIRY);
    let o = order(&mh, 1, 25);
    let back = deliver(
        &mut g,
        "fake-usdc.testnet",
        ONECLICK,
        T0,
        300,
        25,
        &msg(&s, Some(&o)),
    );
    assert_eq!(back, 25);
    assert!(g.get_mandate(mh).is_none());
    assert!(calls().is_empty());
}

#[test]
fn pc_exact_direct_checkout_pays_only_the_signed_payee() {
    let mut g = new_gate();
    let (s, mh) = signed(25, 11, EXPIRY);
    let o = order(&mh, 1, 25);
    assert_eq!(
        deliver(&mut g, TOKEN, ONECLICK, T0, 300, 25, &msg(&s, Some(&o))),
        0
    );
    let c = calls();
    assert_eq!(transfers_to(PAYEE), 25);
    assert!(c.iter().all(|c| c.0 == TOKEN || c.0 == GATE), "{c:?}");
    assert!(c
        .iter()
        .filter(|c| c.1 == "ft_transfer")
        .all(|c| c.2["receiver_id"] == PAYEE && c.3 == 1));
    // The registration batch matches USDC on NEAR mainnet: 0.00125 NEAR, registration only.
    let reg: Vec<_> = c.iter().filter(|c| c.1 == "storage_deposit").collect();
    assert_eq!(reg.len(), 1);
    assert_eq!(reg[0].2["registration_only"], true);
    assert!(reg[0].3 >= USDC_MAINNET_STORAGE);
    let m = g.get_mandate(mh.clone()).unwrap();
    assert_eq!((m.funded.0, m.spent.0, m.escrow.0), (25, 25, 0));
    assert_eq!(
        g.get_receipt(mh, hex_lower(&[1; 32])).unwrap().payout,
        Payout::Pending
    );
}

#[test]
fn pc_sender_id_does_not_change_attribution() {
    // Credit goes to the mandate named in msg whoever the sender is; sender_id is
    // neither stored nor logged.
    let mut g = new_gate();
    let (s, mh) = signed(25, 12, EXPIRY);
    assert_eq!(
        deliver(&mut g, TOKEN, ONECLICK, T0, 300, 10, &msg(&s, None)),
        0
    );
    assert_eq!(
        deliver(&mut g, TOKEN, STRANGER, T0, 300, 5, &msg(&s, None)),
        0
    );
    assert_eq!(escrow_of(&g, &mh), 15);
    assert!(get_logs().iter().all(|l| !l.contains(STRANGER)));
    let (s2, mh2) = signed(25, 13, EXPIRY);
    assert_eq!(
        deliver(&mut g, TOKEN, ONECLICK, T0, 300, 7, &msg(&s2, None)),
        0
    );
    assert_eq!((escrow_of(&g, &mh), escrow_of(&g, &mh2)), (15, 7));
    assert_eq!(g.get_totals()["total_escrow"], "22");
}

#[test]
fn pc_refused_order_keeps_funds_for_refund_to_only() {
    // Under-delivery (order 25, 24 arrived): anchored R7 refusal, the deposit stays in
    // escrow and after expiry goes only to refund_to, with refund_to's registration.
    let mut g = new_gate();
    let (s, mh) = signed(25, 14, EXPIRY);
    let o = order(&mh, 1, 25);
    assert_eq!(
        deliver(&mut g, TOKEN, ONECLICK, T0, 300, 24, &msg(&s, Some(&o))),
        0
    );
    assert_eq!(transfers_to(PAYEE), 0);
    // Author adaptation after audit A1R (docs/audits/A1R.md, author response): a refused order inside a
    // payment is no longer anchored (A1R-02); the refusal is an event and the payment is
    // refund due for refund_to.
    assert!(g.get_receipt(mh.clone(), hex_lower(&[1; 32])).is_none());
    assert_eq!(events("refused")[0]["data"][0]["reason"], "order_refused");
    set_ctx(STRANGER, LATER, 300, vec![]);
    let r: Value = serde_json::from_str(&g.refund(mh.clone())).unwrap();
    assert_eq!(r["refund"], "pending");
    assert_eq!(transfers_to(REFUND), 24);
    assert!(calls()
        .iter()
        .filter(|c| c.1 == "ft_transfer")
        .all(|c| c.2["receiver_id"] == REFUND));
    assert!(calls()
        .iter()
        .any(|c| c.1 == "storage_deposit" && c.2["account_id"] == REFUND));
}

#[test]
fn pc_failed_payout_restores_and_cannot_double_pay() {
    let mut g = new_gate();
    let (s, mh) = signed(25, 15, EXPIRY);
    let o = order(&mh, 1, 25);
    assert_eq!(
        deliver(&mut g, TOKEN, ONECLICK, T0, 300, 25, &msg(&s, Some(&o))),
        0
    );
    set_ctx(GATE, T0 + 1, 300, vec![PromiseResult::Failed]);
    assert!(!g.on_payout(hex_lower(&[1; 32]), mh.clone(), U128(25), acc(PAYEE), true));
    let m = g.get_mandate(mh.clone()).unwrap();
    // Author adaptation after audit A1R (docs/audits/A1R.md, author response): after a failed direct-checkout
    // payout the restored 25 is refund due, payable to refund_to at once (A1R-04); what is
    // held for the buyer is escrow + refund due.
    let held = |g: &Gate| {
        g.get_mandate(mh.clone())
            .map_or(0, |m| m.escrow.0 + m.refund_due.0)
    };
    let totals = |g: &Gate| -> u128 {
        let t = g.get_totals();
        t["total_escrow"].as_str().unwrap().parse::<u128>().unwrap()
            + t["total_refund_due"]
                .as_str()
                .unwrap()
                .parse::<u128>()
                .unwrap()
    };
    assert_eq!((m.spent.0, m.escrow.0 + m.refund_due.0), (0, 25));
    // A replayed callback (not possible on chain because of #[private]) still cannot
    // restore twice: spent is already 0.
    set_ctx(GATE, T0 + 2, 300, vec![PromiseResult::Failed]);
    g.on_payout(hex_lower(&[1; 32]), mh.clone(), U128(25), acc(PAYEE), true);
    assert_eq!(held(&g), 25);
    assert_eq!(totals(&g), 25);
    // The callback refuses any other caller.
    set_ctx(STRANGER, T0 + 3, 300, vec![PromiseResult::Failed]);
    assert!(!g.on_payout(hex_lower(&[1; 32]), mh.clone(), U128(25), acc(PAYEE), true));
    assert_eq!(held(&g), 25);
}

#[test]
fn pc_wrong_network_or_gate_delivery_returned_without_state() {
    let mut g = new_gate();
    // Correctly signed by the buyer, but for mainnet or for another gate (R2), and a
    // tampered copy (R1): each is handed back in full and nothing is stored.
    let reason = || events("funding_refused")[0]["data"][0]["reason"].clone();
    // Author adaptation after the A1 redesign (docs/audits/A1-contract.md, author response): R1 and R2 are now checked when the mandate is registered; the
    // payment then names no registered mandate and is handed back in full.
    let reg_reason = |g: &mut Gate, text: &str| -> Value {
        set_ctx("relayer.testnet", T0, 300, vec![]);
        serde_json::from_str::<Value>(&g.register_mandate(text.to_string())).unwrap()["reason"]
            .clone()
    };
    let (main, mh1) = signed_for("mainnet", GATE, 25, 16, EXPIRY);
    assert_eq!(reg_reason(&mut g, &main), json!("wrong_network"));
    assert_eq!(
        deliver(&mut g, TOKEN, ONECLICK, T0, 300, 25, &msg(&main, None)),
        25
    );
    assert_eq!(reason(), json!("unknown_mandate"));
    let (other, mh2) = signed_for("testnet", "gate2.testnet", 25, 17, EXPIRY);
    assert_eq!(reg_reason(&mut g, &other), json!("wrong_gate"));
    assert_eq!(
        deliver(&mut g, TOKEN, ONECLICK, T0, 300, 25, &msg(&other, None)),
        25
    );
    assert_eq!(reason(), json!("unknown_mandate"));
    let (s, mh3) = signed(25, 18, EXPIRY);
    let tampered = s.replace("\"max_amount\":\"25\"", "\"max_amount\":\"26\"");
    assert_ne!(tampered, s);
    assert_eq!(
        deliver(&mut g, TOKEN, ONECLICK, T0, 300, 26, &msg(&tampered, None)),
        26
    );
    assert_eq!(reason(), json!("mandate_invalid"));
    for mh in [mh1, mh2, mh3] {
        assert!(g.get_mandate(mh).is_none());
    }
    assert_eq!(g.get_totals()["total_escrow"], "0");
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
