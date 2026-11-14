//! Independent audit M4 (docs/audits/M4.md): positive controls for the gate behaviour the
//! M4 demo relies on, on near-sdk's mocked VM. Both pass today; they pin the behaviour the
//! demo's claims rest on (refused injections move nothing; the order cap of M4-01 blocks
//! but cannot move funds, and the escrow still goes back to `refund_to` after expiry).
#![allow(clippy::unwrap_used, clippy::expect_used)]
use ed25519_dalek::{Signer, SigningKey};
use near_sdk::json_types::U128;
use near_sdk::test_utils::{get_created_receipts, VMContextBuilder};
use near_sdk::{testing_env, AccountId, Gas, NearToken, PromiseOrValue, RuntimeFeesConfig};
use sampan_formats::{canonicalize, hash_hex, hex_lower, nep413_hash};
use sampan_gate::{Config, Gate};
use serde_json::{json, Value};

const GATE: &str = "gate.testnet";
const TOKEN: &str = "usdc.testnet";
const AGENT: &str = "agent.testnet";
const PAYEE: &str = "shop.testnet";
const ATTACKER: &str = "attacker-m4.testnet";
const REFUND: &str = "buyer.testnet";
const T0: u64 = 1_000_000_000_000;
const EXPIRY: u64 = 2_000_000_000_000;

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn ctx(pred: &str, now: u64) {
    let c = VMContextBuilder::new()
        .current_account_id(acc(GATE))
        .predecessor_account_id(acc(pred))
        .block_timestamp(now)
        .block_height(4242)
        .prepaid_gas(Gas::from_tgas(300))
        .account_balance(NearToken::from_near(10))
        .build();
    testing_env!(
        c,
        near_sdk::test_vm_config(),
        RuntimeFeesConfig::test(),
        Default::default(),
        vec![]
    );
}

fn gate(max_orders: u32) -> (Gate, String) {
    ctx(GATE, T0);
    drop(near_sdk::mock::with_mocked_blockchain(|b| b.take_storage()));
    ctx(GATE, T0);
    let mut g = Gate::new(Config {
        network: "testnet".into(),
        token: acc(TOKEN),
        min_funding: U128(10),
        max_escrow_per_mandate: U128(1_000_000_000),
        max_total_escrow: U128(1_000_000_000),
        max_mandates: 4,
        max_orders_per_mandate: max_orders,
        registration_deposit: U128(1_250_000_000_000_000_000_000),
        max_lifetime_ns: 86_400_000_000_000,
        guardian: None,
    })
    .unwrap();
    let k = SigningKey::from_bytes(&[42; 32]);
    let nonce = [9u8; 32];
    let mandate = json!({
        "v": "sampan.mandate.v1", "network": "testnet", "gate": GATE,
        "buyer": format!("near:ed25519:{}", bs58::encode(k.verifying_key().to_bytes()).into_string()),
        "agent": AGENT, "asset": TOKEN, "max_amount": "3000000", "payee": PAYEE,
        "items": ["report-001", "report-002"], "expiry_ns": EXPIRY.to_string(),
        "nonce": hex_lower(&nonce), "refund_to": REFUND,
    });
    let message = canonicalize(&mandate).unwrap();
    let sig = k
        .sign(&nep413_hash(&message, &nonce, GATE).unwrap())
        .to_bytes();
    let doc = json!({ "v": "sampan.signed-mandate.v1", "mandate": mandate, "standard": "nep413", "signature": hex_lower(&sig) });
    let signed = canonicalize(&doc).unwrap();
    let m = json!({ "signed_mandate": signed, "order": null }).to_string();
    register_from_msg(&mut g, GATE, &m, T0);
    ctx(TOKEN, T0);
    let r = g.ft_on_transfer(acc(REFUND), U128(3_000_000), m);
    assert!(matches!(r, PromiseOrValue::Value(U128(0))));
    (g, hash_hex(message.as_bytes()))
}

fn buy(g: &mut Gate, mh: &str, n: u8, item: &str, payee: &str, amount: &str) -> Value {
    let order = canonicalize(&json!({
        "v": "sampan.order.v1", "order_id": hex_lower(&[n; 32]), "mandate_hash": mh,
        "item": item, "amount": amount, "asset": TOKEN, "payee": payee,
    }))
    .unwrap();
    ctx(AGENT, T0);
    serde_json::from_str(&g.purchase(order)).unwrap()
}

#[test]
fn pc_m4_refused_injections_change_no_balance() {
    let (mut g, mh) = gate(16);
    let before = g.get_mandate(mh.clone()).unwrap();
    for (n, (item, payee, amount)) in [
        ("report-001", ATTACKER, "1000000"),
        ("premium-bundle-999", PAYEE, "1000000"),
        ("report-001", PAYEE, "5000000"),
    ]
    .iter()
    .enumerate()
    {
        let r = buy(
            &mut g,
            &mh,
            u8::try_from(n + 1).unwrap(),
            item,
            payee,
            amount,
        );
        assert_eq!(r["decision"], "refuse");
        assert_eq!(r["anchored"], true);
        assert!(
            get_created_receipts().is_empty(),
            "a refusal creates no transfer"
        );
    }
    let after = g.get_mandate(mh).unwrap();
    assert_eq!(
        (after.escrow, after.spent, after.funded),
        (before.escrow, before.spent, before.funded)
    );
    assert_eq!(after.orders, before.orders + 3);
}

/// M4-01 as built: refused injections fill the order cap, a later valid order is refused
/// (unanchored, `order_cap`), nothing moves, and the escrow is still refundable to
/// `refund_to` after expiry.
#[test]
fn pc_m4_01_order_cap_blocks_but_moves_no_funds() {
    let (mut g, mh) = gate(4);
    for n in 1..=4u8 {
        assert_eq!(
            buy(&mut g, &mh, n, "report-001", ATTACKER, "1000000")["decision"],
            "refuse"
        );
    }
    let r = buy(&mut g, &mh, 5, "report-001", PAYEE, "1000000");
    assert_ne!(r["decision"], "release", "{r}");
    assert_eq!(g.get_mandate(mh.clone()).unwrap().escrow, U128(3_000_000));
    ctx(REFUND, EXPIRY);
    let r: Value = serde_json::from_str(&g.refund(mh.clone())).unwrap();
    assert_eq!(r["refund"], "pending", "{r}");
    assert_eq!(r["amount"], "3000000");
    assert_eq!(g.get_mandate(mh).unwrap().escrow, U128(0));
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
