//! M4: the labelled agent-demo fixtures (fixtures/attacks/agent-demo/) run through the gate
//! on near-sdk's mocked VM. Every attack must be refused with exactly the rules its fixture
//! names failing, and every control must be released. The fixtures are data: this test
//! reads only `label`, `agent_proposes` and `expected`, never the page text.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use ed25519_dalek::{Signer, SigningKey};
use near_sdk::json_types::U128;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{testing_env, AccountId, Gas, NearToken, PromiseOrValue, RuntimeFeesConfig};
use sampan_formats::{canonicalize, hash_hex, hex_lower, nep413_hash};
use sampan_gate::{Config, Gate};
use serde_json::{json, Value};

const GATE: &str = "gate.testnet";
const TOKEN: &str = "usdc.testnet";
const FAKE_TOKEN: &str = "fake-usdc.testnet";
const AGENT: &str = "agent.testnet";
const PAYEE: &str = "shop.testnet";
const ATTACKER: &str = "attacker-m4.testnet";
const T0: u64 = 1_000_000_000_000;

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn ctx(pred: &str) {
    let c = VMContextBuilder::new()
        .current_account_id(acc(GATE))
        .predecessor_account_id(acc(pred))
        .block_timestamp(T0)
        .block_height(4242)
        .prepaid_gas(Gas::from_tgas(300))
        .account_balance(NearToken::from_near(10))
        .storage_usage(0)
        .build();
    testing_env!(
        c,
        near_sdk::test_vm_config(),
        RuntimeFeesConfig::test(),
        Default::default(),
        vec![]
    );
}

fn resolve(s: &str) -> String {
    s.replace("{{PAYEE}}", PAYEE)
        .replace("{{ATTACKER}}", ATTACKER)
        .replace("{{FAKE_TOKEN}}", FAKE_TOKEN)
        .replace("{{TOKEN}}", TOKEN)
}

fn fixtures() -> Vec<Value> {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/attacks/agent-demo");
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    names.sort();
    names
        .iter()
        .map(|p| serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
        .collect()
}

/// The demo mandate: items report-001 and report-002, payee PAYEE, budget 6 tokens.
fn signed_mandate() -> (String, String) {
    let k = SigningKey::from_bytes(&[42; 32]);
    let nonce = [7u8; 32];
    let mandate = json!({
        "v": "sampan.mandate.v1", "network": "testnet", "gate": GATE,
        "buyer": format!("near:ed25519:{}", bs58::encode(k.verifying_key().to_bytes()).into_string()),
        "agent": AGENT, "asset": TOKEN, "max_amount": "6000000", "payee": PAYEE,
        "items": ["report-001", "report-002"], "expiry_ns": "2000000000000",
        "nonce": hex_lower(&nonce), "refund_to": "buyer.testnet",
    });
    let message = canonicalize(&mandate).unwrap();
    let sig = k
        .sign(&nep413_hash(&message, &nonce, GATE).unwrap())
        .to_bytes();
    let doc = json!({ "v": "sampan.signed-mandate.v1", "mandate": mandate, "standard": "nep413", "signature": hex_lower(&sig) });
    (canonicalize(&doc).unwrap(), hash_hex(message.as_bytes()))
}

/// A fresh gate with the demo mandate funded with its whole 6-token budget.
fn funded_gate(orders_cap: u32) -> (Gate, String) {
    ctx(GATE);
    drop(near_sdk::mock::with_mocked_blockchain(|b| b.take_storage()));
    ctx(GATE);
    let mut g = Gate::new(Config {
        network: "testnet".into(),
        token: acc(TOKEN),
        min_funding: U128(10),
        max_escrow_per_mandate: U128(1_000_000_000),
        max_total_escrow: U128(1_000_000_000),
        max_mandates: 4,
        max_orders_per_mandate: orders_cap,
        registration_deposit: U128(1_250_000_000_000_000_000_000),
        max_lifetime_ns: 86_400_000_000_000,
        guardian: None,
    })
    .unwrap();
    let (signed, mh) = signed_mandate();
    let m = json!({ "signed_mandate": signed, "order": null }).to_string();
    register_from_msg(&mut g, GATE, &m, T0);
    ctx(TOKEN);
    let funded = g.ft_on_transfer(acc("buyer.testnet"), U128(6_000_000), m);
    assert!(matches!(funded, PromiseOrValue::Value(U128(0))));
    (g, mh)
}

fn order(mh: &str, n: u8, item: &str, amount: &str) -> String {
    canonicalize(&json!({
        "v": "sampan.order.v1", "order_id": hex_lower(&[n; 32]), "mandate_hash": mh,
        "item": item, "amount": amount, "asset": TOKEN, "payee": PAYEE,
    }))
    .unwrap()
}

/// M4-01 (found on testnet): anchored refusals count against `max_orders_per_mandate`, so
/// with a cap of 8, six refused injections and two releases leave no room for a third valid
/// order: it is refused without an anchor (`order_cap`) and no funds move. With 16 it is paid.
#[test]
fn m4_01_order_cap_counts_refusals() {
    for (cap, third_released) in [(8u32, false), (16, true)] {
        let (mut g, mh) = funded_gate(cap);
        for n in 1..=6u8 {
            ctx(AGENT);
            let r: Value =
                serde_json::from_str(&g.purchase(order(&mh, n, "report-404", "1000000"))).unwrap();
            assert_eq!(
                (r["decision"].as_str(), r["anchored"].as_bool()),
                (Some("refuse"), Some(true))
            );
        }
        for n in 7..=8u8 {
            ctx(AGENT);
            let r: Value =
                serde_json::from_str(&g.purchase(order(&mh, n, "report-001", "1000000"))).unwrap();
            assert_eq!(r["decision"], "release", "cap {cap}");
        }
        ctx(AGENT);
        let r: Value =
            serde_json::from_str(&g.purchase(order(&mh, 9, "report-002", "1000000"))).unwrap();
        if third_released {
            assert_eq!(r["decision"], "release", "cap {cap}");
        } else {
            assert_eq!(
                (
                    r["decision"].as_str(),
                    r["anchored"].as_bool(),
                    r["reason"].as_str()
                ),
                (Some("refuse"), Some(false), Some("order_cap"))
            );
            assert_eq!(
                g.get_mandate(mh.clone()).unwrap().spent.0,
                2_000_000,
                "no funds moved for the capped order"
            );
        }
    }
}

#[test]
fn every_attack_refused_every_control_released() {
    let (mut g, mh) = funded_gate(16);

    let all = fixtures();
    assert!(all.len() >= 9, "fixture suite present");
    // Attacks first, so the controls' spending cannot be what makes an attack fail.
    let mut ordered: Vec<&Value> = all.iter().filter(|f| f["label"] == "attack").collect();
    ordered.extend(all.iter().filter(|f| f["label"] == "control"));
    let (mut attacks, mut refused, mut controls, mut released) = (0, 0, 0, 0);
    let (mut misses, mut misses_released) = (0, 0);
    for (n, f) in ordered.iter().enumerate() {
        let id = f["id"].as_str().unwrap();
        let p = &f["agent_proposes"];
        let order = canonicalize(&json!({
            "v": "sampan.order.v1",
            "order_id": hex_lower(&[u8::try_from(n + 1).unwrap(); 32]),
            "mandate_hash": mh,
            "item": p["item"],
            "amount": p["amount"],
            "asset": resolve(p["asset"].as_str().unwrap()),
            "payee": resolve(p["payee"].as_str().unwrap()),
        }))
        .unwrap();
        ctx(AGENT);
        let r: Value = serde_json::from_str(&g.purchase(order)).unwrap();
        let logs = near_sdk::test_utils::get_logs();
        let ev = logs
            .iter()
            .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
            .map(|j| serde_json::from_str::<Value>(j).unwrap())
            .find(|e| e["event"] == "receipt")
            .unwrap_or_else(|| panic!("{id}: decision not anchored: {r}"));
        let failing: Vec<Value> = ev["data"][0]["core"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|x| x["pass"] == false)
            .map(|x| x["id"].clone())
            .collect();
        assert_eq!(r["decision"], f["expected"]["decision"], "{id}");
        assert_eq!(
            Value::from(failing),
            f["expected"]["failing"],
            "{id}: failing rules"
        );
        if f["label"] == "attack" && f["expected"]["decision"] == "release" {
            // Known miss (M4-08): inside the signed mandate, released by design.
            misses += 1;
            misses_released += usize::from(r["decision"] == "release");
        } else if f["label"] == "attack" {
            attacks += 1;
            refused += usize::from(r["decision"] == "refuse");
        } else {
            controls += 1;
            released += usize::from(r["decision"] == "release");
        }
    }
    println!("attacks refused: {refused}/{attacks}; known misses released: {misses_released}/{misses}; controls released: {released}/{controls}; false positives: {}", controls - released);
    assert_eq!(
        (refused, misses_released, released),
        (attacks, misses, controls)
    );
    assert!(attacks >= 6 && controls >= 3);
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
