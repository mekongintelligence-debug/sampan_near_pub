//! Gate contract (M3, docs/ARCHITECTURE_AND_PLAN.md section 3.4). Holds escrowed
//! tokens per signed mandate and releases them only when an order passes rules R1-R9.
//!
//! Flow (after audit A1, decided 6-7 Nov 2026):
//! - Registration: `register_mandate(signed_mandate)` with an attached deposit that pays the
//!   mandate's worst-case storage and two token registrations (Q17: whoever creates gate
//!   state pays). It checks R1, R2, asset, expiry within `max_lifetime_ns`, nonce and the
//!   open-mandate cap. On close the registrant gets back what the mandate does not still use.
//! - Funding: `ft_transfer_call` on the configured token with `msg` =
//!   `{"mandate_hash": "<hex>", "order": "<canonical order>" | null}` (fits 1Click's
//!   1,024-character limit, A1P-01) or `{"signed_mandate": "...", "order": ...}`. A payment
//!   that names a registered mandate is never handed back to the sender (1Click's account,
//!   A1P-02): whatever cannot go into escrow becomes "refund due", payable to `refund_to` at
//!   any time. Only an unknown or unreadable message returns the payment.
//! - Direct checkout (`agent` null) is one purchase at exactly the signed price: an order in
//!   the payment is decided only if it asks for `max_amount` and nothing was released yet;
//!   leftovers and later payments become refund due (A1P-03, A1C-04).
//! - `purchase(order)`: the mandate's agent (or, with `agent` null, the buyer's NEAR
//!   implicit account) asks for a release. Rules run; the decision is anchored as a
//!   receipt core (hash stored, full core in a NEP-297 event) and, on release, the gate
//!   pays the payee with a `#[private]` callback that restores the budget on failure.
//! - `refund(mandate_hash)`: anyone; pays refund due at any time and the escrow after
//!   expiry, only to `refund_to`.
//! - `stop()`: the guardian named in the config can stop the gate for good: no new
//!   mandates, payments become refund due, refunds keep working (A1C-03, Q36).
//!
//! Refusals return normally (docs/SECURITY.md 3.1): a panic would roll back the receipt.
//! Calls that are not authorised for a mandate (unknown mandate, wrong caller, a reused
//! order ID) are refused without writing state, so strangers cannot fill storage.

// Contract code: no panics, no unchecked arithmetic or indexing (docs/SECURITY.md 3.1).
// `forbid` cannot be overridden by a local #[allow]. Tests are exempt so they can use
// ordinary arithmetic and assertions. Banned macros are listed in clippy.toml;
// banned calls (env::panic_str, env::abort) are checked by scripts/lint-banned.mjs.
#![cfg_attr(
    not(test),
    forbid(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::disallowed_macros
    )
)]

pub mod rules;

use near_sdk::json_types::U128;
use near_sdk::serde::Deserialize;
use near_sdk::store::{LookupMap, LookupSet};
use near_sdk::{
    env, near, AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault, Promise, PromiseError,
    PromiseOrValue,
};
use rules::{evaluate, RuleMandate};
use sampan_formats::{
    canonicalize, hex_lower, parse_order, parse_receipt_core, verify_signed_mandate, Buyer, Order,
    MAX_DOC_BYTES, RULE_IDS,
};
use serde_json::{json, Value};

/// Version string reported by the contract, so deployments can be identified.
pub const VERSION: &str = "0.2.0-a1";

/// Upper bound for the funding message: two documents of at most 4096 bytes each,
/// JSON-escaped (quotes double in size at most) plus the wrapper.
pub const MAX_MSG_BYTES: usize = 17_000;

pub const GAS_STORAGE_DEPOSIT: Gas = Gas::from_tgas(10);
pub const GAS_FT_TRANSFER: Gas = Gas::from_tgas(15);
pub const GAS_CALLBACK: Gas = Gas::from_tgas(20);
/// Left for this call to finish after the gas check: storage writes, the event and the
/// receipt-creation fees of the transfer batch and callback (measured on the mocked VM,
/// M3-CR5; 20 Tgas was not enough).
pub const GAS_MARGIN: Gas = Gas::from_tgas(40);

/// 0.00125 NEAR: the NEP-145 minimum of near-contract-standards tokens (incl. USDC on NEAR).
pub const MIN_REGISTRATION_DEPOSIT: u128 = 1_250_000_000_000_000_000_000;
pub const MAX_REGISTRATION_DEPOSIT: u128 = 100_000_000_000_000_000_000_000;

/// Worst-case storage of one mandate record with its nonce, and of one receipt, in bytes
/// as NEAR charges it (key + value + 40). Measured by the M3 audit (1,759 and 336 bytes
/// at `ea0f207`) plus the fields and longer keys added since, with margin (M3-05).
pub const WORST_MANDATE_BYTES: u128 = 2_400;
pub const WORST_RECEIPT_BYTES: u128 = 450;

/// Callbacks read at most this many bytes of the token's result.
const MAX_RESULT_BYTES: usize = 64;

#[near(serializers = [borsh])]
#[derive(BorshStorageKey)]
enum StorageKey {
    Mandates,
    Nonces,
    Receipts,
    Registered,
}

/// Shortest and longest mandate lifetime a deployment may allow (A1C-01).
pub const MIN_LIFETIME_NS: u64 = 3_600_000_000_000; // 1 hour
pub const MAX_LIFETIME_NS: u64 = 30 * 86_400_000_000_000; // 30 days
/// Bytes NEAR charges per stored entry on top of key and value.
const ENTRY_OVERHEAD: u64 = 40;

/// Deployment settings, fixed at initialisation (no admin methods, no upgrade method:
/// testnet redeploys with the account key; the mainnet account is locked, Q16).
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// `testnet` or `mainnet`; must equal the mandate's `network` (R2).
    pub network: String,
    /// The only token accepted (USDC on NEAR, Q14).
    pub token: AccountId,
    /// Smallest first deposit for a new mandate (bounds storage the gate pays for).
    pub min_funding: U128,
    /// Most a single mandate may ever be funded with.
    pub max_escrow_per_mandate: U128,
    /// Most the gate holds in escrow at once.
    pub max_total_escrow: U128,
    /// Most mandates open at once. A mandate closes (its record is removed) once it has
    /// expired, holds no escrow and has no transfer in flight (M3-02).
    pub max_mandates: u32,
    /// Most anchored receipts per mandate.
    pub max_orders_per_mandate: u32,
    /// NEAR attached to each storage registration, in yoctoNEAR.
    pub registration_deposit: U128,
    /// Longest time a mandate may stay open after registration, so nobody can hold the
    /// gate's slots or caps for good (A1C-01; recommended 24 hours).
    pub max_lifetime_ns: u64,
    /// Account allowed to stop the gate for good (A1C-03); `None` = no stop switch.
    pub guardian: Option<AccountId>,
}

impl Config {
    fn validate(&self) -> Result<(), String> {
        if self.network != "testnet" && self.network != "mainnet" {
            return Err("network must be testnet or mainnet".to_string());
        }
        let min = self.min_funding.0;
        if min == 0 || self.max_escrow_per_mandate.0 < min || self.max_total_escrow.0 < min {
            return Err("caps must satisfy 0 < min_funding <= max caps".to_string());
        }
        if self.max_mandates == 0 || self.max_orders_per_mandate == 0 {
            return Err("record caps must be positive".to_string());
        }
        if !(MIN_LIFETIME_NS..=MAX_LIFETIME_NS).contains(&self.max_lifetime_ns) {
            return Err("max_lifetime_ns must be 1 hour to 30 days".to_string());
        }
        // The config cannot be changed later (no admin methods, locked account), so a
        // deposit below NEP-145's usual minimum would break every first payout (M3-CR4).
        let dep = self.registration_deposit.0;
        if !(MIN_REGISTRATION_DEPOSIT..=MAX_REGISTRATION_DEPOSIT).contains(&dep) {
            return Err("registration_deposit must be 0.00125 to 0.1 NEAR".to_string());
        }
        Ok(())
    }

    /// Deposit `register_mandate` requires: the record, every receipt it may anchor, and
    /// two token registrations (payee and `refund_to`, A1P-04) (M3-05, A1C-02).
    pub fn reservation_per_mandate(&self) -> u128 {
        let bytes = WORST_RECEIPT_BYTES
            .saturating_mul(u128::from(self.max_orders_per_mandate))
            .saturating_add(WORST_MANDATE_BYTES);
        env::storage_byte_cost()
            .as_yoctonear()
            .saturating_mul(bytes)
            .saturating_add(self.registration_deposit.0.saturating_mul(2))
    }
}

/// The gate's balance above what its current storage locks.
fn free_balance() -> u128 {
    let locked = env::storage_byte_cost().saturating_mul(u128::from(env::storage_usage()));
    env::account_balance().saturating_sub(locked).as_yoctonear()
}

/// A registered mandate. Every field comes from a verified signed mandate, except the
/// counters, which only the gate writes.
/// Invariant: funded = spent + escrow + refunded + refund_due.
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MandateRecord {
    /// The buyer's NEAR implicit account (NEP-413 buyers only); may call `purchase`
    /// when `agent` is null.
    pub buyer_account: Option<AccountId>,
    pub agent: Option<AccountId>,
    pub asset: AccountId,
    pub payee: AccountId,
    pub refund_to: AccountId,
    pub items: Vec<String>,
    pub max_amount: u128,
    pub expiry_ns: u64,
    pub funded: u128,
    pub spent: u128,
    pub escrow: u128,
    pub refunded: u128,
    /// Money kept for the buyer that may go to `refund_to` at any time (A1P-02).
    pub refund_due: u128,
    pub orders: u32,
    /// Payouts and refunds in flight; the mandate cannot close while this is non-zero.
    pub pending: u32,
    /// Token registrations the gate has paid or is paying for this mandate (at most 2).
    pub registrations_in_use: u8,
    /// Key of the nonce in `Gate::nonces`, removed when the mandate closes.
    pub nonce_key: String,
    /// Who registered the mandate and the deposit they attached (A1C-02).
    pub registrant: AccountId,
    pub deposit: u128,
    /// Storage this mandate leaves behind after closing (receipts, registrations), charged
    /// to its deposit.
    pub kept_bytes: u64,
    /// Agentless mandates: the single purchase was released (A1C-04).
    pub released: bool,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Payout {
    /// Refusal: nothing to pay.
    None,
    Pending,
    Done,
    /// The token transfer failed; the mandate's budget and escrow were restored.
    Failed,
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRecord {
    pub mandate_hash: String,
    pub core_hash: String,
    pub release: bool,
    pub amount: u128,
    pub payout: Payout,
    pub block_height: u64,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MandateView {
    pub agent: Option<AccountId>,
    pub payee: AccountId,
    pub refund_to: AccountId,
    pub max_amount: U128,
    pub expiry_ns: String,
    pub funded: U128,
    pub spent: U128,
    pub escrow: U128,
    pub refunded: U128,
    pub refund_due: U128,
    pub orders: u32,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptView {
    pub mandate_hash: String,
    pub core_hash: String,
    pub decision: String,
    pub amount: U128,
    pub payout: Payout,
    pub block_height: String,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct FundingMsg {
    #[serde(default)]
    signed_mandate: Option<String>,
    #[serde(default)]
    mandate_hash: Option<String>,
    order: Option<String>,
}

/// Who is asking for a decision.
enum Authority {
    /// `purchase` called by this account.
    Caller(AccountId),
    /// An order delivered with the funding transfer: the buyer's signature is the authority
    /// (valid only for mandates with `agent` null).
    BuyerSignature,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Gate {
    config: Config,
    mandates: LookupMap<String, MandateRecord>,
    nonces: LookupSet<String>,
    receipts: LookupMap<String, ReceiptRecord>,
    registered: LookupSet<AccountId>,
    /// Successful gate-paid registrations (information only).
    registrations: u32,
    /// Mandates stored (open, or expired and not yet closed).
    open_mandates: u32,
    /// Expiry of every mandate registered and not yet expired; `max_mandates` bounds its
    /// length (A1R-01: an expired mandate never holds a slot, even if it cannot close).
    live_expiries: Vec<u64>,
    total_escrow: u128,
    /// Sum of all mandates' refund due.
    total_refund_due: u128,
    /// Set for good by the guardian (A1C-03).
    stopped: bool,
}

/// Result of `decide`: the JSON returned to the caller, and whether it was anchored.
struct Decision {
    json: String,
    anchored: bool,
}

fn unanchored(json: String) -> Decision {
    Decision {
        json,
        anchored: false,
    }
}

/// Key of a mandate nonce: nonces are single use per buyer, so nobody can block a
/// buyer's mandate by funding their own mandate with the same nonce first (M3-CR1).
fn nonce_key(buyer: &Buyer, nonce: &[u8; 32]) -> String {
    let who = match buyer {
        Buyer::Near { public_key } => format!("near:{}", hex_lower(public_key)),
        Buyer::Evm { address } => format!("evm:{}", hex_lower(address)),
    };
    format!("{who}:{}", hex_lower(nonce))
}

fn receipt_key(mandate_hash: &str, order_id: &str) -> String {
    format!("{mandate_hash}:{order_id}")
}

/// Which counter a failed transfer is restored from.
enum Bucket {
    Spent,
    Refunded,
}

/// Storage of one map entry as NEAR charges it: 1-byte collection prefix, borsh key
/// (4-byte length + bytes), value and the per-entry overhead.
fn entry_bytes(key_len: usize, value_len: usize) -> u64 {
    u64::try_from(key_len.saturating_add(value_len).saturating_add(5))
        .unwrap_or(u64::MAX)
        .saturating_add(ENTRY_OVERHEAD)
}

fn is_hex32(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// NEP-297 event. `data` must already be JSON built only from grammar-checked values.
fn emit(event: &str, data: &str) {
    env::log_str(&format!(
        "EVENT_JSON:{{\"data\":[{data}],\"event\":\"{event}\",\"standard\":\"sampan\",\"version\":\"1.0.0\"}}"
    ));
}

fn refusal(reason: &'static str) -> String {
    emit("refused", &json!({ "reason": reason }).to_string());
    json!({ "decision": "refuse", "anchored": false, "reason": reason }).to_string()
}

/// Refusal of an authorised caller: the event names the mandate and order (both
/// grammar-checked hex) so it can be attributed (M3-07).
fn refusal_for(reason: &'static str, mandate_hash: &str, order_id: &str) -> String {
    emit(
        "refused",
        &json!({ "reason": reason, "mandate_hash": mandate_hash, "order_id": order_id })
            .to_string(),
    );
    json!({ "decision": "refuse", "anchored": false, "reason": reason, "mandate_hash": mandate_hash, "order_id": order_id })
        .to_string()
}

fn gas_left() -> u64 {
    env::prepaid_gas()
        .as_gas()
        .saturating_sub(env::used_gas().as_gas())
}

fn gas_needed(register: bool) -> u64 {
    let mut need = GAS_FT_TRANSFER
        .as_gas()
        .saturating_add(GAS_CALLBACK.as_gas())
        .saturating_add(GAS_MARGIN.as_gas());
    if register {
        need = need.saturating_add(GAS_STORAGE_DEPOSIT.as_gas());
    }
    need
}

#[near]
impl Gate {
    #[init]
    #[private]
    #[handle_result]
    pub fn new(config: Config) -> Result<Self, String> {
        // #[private] holds in the wasm entry point; this also holds in direct calls (M3-04).
        if env::predecessor_account_id() != env::current_account_id() {
            return Err("only the gate account may initialise it".to_string());
        }
        config.validate()?;
        // The network must be the one the account lives on (A1C-09).
        // Implicit accounts exist on both networks, so they are refused (A1R-08).
        let account = env::current_account_id();
        let fits = match config.network.as_str() {
            "testnet" => account.as_str().ends_with(".testnet"),
            "mainnet" => account.as_str().ends_with(".near"),
            _ => false,
        };
        if !fits {
            return Err("network does not match the gate account".to_string());
        }
        // Mandate storage is paid by registration deposits (A1C-02), not by the gate.
        Ok(Self {
            config,
            mandates: LookupMap::new(StorageKey::Mandates),
            nonces: LookupSet::new(StorageKey::Nonces),
            receipts: LookupMap::new(StorageKey::Receipts),
            registered: LookupSet::new(StorageKey::Registered),
            registrations: 0,
            open_mandates: 0,
            live_expiries: Vec::new(),
            total_escrow: 0,
            total_refund_due: 0,
            stopped: false,
        })
    }

    // ---- funding ---------------------------------------------------------------------

    /// NEP-141 receiver. Returns the amount to give back: zero for any payment that names a
    /// registered mandate (it is kept for the buyer), everything only when the message is
    /// unreadable or names no registered mandate. Never panics.
    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        // The sender may be 1Click's account; it is never trusted, stored or logged.
        let _ = sender_id;
        if env::predecessor_account_id() != self.config.token {
            emit(
                "funding_refused",
                &json!({ "reason": "wrong_token" }).to_string(),
            );
            return PromiseOrValue::Value(amount);
        }
        match self.fund(amount.0, &msg) {
            Ok(()) => PromiseOrValue::Value(U128(0)),
            Err(reason) => {
                emit("funding_refused", &json!({ "reason": reason }).to_string());
                PromiseOrValue::Value(amount)
            }
        }
    }

    // ---- registration ----------------------------------------------------------------

    /// Register a signed mandate (A1P-01). The attached deposit must cover the mandate's
    /// worst-case storage and two token registrations; any surplus is returned at once.
    /// A refusal returns normally and gives the whole deposit back.
    #[payable]
    pub fn register_mandate(&mut self, signed_mandate: String) -> String {
        let registrant = env::predecessor_account_id();
        let deposit = env::attached_deposit().as_yoctonear();
        match self.try_register(&signed_mandate, &registrant, deposit) {
            Ok((hash, needed)) => {
                if deposit > needed {
                    Promise::new(registrant)
                        .transfer(NearToken::from_yoctonear(deposit.saturating_sub(needed)))
                        .detach();
                }
                emit("registered", &json!({ "mandate_hash": hash }).to_string());
                json!({ "registered": true, "mandate_hash": hash }).to_string()
            }
            Err(reason) => {
                if deposit > 0 {
                    Promise::new(registrant)
                        .transfer(NearToken::from_yoctonear(deposit))
                        .detach();
                }
                emit(
                    "registration_refused",
                    &json!({ "reason": reason }).to_string(),
                );
                json!({ "registered": false, "reason": reason }).to_string()
            }
        }
    }

    /// Stop the gate for good (A1C-03). Only the guardian; it cannot move funds, change
    /// rules or undo the stop. Refunds keep working.
    pub fn stop(&mut self) -> String {
        let is_guardian = self.config.guardian.as_ref() == Some(&env::predecessor_account_id());
        if !is_guardian {
            return refusal("not_guardian");
        }
        if !self.stopped {
            self.stopped = true;
            emit("stopped", &json!({}).to_string());
        }
        json!({ "stopped": true }).to_string()
    }

    // ---- purchase --------------------------------------------------------------------

    /// Ask the gate to pay for `order` (canonical `sampan.order.v1`). Returns the decision
    /// as JSON; a refusal is a normal return, never a panic.
    pub fn purchase(&mut self, order: String) -> String {
        if order.len() > MAX_DOC_BYTES {
            return refusal("order_invalid");
        }
        let Ok((order, order_hash)) = parse_order(order.as_bytes()) else {
            return refusal("order_invalid");
        };
        if self.stopped {
            return refusal("stopped");
        }
        self.decide(
            order,
            order_hash,
            Authority::Caller(env::predecessor_account_id()),
        )
        .json
    }

    #[private]
    pub fn on_payout(
        &mut self,
        order_id: String,
        mandate_hash: String,
        amount: U128,
        account: AccountId,
        registering: bool,
    ) -> bool {
        // #[private] already rejects other callers in the wasm entry point; this second
        // check returns normally so it also holds in direct (unit test) calls.
        if env::predecessor_account_id() != env::current_account_id() {
            return false;
        }
        let ok = Self::transfer_succeeded();
        self.settle(&mandate_hash, &account, registering, ok);
        // On failure, restore exactly what `decide` took (Q18). The order ID stays used so
        // its receipt is never overwritten; the agent retries with a new order.
        let status = if ok {
            Payout::Done
        } else if self.restore(&mandate_hash, amount.0, Bucket::Spent) {
            // Direct checkout: the buyer's money is owed to refund_to now, and the single
            // purchase may be tried again with a new payment (A1R-04).
            let agentless = self
                .mandates
                .get(&mandate_hash)
                .is_some_and(|m| m.agent.is_none());
            if agentless {
                if let Some(m) = self.mandates.get_mut(&mandate_hash) {
                    m.released = false;
                }
                self.escrow_to_refund_due(&mandate_hash, amount.0);
            }
            Payout::Failed
        } else {
            Payout::Pending // restore impossible; flagged by the "internal" event
        };
        if let Some(r) = self
            .receipts
            .get_mut(&receipt_key(&mandate_hash, &order_id))
        {
            r.payout = status;
        }
        emit(
            "payout",
            &json!({ "mandate_hash": mandate_hash, "order_id": order_id, "status": payout_str(status) }).to_string(),
        );
        self.try_close(&mandate_hash);
        ok
    }

    // ---- refund ----------------------------------------------------------------------

    /// Anyone may pay out what is owed to the buyer, only to `refund_to`: refund due at any
    /// time (A1P-02, A1P-07), and the unspent escrow at or after expiry.
    pub fn refund(&mut self, mandate_hash: String) -> String {
        if !is_hex32(&mandate_hash) {
            return refusal("invalid_mandate_hash");
        }
        let now = env::block_timestamp();
        let Some(m) = self.mandates.get(&mandate_hash) else {
            return refusal("unknown_mandate");
        };
        let expired = now >= m.expiry_ns;
        let from_escrow = if expired { m.escrow } else { 0 };
        let from_due = m.refund_due;
        let Some(amount) = from_escrow.checked_add(from_due) else {
            return refusal("internal");
        };
        if amount == 0 {
            if !expired && m.escrow > 0 {
                return refusal("not_expired");
            }
            if self.try_close(&mandate_hash) {
                return json!({ "refund": "closed", "amount": "0" }).to_string();
            }
            return refusal("nothing_to_refund");
        }
        let refund_to = m.refund_to.clone();
        let register = self.should_register(m, &refund_to);
        let Some(pending) = m.pending.checked_add(1) else {
            return refusal("internal");
        };
        if gas_left() < gas_needed(register) {
            return refusal("insufficient_gas");
        }
        let (Some(refunded), Some(total), Some(total_due)) = (
            m.refunded.checked_add(amount),
            self.total_escrow.checked_sub(from_escrow),
            self.total_refund_due.checked_sub(from_due),
        ) else {
            return refusal("internal");
        };
        // State first, then the promise (docs/SECURITY.md 3.1).
        if let Some(m) = self.mandates.get_mut(&mandate_hash) {
            m.escrow = m.escrow.saturating_sub(from_escrow);
            m.refund_due = 0;
            m.refunded = refunded;
            m.pending = pending;
            if register {
                m.registrations_in_use = m.registrations_in_use.saturating_add(1);
            }
        }
        self.total_escrow = total;
        self.total_refund_due = total_due;
        emit(
            "refund",
            &json!({ "mandate_hash": mandate_hash, "amount": amount.to_string(), "status": "pending" })
                .to_string(),
        );
        self.transfer(&refund_to, amount, register)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_CALLBACK)
                    .on_refund(mandate_hash.clone(), U128(amount), refund_to, register),
            )
            .detach();
        json!({ "refund": "pending", "amount": amount.to_string() }).to_string()
    }

    #[private]
    pub fn on_refund(
        &mut self,
        mandate_hash: String,
        amount: U128,
        account: AccountId,
        registering: bool,
    ) -> bool {
        if env::predecessor_account_id() != env::current_account_id() {
            return false;
        }
        let ok = Self::transfer_succeeded();
        self.settle(&mandate_hash, &account, registering, ok);
        if !ok {
            self.restore(&mandate_hash, amount.0, Bucket::Refunded);
        }
        emit(
            "refund",
            &json!({ "mandate_hash": mandate_hash, "amount": amount.0.to_string(), "status": if ok { "done" } else { "failed" } })
                .to_string(),
        );
        self.try_close(&mandate_hash);
        ok
    }

    // ---- views -----------------------------------------------------------------------

    pub fn version(&self) -> String {
        VERSION.to_string()
    }

    pub fn get_config(&self) -> Config {
        self.config.clone()
    }

    pub fn get_mandate(&self, mandate_hash: String) -> Option<MandateView> {
        self.mandates.get(&mandate_hash).map(|m| MandateView {
            agent: m.agent.clone(),
            payee: m.payee.clone(),
            refund_to: m.refund_to.clone(),
            max_amount: U128(m.max_amount),
            expiry_ns: m.expiry_ns.to_string(),
            funded: U128(m.funded),
            spent: U128(m.spent),
            escrow: U128(m.escrow),
            refunded: U128(m.refunded),
            refund_due: U128(m.refund_due),
            orders: m.orders,
        })
    }

    /// Receipts are per mandate: an order ID is single use within its mandate (R4), so
    /// another mandate cannot claim it first (M3-CR2).
    pub fn get_receipt(&self, mandate_hash: String, order_id: String) -> Option<ReceiptView> {
        self.receipts
            .get(&receipt_key(&mandate_hash, &order_id))
            .map(|r| ReceiptView {
                mandate_hash: r.mandate_hash.clone(),
                core_hash: r.core_hash.clone(),
                decision: if r.release { "release" } else { "refuse" }.to_string(),
                amount: U128(r.amount),
                payout: r.payout,
                block_height: r.block_height.to_string(),
            })
    }

    pub fn get_totals(&self) -> Value {
        json!({
            "total_escrow": self.total_escrow.to_string(),
            "total_refund_due": self.total_refund_due.to_string(),
            "stopped": self.stopped,
            "mandates": self.open_mandates,
            "live_mandates": self.live_expiries.iter().filter(|&&e| e > env::block_timestamp()).count(),
            "registrations": self.registrations,
        })
    }
}

fn payout_str(p: Payout) -> &'static str {
    match p {
        Payout::None => "none",
        Payout::Pending => "pending",
        Payout::Done => "done",
        Payout::Failed => "failed",
    }
}

impl Gate {
    /// Verify a registration; returns the mandate hash and the deposit it needs.
    fn try_register(
        &mut self,
        text: &str,
        registrant: &AccountId,
        deposit: u128,
    ) -> Result<(String, u128), &'static str> {
        if self.stopped {
            return Err("stopped");
        }
        let vm = verify_signed_mandate(text.as_bytes()).map_err(|_| "mandate_invalid")?;
        let m = vm.mandate;
        let hash = vm.mandate_hash;
        if m.network != self.config.network {
            return Err("wrong_network");
        }
        if m.gate.as_str() != env::current_account_id().as_str() {
            return Err("wrong_gate");
        }
        if m.asset.as_str() != self.config.token.as_str() {
            return Err("wrong_asset");
        }
        let now = env::block_timestamp();
        if now >= m.expiry_ns {
            return Err("expired");
        }
        if m.expiry_ns.saturating_sub(now) > self.config.max_lifetime_ns {
            return Err("lifetime_too_long");
        }
        if self.mandates.contains_key(&hash) {
            return Err("already_registered");
        }
        let key = nonce_key(&m.buyer, &m.nonce);
        if self.nonces.contains(&key) {
            return Err("nonce_used");
        }
        // Only mandates that have not expired count against the cap (A1R-01).
        self.live_expiries.retain(|&e| e > now);
        if self.live_expiries.len()
            >= usize::try_from(self.config.max_mandates).unwrap_or(usize::MAX)
        {
            return Err("mandate_cap");
        }
        let needed = self.config.reservation_per_mandate();
        if deposit < needed {
            return Err("deposit_too_small");
        }
        let parse = |s: &str| s.parse::<AccountId>().map_err(|_| "mandate_invalid");
        let buyer_account = match &m.buyer {
            Buyer::Near { public_key } => Some(parse(&hex_lower(public_key))?),
            Buyer::Evm { .. } => None,
        };
        let record = MandateRecord {
            buyer_account,
            agent: m.agent.as_deref().map(parse).transpose()?,
            asset: parse(&m.asset)?,
            payee: parse(&m.payee)?,
            refund_to: parse(&m.refund_to)?,
            items: m.items.clone(),
            max_amount: m.max_amount,
            expiry_ns: m.expiry_ns,
            funded: 0,
            spent: 0,
            escrow: 0,
            refunded: 0,
            refund_due: 0,
            orders: 0,
            pending: 0,
            registrations_in_use: 0,
            nonce_key: key.clone(),
            registrant: registrant.clone(),
            deposit: needed,
            kept_bytes: 0,
            released: false,
        };
        self.nonces.insert(key);
        self.live_expiries.push(m.expiry_ns);
        self.open_mandates = self.open_mandates.saturating_add(1);
        self.mandates.insert(hash.clone(), record);
        Ok((hash, needed))
    }

    /// Credit a payment. `Err` (payment returned to the sender) only when the message is
    /// unreadable or names no registered mandate; otherwise the payment is kept for the
    /// buyer, in escrow or as refund due (A1P-02).
    fn fund(&mut self, amount: u128, msg: &str) -> Result<(), &'static str> {
        if amount == 0 {
            return Err("zero_amount");
        }
        if msg.len() > MAX_MSG_BYTES {
            return Err("msg_too_large");
        }
        let fm: FundingMsg = near_sdk::serde_json::from_str(msg).map_err(|_| "msg_invalid")?;
        let hash = match (fm.signed_mandate, fm.mandate_hash) {
            (Some(text), None) => {
                verify_signed_mandate(text.as_bytes())
                    .map_err(|_| "mandate_invalid")?
                    .mandate_hash
            }
            (None, Some(h)) if is_hex32(&h) => h,
            _ => return Err("msg_invalid"),
        };
        let Some(m) = self.mandates.get(&hash) else {
            return Err("unknown_mandate");
        };
        // From here on the payment is the buyer's: never handed back to the sender.
        let now = env::block_timestamp();
        let used = m.spent.saturating_add(m.escrow);
        let to_escrow = if self.stopped || now >= m.expiry_ns {
            0
        } else {
            let room = m
                .max_amount
                .min(self.config.max_escrow_per_mandate.0)
                .saturating_sub(used)
                .min(
                    self.config
                        .max_total_escrow
                        .0
                        .saturating_sub(self.total_escrow),
                );
            amount.min(room)
        };
        let to_due = amount.saturating_sub(to_escrow);
        let agentless = m.agent.is_none();
        // Checked before any write (A1R-05); an overflow hands the payment back.
        let (Some(funded), Some(escrow), Some(due), Some(total), Some(total_due)) = (
            m.funded.checked_add(amount),
            m.escrow.checked_add(to_escrow),
            m.refund_due.checked_add(to_due),
            self.total_escrow.checked_add(to_escrow),
            self.total_refund_due.checked_add(to_due),
        ) else {
            return Err("internal");
        };
        if let Some(m) = self.mandates.get_mut(&hash) {
            m.funded = funded;
            m.escrow = escrow;
            m.refund_due = due;
        }
        self.total_escrow = total;
        self.total_refund_due = total_due;
        emit(
            "funded",
            &json!({ "mandate_hash": hash, "amount": amount.to_string(), "escrow": to_escrow.to_string(), "refund_due": to_due.to_string() })
                .to_string(),
        );
        let Some(text) = fm.order else {
            return Ok(());
        };
        if !agentless {
            // An agent mandate's orders come from its agent; the payment stays in escrow.
            emit(
                "order_ignored",
                &json!({ "mandate_hash": hash, "reason": "agent_mandate" }).to_string(),
            );
            return Ok(());
        }
        // Direct checkout: one purchase at exactly the signed price (A1C-04). Whatever is
        // not paid out ends as refund due for the buyer, never back with the sender.
        let released = match parse_order(text.as_bytes()) {
            Ok((order, order_hash)) if order.mandate_hash == hash && to_escrow > 0 => {
                let d = self.decide(order, order_hash, Authority::BuyerSignature);
                d.anchored && d.json.contains("\"decision\":\"release\"")
            }
            _ => {
                emit(
                    "order_ignored",
                    &json!({ "mandate_hash": hash, "reason": "order_invalid" }).to_string(),
                );
                false
            }
        };
        // After the single purchase, whatever is left is owed to the buyer now. If this
        // payment's order was not paid, this payment becomes refund due; money already in
        // escrow stays for the buyer's own purchase or the refund after expiry.
        let cap = if released { u128::MAX } else { to_escrow };
        self.escrow_to_refund_due(&hash, cap);
        Ok(())
    }

    /// Move up to `cap` of a mandate's escrow into refund due (owed to `refund_to` now).
    fn escrow_to_refund_due(&mut self, hash: &str, cap: u128) {
        if let Some(m) = self.mandates.get_mut(hash) {
            let moved = m.escrow.min(cap);
            m.escrow = m.escrow.saturating_sub(moved);
            m.refund_due = m.refund_due.saturating_add(moved);
            self.total_escrow = self.total_escrow.saturating_sub(moved);
            self.total_refund_due = self.total_refund_due.saturating_add(moved);
        }
    }

    /// Run R1-R9 for an order and anchor the decision. Unauthorised calls are refused
    /// before any state is written.
    fn decide(&mut self, order: Order, order_hash: String, authority: Authority) -> Decision {
        let Some(m) = self.mandates.get(&order.mandate_hash) else {
            return unanchored(refusal("unknown_mandate"));
        };
        let caller_ok = match &authority {
            Authority::Caller(c) => match &m.agent {
                Some(agent) => c == agent,
                None => m.buyer_account.as_ref() == Some(c),
            },
            Authority::BuyerSignature => m.agent.is_none(),
        };
        if !caller_ok {
            return unanchored(refusal("not_authorised"));
        }
        let order_id = hex_lower(&order.order_id);
        let mh = order.mandate_hash.clone();
        let refuse = |reason| unanchored(refusal_for(reason, &mh, &order_id));
        let key = receipt_key(&order.mandate_hash, &order_id);
        if self.receipts.contains_key(&key) {
            return refuse("order_used");
        }
        if m.orders >= self.config.max_orders_per_mandate {
            return refuse("order_cap");
        }
        if m.escrow == 0 {
            return refuse("no_escrow");
        }
        // An unsigned order inside a payment may only buy once, at exactly the signed price
        // (A1C-04, FORMATS 3). The buyer's own account calling `purchase` is authenticated
        // and may buy within the budget like an agent.
        if matches!(authority, Authority::BuyerSignature) {
            if m.released {
                return refuse("already_paid");
            }
            if order.amount != m.max_amount {
                return refuse("not_exact_price");
            }
        }
        let eval = evaluate(
            &RuleMandate {
                asset: m.asset.as_str(),
                payee: m.payee.as_str(),
                items: &m.items,
                max_amount: m.max_amount,
                expiry_ns: m.expiry_ns,
                spent: m.spent,
                escrow: m.escrow,
            },
            &order,
            env::block_timestamp(),
            true,
            true,
        );
        let release = eval.release();
        // An unsigned order inside a payment is anchored only when it is released: anyone
        // can send a payment, so its refusals must not use the mandate's order slots or the
        // registrant's deposit (A1R-02). The payment then becomes refund due.
        if !release && matches!(authority, Authority::BuyerSignature) {
            return refuse("order_refused");
        }
        let payee = m.payee.clone();
        let register = release && self.should_register(m, &payee);
        let block_height = env::block_height();
        let Some((core, core_hash)) = self.receipt_core(&order, &order_hash, &eval, block_height)
        else {
            return refuse("internal");
        };
        // Compute the new balances before writing anything.
        let (spent, escrow, total) = if release {
            match (
                m.spent.checked_add(order.amount),
                m.escrow.checked_sub(order.amount),
                self.total_escrow.checked_sub(order.amount),
            ) {
                (Some(s), Some(e), Some(t)) => (s, e, t),
                _ => return refuse("internal"),
            }
        } else {
            (m.spent, m.escrow, self.total_escrow)
        };
        let (Some(orders), Some(pending)) = (
            m.orders.checked_add(1),
            m.pending.checked_add(u32::from(release)),
        ) else {
            return refuse("internal");
        };
        // Checked after the expensive work above, right before writing (M3-CR5):
        // GAS_MARGIN covers the writes, the event and creating the promises.
        if release && gas_left() < gas_needed(register) {
            return refuse("insufficient_gas");
        }
        let receipt = ReceiptRecord {
            mandate_hash: order.mandate_hash.clone(),
            core_hash: core_hash.clone(),
            release,
            amount: order.amount,
            payout: if release {
                Payout::Pending
            } else {
                Payout::None
            },
            block_height,
        };
        let receipt_bytes = entry_bytes(
            key.len(),
            near_sdk::borsh::to_vec(&receipt)
                .map(|v| v.len())
                .unwrap_or(1024),
        );
        // State first, then the promise.
        if let Some(m) = self.mandates.get_mut(&order.mandate_hash) {
            m.spent = spent;
            m.escrow = escrow;
            m.orders = orders;
            m.pending = pending;
            if register {
                m.registrations_in_use = m.registrations_in_use.saturating_add(1);
            }
            if release && m.agent.is_none() {
                m.released = true;
            }
            // The receipt stays after the mandate closes: its storage is charged to the
            // mandate's deposit (A1C-02).
            m.kept_bytes = m.kept_bytes.saturating_add(receipt_bytes);
        }
        self.total_escrow = total;
        self.receipts.insert(key.clone(), receipt);
        // The core is canonical JSON produced and re-parsed above, so it embeds safely.
        emit(
            "receipt",
            &format!(
                "{{\"core\":{core},\"core_hash\":\"{core_hash}\",\"order_id\":\"{order_id}\"}}"
            ),
        );
        if release {
            self.transfer(&payee, order.amount, register)
                .then(
                    Self::ext(env::current_account_id())
                        .with_static_gas(GAS_CALLBACK)
                        .on_payout(
                            order_id.clone(),
                            order.mandate_hash.clone(),
                            U128(order.amount),
                            payee,
                            register,
                        ),
                )
                .detach();
        }
        Decision {
            json: json!({
                "decision": if release { "release" } else { "refuse" },
                "anchored": true,
                "order_id": order_id,
                "core_hash": core_hash,
            })
            .to_string(),
            anchored: true,
        }
    }

    /// Build the canonical receipt core and check it parses as `sampan.receipt.v1`.
    fn receipt_core(
        &self,
        order: &Order,
        order_hash: &str,
        eval: &rules::Evaluation,
        block_height: u64,
    ) -> Option<(String, String)> {
        let rules: Vec<Value> = RULE_IDS
            .iter()
            .zip(eval.pass)
            .map(|(id, pass)| json!({ "id": id, "pass": pass }))
            .collect();
        let core = json!({
            "v": "sampan.receipt.v1",
            "network": self.config.network,
            "gate": env::current_account_id().as_str(),
            "mandate_hash": order.mandate_hash,
            "order_hash": order_hash,
            "observed": { "amount": eval.observed_amount.to_string(), "asset": self.config.token.as_str() },
            "rules": rules,
            "decision": if eval.release() { "release" } else { "refuse" },
            "block_height": block_height.to_string(),
        });
        let text = canonicalize(&core).ok()?;
        let (_, hash) = parse_receipt_core(text.as_bytes()).ok()?;
        Some((text, hash))
    }

    /// Whether the gate should pay the token registration for `account` (Q17): at most
    /// twice per mandate, payee and `refund_to` (covered by its deposit, A1P-04, A1C-05),
    /// and never for an account the gate has registered before.
    fn should_register(&self, m: &MandateRecord, account: &AccountId) -> bool {
        if m.registrations_in_use >= 2 || self.registered.contains(account) {
            return false;
        }
        // Defence in depth: only pay from balance above the gate's own storage.
        free_balance() > self.config.registration_deposit.0.saturating_mul(4)
    }

    /// Remove a mandate that has expired, holds no escrow and has nothing in flight.
    /// Its receipts stay; an expired mandate can never be funded again, so removing the
    /// record and nonce does not allow a replay (M3-02).
    fn try_close(&mut self, mandate_hash: &str) -> bool {
        let closable = self.mandates.get(mandate_hash).is_some_and(|m| {
            env::block_timestamp() >= m.expiry_ns
                && m.escrow == 0
                && m.refund_due == 0
                && m.pending == 0
        });
        if !closable {
            return false;
        }
        if let Some(m) = self.mandates.remove(mandate_hash) {
            self.nonces.remove(&m.nonce_key);
            // Return the deposit minus what the mandate leaves behind: its receipts and
            // the token registrations the gate paid for it (A1C-02).
            let kept = env::storage_byte_cost()
                .as_yoctonear()
                .saturating_mul(u128::from(m.kept_bytes))
                .saturating_add(
                    self.config
                        .registration_deposit
                        .0
                        .saturating_mul(u128::from(m.registrations_in_use)),
                );
            let back = m.deposit.saturating_sub(kept);
            if back > 0 {
                Promise::new(m.registrant.clone())
                    .transfer(NearToken::from_yoctonear(back))
                    .detach();
            }
        }
        self.open_mandates = self.open_mandates.saturating_sub(1);
        // A closed mandate has expired: drop expired entries so none outlives its mandate.
        let now = env::block_timestamp();
        self.live_expiries.retain(|&e| e > now);
        emit(
            "closed",
            &json!({ "mandate_hash": mandate_hash }).to_string(),
        );
        true
    }

    /// One batch on the token: optional `storage_deposit` for `account`, then
    /// `ft_transfer`. A batch is atomic: if registration fails, nothing is transferred.
    fn transfer(&self, account: &AccountId, amount: u128, register: bool) -> Promise {
        let mut p = Promise::new(self.config.token.clone());
        if register {
            p = p.function_call(
                "storage_deposit",
                json!({ "account_id": account, "registration_only": true })
                    .to_string()
                    .into_bytes(),
                NearToken::from_yoctonear(self.config.registration_deposit.0),
                GAS_STORAGE_DEPOSIT,
            );
        }
        p.function_call(
            "ft_transfer",
            json!({ "receiver_id": account, "amount": amount.to_string() })
                .to_string()
                .into_bytes(),
            NearToken::from_yoctonear(1),
            GAS_FT_TRANSFER,
        )
    }

    /// Undo a failed transfer: a payout goes back into escrow, a refund back into refund
    /// due (still owed to `refund_to` only). Returns false (and emits an "internal" event)
    /// if that is impossible (M3-CR7).
    fn restore(&mut self, mandate_hash: &str, amount: u128, from: Bucket) -> bool {
        let done = match self.mandates.get_mut(mandate_hash) {
            Some(m) => match from {
                Bucket::Spent => match (
                    m.spent.checked_sub(amount),
                    m.escrow.checked_add(amount),
                    self.total_escrow.checked_add(amount),
                ) {
                    (Some(left), Some(escrow), Some(total)) => {
                        m.spent = left;
                        m.escrow = escrow;
                        self.total_escrow = total;
                        true
                    }
                    _ => false,
                },
                Bucket::Refunded => match (
                    m.refunded.checked_sub(amount),
                    m.refund_due.checked_add(amount),
                    self.total_refund_due.checked_add(amount),
                ) {
                    (Some(left), Some(due), Some(total)) => {
                        m.refunded = left;
                        m.refund_due = due;
                        self.total_refund_due = total;
                        true
                    }
                    _ => false,
                },
            },
            None => false,
        };
        if !done {
            emit(
                "internal",
                &json!({ "mandate_hash": mandate_hash, "reason": "restore_failed" }).to_string(),
            );
        }
        done
    }

    /// A long result is still a success: only `Failed` means the tokens did not move (M3-08).
    fn transfer_succeeded() -> bool {
        env::promise_results_count() == 1
            && !matches!(
                env::promise_result_checked(0, MAX_RESULT_BYTES),
                Err(PromiseError::Failed)
            )
    }

    /// Book the callback: one transfer fewer in flight, and the registration outcome.
    fn settle(&mut self, mandate_hash: &str, account: &AccountId, registering: bool, ok: bool) {
        let registered_entry = entry_bytes(account.as_str().len(), 0);
        if let Some(m) = self.mandates.get_mut(mandate_hash) {
            m.pending = m.pending.saturating_sub(1);
            if registering && !ok {
                m.registrations_in_use = m.registrations_in_use.saturating_sub(1);
                // the deposit came back
            }
            if registering && ok {
                m.kept_bytes = m.kept_bytes.saturating_add(registered_entry); // the gate's record of it
            }
        }
        if registering && ok {
            self.registered.insert(account.clone());
            self.registrations = self.registrations.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests;
