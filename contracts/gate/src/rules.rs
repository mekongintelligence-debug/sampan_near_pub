//! Rules R1-R9 (docs/FORMATS.md section 9) as a pure function, so they can be unit,
//! property and mutation tested without a chain. The contract supplies the stored
//! mandate, the parsed order and the block time; nothing here touches state.
use sampan_formats::Order;

/// The fields of a funded mandate that the rules read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMandate<'a> {
    pub asset: &'a str,
    pub payee: &'a str,
    pub items: &'a [String],
    pub max_amount: u128,
    pub expiry_ns: u64,
    pub spent: u128,
    pub escrow: u128,
}

/// Outcome of the rules for one order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// R1..R9 in order.
    pub pass: [bool; 9],
    /// What the gate itself holds for this order: the order amount when the escrow
    /// covers it, otherwise the whole (smaller) escrow. Zero only when escrow is empty.
    pub observed_amount: u128,
}

impl Evaluation {
    pub fn release(&self) -> bool {
        self.pass.iter().all(|p| *p)
    }
}

/// R1 (signature) and R2 (network, gate) are checked when the mandate is funded: a
/// mandate that fails them is never stored, so a stored mandate passes both. R4 (order
/// ID unused) and R5 (caller) are checked by the caller of this function before any
/// state is written and passed in.
pub fn evaluate(
    m: &RuleMandate<'_>,
    order: &Order,
    now_ns: u64,
    order_unused: bool,
    caller_ok: bool,
) -> Evaluation {
    let r3 = now_ns < m.expiry_ns;
    let r6 = order.asset == m.asset;
    let remaining_budget = m.max_amount.saturating_sub(m.spent);
    let r7 = order.amount <= remaining_budget && order.amount <= m.escrow;
    let r8 = order.payee == m.payee;
    let r9 = m.items.contains(&order.item);
    let observed_amount = if order.amount <= m.escrow {
        order.amount
    } else {
        m.escrow
    };
    Evaluation {
        pass: [true, true, r3, order_unused, caller_ok, r6, r7, r8, r9],
        observed_amount,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items() -> Vec<String> {
        vec!["report-001".to_string(), "report-002".to_string()]
    }

    fn mandate(items: &[String]) -> RuleMandate<'_> {
        RuleMandate {
            asset: "usdc.testnet",
            payee: "shop.testnet",
            items,
            max_amount: 100,
            expiry_ns: 1_000,
            spent: 0,
            escrow: 100,
        }
    }

    fn order(amount: u128) -> Order {
        Order {
            order_id: [7; 32],
            mandate_hash: "00".repeat(32),
            item: "report-001".to_string(),
            amount,
            asset: "usdc.testnet".to_string(),
            payee: "shop.testnet".to_string(),
        }
    }

    #[test]
    fn all_pass_releases() {
        let it = items();
        let e = evaluate(&mandate(&it), &order(40), 999, true, true);
        assert_eq!(e.pass, [true; 9]);
        assert!(e.release());
        assert_eq!(e.observed_amount, 40);
    }

    #[test]
    fn r3_exact_expiry_nanosecond_is_expired() {
        let it = items();
        assert!(!evaluate(&mandate(&it), &order(1), 1_000, true, true).pass[2]);
        assert!(evaluate(&mandate(&it), &order(1), 999, true, true).pass[2]);
    }

    #[test]
    fn r4_r5_are_passed_through() {
        let it = items();
        let e = evaluate(&mandate(&it), &order(1), 0, false, true);
        assert!(!e.pass[3] && !e.release());
        let e = evaluate(&mandate(&it), &order(1), 0, true, false);
        assert!(!e.pass[4] && !e.release());
    }

    #[test]
    fn r6_wrong_asset() {
        let it = items();
        let mut o = order(1);
        o.asset = "fake-usdc.testnet".to_string();
        assert!(!evaluate(&mandate(&it), &o, 0, true, true).pass[5]);
    }

    #[test]
    fn r7_budget_boundaries() {
        let it = items();
        let mut m = mandate(&it);
        m.spent = 60;
        m.escrow = 40;
        assert!(
            evaluate(&m, &order(40), 0, true, true).pass[6],
            "exactly the remaining budget"
        );
        assert!(
            !evaluate(&m, &order(41), 0, true, true).pass[6],
            "one above the remaining budget"
        );
    }

    #[test]
    fn r7_escrow_smaller_than_budget() {
        let it = items();
        let mut m = mandate(&it);
        m.escrow = 10; // funded less than the budget
        let e = evaluate(&m, &order(11), 0, true, true);
        assert!(!e.pass[6]);
        assert_eq!(e.observed_amount, 10, "observed is what the gate holds");
        assert!(evaluate(&m, &order(10), 0, true, true).pass[6]);
    }

    #[test]
    fn r7_spent_above_max_never_underflows() {
        let it = items();
        let mut m = mandate(&it);
        m.spent = u128::MAX;
        assert!(!evaluate(&m, &order(1), 0, true, true).pass[6]);
    }

    #[test]
    fn r8_wrong_payee() {
        let it = items();
        let mut o = order(1);
        o.payee = "attacker.testnet".to_string();
        assert!(!evaluate(&mandate(&it), &o, 0, true, true).pass[7]);
    }

    #[test]
    fn r9_item_not_in_mandate() {
        let it = items();
        let mut o = order(1);
        o.item = "report-003".to_string();
        assert!(!evaluate(&mandate(&it), &o, 0, true, true).pass[8]);
        o.item = "report-002".to_string();
        assert!(evaluate(&mandate(&it), &o, 0, true, true).pass[8]);
    }

    #[test]
    fn each_single_failure_refuses() {
        let it = items();
        for i in 2..9 {
            let mut m = mandate(&it);
            let mut o = order(10);
            let (mut now, mut unused, mut caller) = (0, true, true);
            match i {
                2 => now = 1_000,
                3 => unused = false,
                4 => caller = false,
                5 => o.asset = "x.testnet".to_string(),
                6 => m.escrow = 9,
                7 => o.payee = "x.testnet".to_string(),
                _ => o.item = "x".to_string(),
            }
            let e = evaluate(&m, &o, now, unused, caller);
            assert!(!e.release(), "rule index {i}");
            assert_eq!(
                e.pass.iter().filter(|p| !**p).count(),
                1,
                "only rule index {i} fails"
            );
        }
    }
}
