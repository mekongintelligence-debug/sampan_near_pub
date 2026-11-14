//! THROWAWAY spike gate for Gate 2 (M1). Proves only that a contract can move tokens it
//! holds when called through an agent's function-call key. Not the real gate (M3).
use near_sdk::json_types::U128;
use near_sdk::{env, near, AccountId, Gas, NearToken, Promise, PromiseOrValue};

#[near(contract_state)]
pub struct Gate {
    token: AccountId,
    agent: AccountId,
}

impl Default for Gate {
    fn default() -> Self {
        env::panic_str("not initialised")
    }
}

#[near]
impl Gate {
    #[init]
    pub fn new(token: AccountId, agent: AccountId) -> Self {
        Self { token, agent }
    }

    /// Callable by the agent only. The gate itself sends the token (attaches 1 yoctoNEAR).
    /// A refusal returns normally with a reason (panic messages are lost as bare traps on this
    /// toolchain, and M3 refusals never panic).
    pub fn purchase(&mut self, payee: AccountId, amount: U128) -> PromiseOrValue<String> {
        if env::predecessor_account_id() != self.agent {
            return PromiseOrValue::Value("refused: only the agent may call purchase".to_string());
        }
        let args = near_sdk::serde_json::json!({ "receiver_id": payee, "amount": amount, "memo": "gate2-spike" });
        PromiseOrValue::Promise(Promise::new(self.token.clone()).function_call(
            "ft_transfer".to_string(),
            args.to_string().into_bytes(),
            NearToken::from_yoctonear(1),
            Gas::from_tgas(15),
        ))
    }

    /// View: who the agent is (also tells scripts the gate is initialised).
    pub fn agent(&self) -> AccountId {
        self.agent.clone()
    }

    /// A second method the agent key must NOT be able to call.
    pub fn admin_note(&mut self) -> String {
        "reached admin_note".to_string()
    }
}
