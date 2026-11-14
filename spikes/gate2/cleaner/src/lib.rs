//! THROWAWAY testnet maintenance contract (M3): deployed over an old testnet gate whose
//! state layout changed, it removes the given storage keys so the gate can be redeployed
//! and initialised again. Only the account itself may call it. Never used on mainnet.
//! `clean` takes no `self`, so near-sdk does not try to read the old state.
use near_sdk::json_types::Base64VecU8;
use near_sdk::{env, near};

#[near(contract_state)]
#[derive(Default)]
pub struct Cleaner {}

#[near]
impl Cleaner {
    #[private]
    pub fn clean(keys: Vec<Base64VecU8>) -> u32 {
        let mut n = 0u32;
        for k in keys {
            if env::storage_remove(&k.0) {
                n = n.saturating_add(1);
            }
        }
        n
    }
}
