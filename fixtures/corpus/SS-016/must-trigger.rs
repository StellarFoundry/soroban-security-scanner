// Must-trigger recall fixture (SS-016)
// Rationale: True positive because `record_entries` stores multiple distinct
// keys in `env.storage().instance()`, which loads the entire contract instance
// map on every call and is unsuitable for multi-key or per-item state.

#![no_std]
use soroban_sdk::{contractimpl, Env};

pub struct InstanceAbuse;

#[contractimpl]
impl InstanceAbuse {
    pub fn record_entries(env: Env, first: u64, second: u64) {
        env.storage().instance().set(&DataKey::First, &first);
        env.storage().instance().set(&DataKey::Second, &second);
    }
}
