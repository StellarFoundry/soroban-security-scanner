// Must-trigger recall fixture (SS-003)
// Rationale: True positive because `sum_all_values` iterates over all persistent
// storage values (`env.storage().persistent().values()`) with no bound, which
// will exceed Soroban CPU/read ledger limits as storage grows.

#![no_std]
use soroban_sdk::{contractimpl, Env};

pub struct Accounting;

#[contractimpl]
impl Accounting {
    pub fn sum_all_values(env: Env) -> u32 {
        let mut total = 0u32;
        for _val in env.storage().persistent().values() {
            total += 1;
        }
        total
    }
}
