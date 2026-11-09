// Must-trigger recall fixture (SS-008)
// Rationale: True positive because `credit_account` performs raw `+` and `*`
// arithmetic on caller-controlled balance values in a contract entry point
// without `checked_add`/`checked_mul`.

#![no_std]
use soroban_sdk::{contractimpl, Address, Env};

pub struct LedgerPool;

#[contractimpl]
impl LedgerPool {
    pub fn credit_account(env: Env, user: Address, principal: i128, rate: i128) -> i128 {
        user.require_auth();
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0);
        current + (principal * rate)
    }
}
