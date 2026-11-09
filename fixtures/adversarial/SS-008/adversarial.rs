// Adversarial fixture (SS-008)
// Technique: Parenthesized nested binary arithmetic with unusual whitespace.
// Expected: trigger (raw `+` and `-` operators in an entry point are flagged).

#![no_std]
use soroban_sdk::{contractimpl, Address, Env};

pub struct Pool;

#[contractimpl]
impl Pool {
    pub fn adjust(env: Env, caller: Address, delta: i128, fee: i128) -> i128 {
        caller.require_auth();
        let base: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Base)
            .unwrap_or(0);
        ((base + delta) - fee)
    }
}
