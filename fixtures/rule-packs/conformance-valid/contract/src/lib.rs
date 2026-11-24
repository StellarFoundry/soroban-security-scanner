//! Conformance fixture contract: intentionally contains SS-001 and SS-008.
//! This is synthetic test data, not a production contract.

#![no_std]

use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct ConformanceContract;

#[contractimpl]
impl ConformanceContract {
    /// SS-001: persistent write without an authorization check.
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage()
            .persistent()
            .set(&symbol_short!("ADMIN"), &new_admin);
    }

    /// SS-001 and SS-008: unchecked subtraction plus an unguarded write.
    pub fn withdraw(env: Env, amount: i128) -> i128 {
        let balance: i128 = env
            .storage()
            .persistent()
            .get(&symbol_short!("BAL"))
            .unwrap_or(0);
        let new_balance = balance - amount;
        env.storage()
            .persistent()
            .set(&symbol_short!("BAL"), &new_balance);
        new_balance
    }
}
