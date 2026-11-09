// SS-018 positive: unchecked narrowing integer cast in a contract entry point.
//
// The entry point narrows an `i128` parameter to `u64` with `as`, which
// silently truncates high bits and wraps negative values.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn deposit(_env: Env, from: Address, amount: i128) -> u64 {
        from.require_auth();
        amount as u64
    }
}
