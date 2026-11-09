// SS-018 negative: fallible integer conversion using `try_into`.
//
// The entry point converts `i128` to `u64` with `try_into` instead of a
// truncating `as` cast.

#![no_std]

use core::convert::TryInto;
use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn deposit(_env: Env, from: Address, amount: i128) -> u64 {
        from.require_auth();
        amount.try_into().unwrap_or(0)
    }
}
