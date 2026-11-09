// SS-018 negative: widening integer casts to larger widths.
//
// Casting `u32` to `u64` or `u64` to `i128` cannot truncate or wrap.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn scale(_env: Env, from: Address, raw_shares: u32) -> i128 {
        from.require_auth();
        let widened: u64 = raw_shares as u64;
        widened as i128
    }
}
