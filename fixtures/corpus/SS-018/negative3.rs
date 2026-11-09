// SS-018 negative: local constant cast and private helper.
//
// Casting a local constant does not depend on caller parameters or contract
// storage, and private helpers are not public contract entry points.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn default_fee(_env: Env) -> u32 {
        let base_bps: u64 = 25;
        base_bps as u32
    }

    fn narrow_helper(value: i128) -> u32 {
        value as u32
    }
}
