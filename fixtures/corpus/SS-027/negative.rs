#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct Treasury;

#[contractimpl]
impl Treasury {
    pub fn set_quota(env: Env, caller: Address, quota: i128) {
        caller.require_auth();
        let key = symbol_short!("QUOTA");
        env.storage().persistent().set(&key, &quota);
        env.storage().persistent().extend_ttl(&key, 100, 1000);
    }
}
