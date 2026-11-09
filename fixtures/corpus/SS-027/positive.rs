#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct Treasury;

#[contractimpl]
impl Treasury {
    pub fn set_quota(env: Env, quota: i128) {
        let self_addr = env.current_contract_address();
        self_addr.require_auth();
        let key = symbol_short!("QUOTA");
        env.storage().persistent().set(&key, &quota);
        env.storage().persistent().extend_ttl(&key, 100, 1000);
    }
}
