#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct Store;

#[contractimpl]
impl Store {
    pub fn write(env: Env, user: Address, val: u64) {
        user.require_auth();
        let key = symbol_short!("VAL");
        env.storage().persistent().set(&key, &val);
        env.storage().persistent().extend_ttl(&key, 500, 500);
    }
}
