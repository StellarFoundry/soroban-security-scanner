#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

const TTL_THRESHOLD: u32 = 1_000;
const TTL_EXTEND_TO: u32 = 10_000;

#[contract]
pub struct Store;

#[contractimpl]
impl Store {
    pub fn write(env: Env, user: Address, val: u64) {
        user.require_auth();
        let key = symbol_short!("VAL");
        env.storage().persistent().set(&key, &val);
        env.storage()
            .persistent()
            .extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND_TO);
    }
}
