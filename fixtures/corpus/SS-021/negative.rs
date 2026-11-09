#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn record_balance(env: Env, admin: Address, balance: i128) {
        admin.require_auth();
        let key = symbol_short!("balance");
        env.storage().persistent().set(&key, &balance);
        env.storage().persistent().extend_ttl(&key, 100, 1000);
    }
}
