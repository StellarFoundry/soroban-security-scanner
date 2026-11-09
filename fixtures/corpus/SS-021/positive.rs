#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn record_balance(env: Env, admin: Address, balance: i128) {
        admin.require_auth();
        env.storage()
            .temporary()
            .set(&symbol_short!("balance"), &balance);
    }
}
