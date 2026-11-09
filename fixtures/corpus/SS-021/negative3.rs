#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn cache_quote(env: Env, caller: Address, quote: i128) {
        caller.require_auth();
        env.storage()
            .temporary()
            .set(&symbol_short!("quote"), &quote);
    }
}
