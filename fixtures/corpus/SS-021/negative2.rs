#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn set_nonce(env: Env, user: Address, nonce: u64) {
        user.require_auth();
        env.storage()
            .temporary()
            .set(&symbol_short!("nonce"), &nonce);
    }
}
