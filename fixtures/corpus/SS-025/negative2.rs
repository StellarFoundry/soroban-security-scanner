#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, BytesN, Env};

#[contract]
pub struct Registry;

#[contractimpl]
impl Registry {
    pub fn set_digest(env: Env, user: Address, digest: BytesN<32>) {
        user.require_auth();
        let key = symbol_short!("DIGEST");
        env.storage().persistent().set(&key, &digest);
        env.storage().persistent().extend_ttl(&key, 100, 1000);
    }
}
