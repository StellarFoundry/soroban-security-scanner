#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Bytes, Env};

#[contract]
pub struct Registry;

#[contractimpl]
impl Registry {
    pub fn set_blob(env: Env, user: Address, blob: Bytes) {
        user.require_auth();
        if blob.is_empty() || blob.len() > 64 {
            return;
        }
        let key = symbol_short!("BLOB");
        env.storage().persistent().set(&key, &blob);
        env.storage().persistent().extend_ttl(&key, 100, 1000);
    }
}
