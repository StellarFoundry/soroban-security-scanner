#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, String};

#[contract]
pub struct Registry;

#[contractimpl]
impl Registry {
    pub fn set_metadata(env: Env, user: Address, metadata_uri: String) {
        user.require_auth();
        let key = symbol_short!("URI");
        env.storage().persistent().set(&key, &metadata_uri);
        env.storage().persistent().extend_ttl(&key, 100, 1000);
    }
}
