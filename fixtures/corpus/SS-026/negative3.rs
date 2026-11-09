#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Store;

#[contractimpl]
impl Store {
    pub fn touch_instance(env: Env, user: Address) {
        user.require_auth();
        env.storage().instance().extend_ttl(100, 2000);
    }
}
