// SS-011 positive: an initializer writes storage without a re-initialization
// guard (no `has`/`get` existence check, no authorization).

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }
}
