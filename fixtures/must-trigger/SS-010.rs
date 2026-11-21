// SS-010 positive: privileged storage change without an event.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Config;

#[contractimpl]
impl Config {
    pub fn set_admin(env: Env, admin: Address) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }
}
