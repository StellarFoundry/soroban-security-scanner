// SS-025 positive: caller-controlled bytes are persisted without a length bound.
#![no_std]
use soroban_sdk::{contractimpl, Env, String};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_name(env: Env, name: String) {
        env.storage().persistent().set(&DataKey::Name, &name);
    }
}
