// SS-021 negative: an ephemeral key that is safe to discard.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Settings;

#[contractimpl]
impl Settings {
    pub fn cache(env: Env, value: u32) {
        env.storage().temporary().set(&DataKey::Session, &value);
    }
}
