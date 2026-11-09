// Adversarial fixture (SS-016)
// Technique: Multiple distinct `instance().set(...)` calls separated by comments and inner scopes.
// Expected: trigger (multiple distinct keys written to instance storage).

#![no_std]
use soroban_sdk::{contractimpl, Env};

pub struct MultiInstance;

#[contractimpl]
impl MultiInstance {
    pub fn write_both(env: Env, x: u32, y: u32) {
        {
            env.storage().instance().set(&DataKey::X, &x);
        }
        // second distinct key in instance storage
        {
            env.storage().instance().set(&DataKey::Y, &y);
        }
    }
}
