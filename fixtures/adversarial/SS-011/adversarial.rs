// Adversarial fixture (SS-011)
// Technique: `init` entry point with extra type aliases and nested block but no existence guard.
// Expected: trigger (unprotected initializer mutating storage without a re-init check).

#![no_std]
use soroban_sdk::{contractimpl, Address, Env};

pub struct Boot;

#[contractimpl]
impl Boot {
    pub fn init(env: Env, owner: Address) {
        {
            env.storage()
                .instance()
                .set(&DataKey::Owner, &owner);
        }
    }
}
