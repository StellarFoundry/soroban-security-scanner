// Adversarial fixture (SS-003)
// Technique: Nested block expression and extra whitespace around `.persistent().keys()`.
// Expected: trigger (unbounded storage key iteration in an entry point).

#![no_std]
use soroban_sdk::{contractimpl, Env};

pub struct Registry;

#[contractimpl]
impl Registry {
    pub fn sweep(env: Env) -> u32 {
        let mut n = 0;
        {
            for _k in env
                .storage( )
                .persistent( )
                .keys( )
            {
                n += 1;
            }
        }
        n
    }
}
