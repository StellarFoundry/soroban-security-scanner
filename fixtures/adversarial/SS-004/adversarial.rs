// Adversarial fixture (SS-004)
// Technique: Chained `.expect(...)` inside a match arm and nested block expression.
// Expected: trigger (panic-prone `.expect` in a public contract entry point).

#![no_std]
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Store;

#[contractimpl]
impl Store {
    pub fn fetch(env: Env, flag: bool) -> u32 {
        match flag {
            true => {
                env.storage()
                    .persistent()
                    .get(&symbol_short!("KEY"))
                    .expect("missing key in storage")
            }
            false => 0,
        }
    }
}
