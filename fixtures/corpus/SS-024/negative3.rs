#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

struct InternalScratch {
    value: u32,
}

#[contract]
pub struct Market;

#[contractimpl]
impl Market {
    pub fn sequence(env: Env) -> u32 {
        let scratch = InternalScratch {
            value: env.ledger().sequence(),
        };
        scratch.value
    }
}
