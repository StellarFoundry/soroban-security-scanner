// SS-004 positive: panic-prone constructs in an entry point.
// This file is a security fixture, not production code.

use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Store {
    pub fn read_or_die(env: Env) -> u32 {
        let value = env.storage().persistent().get(&K).unwrap();
        if value == 0 {
            panic!("empty");
        }
        value
    }
}
