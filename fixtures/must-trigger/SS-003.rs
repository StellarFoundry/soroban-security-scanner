// SS-003 positive: unbounded iteration over storage in an entry point.
// This file is a security fixture, not production code.

use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Registry {
    pub fn count_all(env: Env) -> u32 {
        let mut count = 0;
        for _key in env.storage().persistent().keys() {
            count += 1;
        }
        count
    }
}
