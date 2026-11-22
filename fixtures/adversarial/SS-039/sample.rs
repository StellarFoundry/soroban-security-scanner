// SS-039 adversarial: a persistent read split across lines is still a read
// without a TTL extension.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn load(env: Env) -> u32 {
        let value: u32 = env
            .storage()
            .persistent()
            .get(&0)
            .unwrap();
        value
    }
}
