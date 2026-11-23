// SS-024 adversarial: a local type nested inside a container still counts.

#![no_std]

use soroban_sdk::{contractimpl, Env, Vec};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn store(env: Env, values: Vec<Payload>) {
        let _ = (&env, &values);
    }
}

pub struct Payload {
    pub amount: i128,
}