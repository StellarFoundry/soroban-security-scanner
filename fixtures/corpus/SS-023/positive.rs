// SS-023 positive: a secret parameter is published in an event.

#![no_std]

use soroban_sdk::{contractimpl, Bytes, Env};

pub struct Commitments;

#[contractimpl]
impl Commitments {
    pub fn commit(env: Env, secret: Bytes) {
        env.events().publish(symbol_short!("commit"), secret);
    }
}
