// SS-023 negative: a private helper is not an entry point.

#![no_std]

use soroban_sdk::{contractimpl, Bytes, Env};

pub struct Commitments;

#[contractimpl]
impl Commitments {
    fn commit(env: Env, secret: Bytes) {
        env.events().publish(symbol_short!("commit"), secret);
    }
}
