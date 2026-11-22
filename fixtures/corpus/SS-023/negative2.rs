// SS-023 negative: a public key is safe to publish.

#![no_std]

use soroban_sdk::{contractimpl, symbol_short, BytesN, Env};

pub struct Commitments;

#[contractimpl]
impl Commitments {
    pub fn register(env: Env, public_key: BytesN<32>) {
        env.events().publish(symbol_short!("register"), public_key);
    }
}
