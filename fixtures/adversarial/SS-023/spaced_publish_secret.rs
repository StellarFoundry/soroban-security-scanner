// SS-023 adversarial: a spaced publish chain still exposes both a
// secret-named parameter and a sensitive string literal.

#![no_std]

use soroban_sdk::{contractimpl, symbol_short, Bytes, Env};

pub struct Commitments;

#[contractimpl]
impl Commitments {
    pub fn commit(env: Env, secret: Bytes) {
        env . events () . publish ((symbol_short!("log"), "seed"), secret);
    }
}
