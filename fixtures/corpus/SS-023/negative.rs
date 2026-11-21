// SS-023 negative: benign transfer data is published.

#![no_std]

use soroban_sdk::{contractimpl, symbol_short, Address, Env};

pub struct Commitments;

#[contractimpl]
impl Commitments {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        env.events()
            .publish(symbol_short!("transfer"), (from, to, amount));
    }
}
