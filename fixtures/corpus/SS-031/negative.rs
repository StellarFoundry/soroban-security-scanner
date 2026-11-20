// SS-031 negative: constant topics with caller data in the payload.

#![no_std]

use soroban_sdk::{contractimpl, symbol_short, Address, Env, Symbol};

pub struct Events;

#[contractimpl]
impl Events {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        env.events().publish(
            (symbol_short!("transfer"), Symbol::new(&env, "v1")),
            (from, to, amount),
        );
    }
}
