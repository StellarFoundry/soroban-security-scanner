// SS-031 negative: parameters appear only in the event data payload.

#![no_std]

use soroban_sdk::{contractimpl, symbol_short, Address, Env};

pub struct Events;

#[contractimpl]
impl Events {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        env.events()
            .publish(symbol_short!("transfer"), (from, to, amount));
    }
}
