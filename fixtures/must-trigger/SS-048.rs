// SS-048 must trigger: an entry point publishes a caller-supplied `Vec` with no
// length bound, so the event payload size is attacker-controlled.

#![no_std]

use soroban_sdk::{contractimpl, symbol_short, Address, Env, Vec};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn record(env: Env, items: Vec<Address>) {
        env.events().publish((symbol_short!("record"),), items);
    }
}
