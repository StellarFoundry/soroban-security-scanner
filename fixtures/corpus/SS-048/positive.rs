// SS-048 positive fixture: an entry point publishes an unbounded `Vec`.
#![no_std]

use soroban_sdk::{contractimpl, symbol_short, Address, Env, Vec};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn record(env: Env, items: Vec<Address>) {
        env.events().publish((symbol_short!("record"),), items);
    }
}
