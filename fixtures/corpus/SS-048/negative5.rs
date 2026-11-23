// SS-048 negative fixture: an unbounded collection is received but only its
// length is published.
#![no_std]

use soroban_sdk::{contractimpl, symbol_short, Address, Env, Vec};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn record(env: Env, items: Vec<Address>) {
        let count = items.len();
        env.events()
            .publish((symbol_short!("record"),), count);
    }
}
