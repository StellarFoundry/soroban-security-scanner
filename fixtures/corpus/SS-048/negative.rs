// SS-048 negative fixture: the payload length is bounded before publishing.
#![no_std]

use soroban_sdk::{contractimpl, symbol_short, Address, Env, Vec};

const MAX_ITEMS: u32 = 32;

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn record(env: Env, items: Vec<Address>) {
        if items.len() > MAX_ITEMS {
            panic!("too many items");
        }
        env.events().publish((symbol_short!("record"),), items);
    }
}
