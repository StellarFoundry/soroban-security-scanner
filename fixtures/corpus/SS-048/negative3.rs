// SS-048 negative fixture: only a private helper publishes the unbounded value.
#![no_std]

use soroban_sdk::{contractimpl, symbol_short, Address, Env, Vec};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn record(env: Env, items: Vec<Address>) {
        Self::emit(&env, items);
    }

    fn emit(env: &Env, items: Vec<Address>) {
        env.events().publish((symbol_short!("record"),), items);
    }
}
