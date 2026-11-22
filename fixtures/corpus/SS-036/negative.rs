// SS-036 negative: current event and cost-estimate APIs are used.

#![no_std]

use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn entry(env: Env) {
        env.events().publish((symbol_short!("topic"),), 1_u32);
        let _ = env.cost_estimate();
    }
}