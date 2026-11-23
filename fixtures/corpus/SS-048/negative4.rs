// SS-048 negative fixture: the payload is a small tuple of fixed-size values and
// a compile-time literal.
#![no_std]

use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn record(env: Env, count: u32) {
        env.events()
            .publish((symbol_short!("record"),), ("ok", count));
    }
}
