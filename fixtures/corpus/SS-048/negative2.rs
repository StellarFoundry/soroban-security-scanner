// SS-048 negative fixture: all event payload types are fixed-size.
#![no_std]

use soroban_sdk::{contractevent, contractimpl, symbol_short, BytesN, Env};

#[contractevent]
pub struct Recorded {
    pub digest: BytesN<32>,
    pub count: u32,
}

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn record(env: Env, digest: BytesN<32>, count: u32) {
        env.events()
            .publish((symbol_short!("record"),), (digest, count));
    }
}
