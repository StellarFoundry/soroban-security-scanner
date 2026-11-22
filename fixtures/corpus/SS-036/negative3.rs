// SS-036 negative: a same-named method on a non-Env receiver is not the SDK API.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Counter;

impl Counter {
    pub fn budget(&self) -> u32 {
        0
    }
}

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn entry(env: Env) {
        let counter = Counter;
        let _ = (&env, counter.budget());
    }
}