// SS-024 negative: an untyped local type is only used by a private helper.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn entry(env: Env) {
        let _ = &env;
    }

    fn helper(value: Payload) {
        let _ = &value;
    }
}

pub struct Payload {
    pub amount: i128,
}