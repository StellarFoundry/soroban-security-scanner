// SS-036 negative: current address constructors are used.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn entry(env: Env) {
        let _ = Address::from_string(&soroban_sdk::String::from_str(&env, "G..."));
    }
}