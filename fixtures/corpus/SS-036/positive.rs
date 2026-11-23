// SS-036 positive: the contract calls the removed Env::logger API.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn entry(env: Env) {
        env.logger().log("deprecated");
    }
}