// SS-036 adversarial: whitespace does not hide the deprecated call chain.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn entry(env: Env) {
        env . logger () . log ("deprecated");
    }
}