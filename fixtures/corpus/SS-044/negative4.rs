// SS-044 negative: a read-only call has no privileged address argument.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn balance(env: Env, token_id: Address, owner: Address) -> i128 {
        let client = token::Client::new(&env, &token_id);
        client.balance(&owner)
    }
}
