// SS-044 negative: the address comes from stored configuration, not a caller.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn payout(env: Env, token_id: Address, amount: i128) {
        let treasury: Address = env.storage().instance().get(&0).unwrap();
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &treasury, &amount);
    }
}
