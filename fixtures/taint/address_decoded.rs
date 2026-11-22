// Taint fixture: a decoder introduces an address that reaches a privileged
// transfer. This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env, String};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn payout(env: Env, token_id: Address, raw: String, amount: i128) {
        let to = Address::from_string(&raw);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
