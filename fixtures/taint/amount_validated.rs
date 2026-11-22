// Taint fixture: a documented validation helper clears the amount taint.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
        let checked = validate_amount(&env, amount);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &checked);
    }
}

fn validate_amount(env: &Env, amount: i128) -> i128 {
    let _ = env;
    amount
}
