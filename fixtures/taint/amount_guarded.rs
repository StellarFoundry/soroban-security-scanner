// Taint fixture: a bare comparison is not a documented sanitizer.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
        if amount > 0 {
            let client = token::Client::new(&env, &token_id);
            client.transfer(&env.current_contract_address(), &to, &amount);
        }
    }
}
