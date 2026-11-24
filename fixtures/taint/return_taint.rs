// Taint fixture: a helper return value carries taint back to the caller.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
        let value = Self::take(amount);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }

    fn take(value: i128) -> i128 {
        value
    }
}
